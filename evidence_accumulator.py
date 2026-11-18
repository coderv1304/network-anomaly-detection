"""Slips-style multi-signal risk accumulation.

A single per-flow probability threshold is a poor alerting unit: at realistic
attack prevalence most threshold crossings are false positives, and a single
score cannot distinguish a noisy flow from a sustained host-level incident.
This module groups observations by ``(tenant, source IP, time window)`` and
accumulates independent evidence:

1. a calibrated supervised score (Random Forest ``1 - P(BENIGN)``),
2. an unsupervised anomaly confidence (Isolation Forest), and
3. an external reputation score (AbuseIPDB, optional).

No single signal can open an incident under the default policy. Points are
capped per signal per window, so a host cannot manufacture an incident by
sending more flows. The result is an explainable host/window record rather
than another per-flow alert.

Calibrated scoring mode
-----------------------
The default ``multi_signal`` mode deliberately scores each signal on a
0-to-weight scale, which makes it a multi-signal correlator rather than a
single-score accumulator. When a caller only has one *calibrated* probability
per flow and wants to test whether windowing repairs low-prevalence precision,
``scoring_mode="calibrated"`` replaces that policy with an explicit, auditable
one:

* ``points = 100 * max(0, (p - p_floor) / (1 - p_floor))`` per flow, capped at
  ``per_flow_cap``;
* window points are the sum of per-flow points, capped at ``window_cap``;
* an incident opens when window points reach ``incident_threshold``.

Because ``per_flow_cap < incident_threshold`` is enforced, one flow can never
open an incident; corroboration by at least two flows in the same
``(tenant, source IP, window)`` bucket is required. ``min_signals`` is forced
to 1 in this mode: it is a single-signal accumulator by definition, and
pretending otherwise would misreport what was measured.

The module is deliberately dependency-free and does not import Flask. The
application owns wiring and persistence.
"""

from __future__ import annotations

import json
import math
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

DEFAULT_WINDOW_SECONDS = 300
DEFAULT_INCIDENT_THRESHOLD = 70.0

# Signal weights are the maximum contribution of one signal in a window.
DEFAULT_WEIGHTS = {
    "supervised": 50.0,
    "unsupervised": 35.0,
    "reputation": 45.0,
}

# Minimum confidence before a signal contributes at all.
DEFAULT_MINIMUMS = {
    "supervised": 0.50,
    "unsupervised": 0.50,
    "reputation": 50.0,  # AbuseIPDB confidence is 0-100
}

# Calibrated single-score mode (see module docstring).
SCORING_MODES = ("multi_signal", "calibrated")
DEFAULT_SCORING_MODE = "multi_signal"
DEFAULT_P_FLOOR = 0.50
DEFAULT_PER_FLOW_CAP = 50.0
DEFAULT_WINDOW_CAP = 100.0
CALIBRATED_POINT_SCALE = 100.0


def calibrated_flow_points(
    probabilities,
    *,
    p_floor: float = DEFAULT_P_FLOOR,
    per_flow_cap: float = DEFAULT_PER_FLOW_CAP,
):
    """Vectorised twin of the accumulator's calibrated per-flow score.

    ``points = 100 * max(0, (p - p_floor) / (1 - p_floor))``, clamped to
    ``per_flow_cap``. Batch evaluation of a million flows needs this path; it
    must stay numerically identical to the scalar path used by
    :meth:`EvidenceAccumulator.observe`, which is asserted by a unit test.
    """
    import numpy as np

    if not 0.0 <= float(p_floor) < 1.0:
        raise ValueError("p_floor must be in [0, 1)")
    values = np.clip(np.asarray(probabilities, dtype=np.float64), 0.0, 1.0)
    excess = (values - float(p_floor)) / max(1e-12, 1.0 - float(p_floor))
    return np.minimum(
        CALIBRATED_POINT_SCALE * np.maximum(0.0, excess), float(per_flow_cap)
    )


@dataclass(frozen=True)
class Observation:
    """One scored flow, already normalised to the accumulator's input units.

    ``supervised_probability`` is expected to be calibrated. Callers that only
    have a raw score must say so in ``supervised_calibration`` so the incident
    record does not imply calibration that did not happen.

    ``unsupervised_confidence`` is 0-1, where 1 is most anomalous.
    ``reputation_score`` is the AbuseIPDB 0-100 confidence, or ``None`` when no
    lookup was made.
    """

    source_ip: str
    timestamp: float
    supervised_probability: float | None = None
    unsupervised_confidence: float | None = None
    reputation_score: float | None = None
    supervised_calibration: str = "uncalibrated"
    destination_ip: str | None = None
    destination_port: int | None = None
    tenant_id: int | None = None
    flow_id: str | None = None


@dataclass
class _SourceWindow:
    tenant_id: int | None
    source_ip: str
    window_start: float
    window_seconds: int
    first_seen: float
    last_seen: float
    flow_count: int = 0
    points: dict[str, float] = field(
        default_factory=lambda: {"supervised": 0.0, "unsupervised": 0.0, "reputation": 0.0}
    )
    signal_hits: dict[str, int] = field(
        default_factory=lambda: {"supervised": 0, "unsupervised": 0, "reputation": 0}
    )
    last_values: dict[str, float | None] = field(
        default_factory=lambda: {
            "supervised": None,
            "unsupervised": None,
            "reputation": None,
        }
    )
    destination_ports: set[int] = field(default_factory=set)
    destination_ips: set[str] = field(default_factory=set)
    evidence: list[str] = field(default_factory=list)
    incident_open: bool = False
    incident_opened_at: float | None = None
    max_risk_points: float = 0.0
    sample_flow_ids: list[str] = field(default_factory=list)


class EvidenceAccumulator:
    """Thread-safe, in-memory host/window evidence store.

    The default policy requires at least two independent signals and a total
    risk of 70 points before an incident opens. A single high-confidence
    supervised score therefore cannot reproduce the per-flow threshold failure
    mode.
    """

    def __init__(
        self,
        *,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        incident_threshold: float = DEFAULT_INCIDENT_THRESHOLD,
        weights: dict[str, float] | None = None,
        minimums: dict[str, float] | None = None,
        min_signals: int = 2,
        max_destination_tracking: int = 500,
        max_windows_per_source: int = 12,
        scoring_mode: str = DEFAULT_SCORING_MODE,
        p_floor: float = DEFAULT_P_FLOOR,
        per_flow_cap: float = DEFAULT_PER_FLOW_CAP,
        window_cap: float = DEFAULT_WINDOW_CAP,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if incident_threshold <= 0:
            raise ValueError("incident_threshold must be positive")
        if scoring_mode not in SCORING_MODES:
            raise ValueError(
                f"scoring_mode must be one of {SCORING_MODES}, got {scoring_mode!r}"
            )
        if not 0.0 <= float(p_floor) < 1.0:
            raise ValueError("p_floor must be in [0, 1)")
        if per_flow_cap <= 0:
            raise ValueError("per_flow_cap must be positive")
        if window_cap <= 0:
            raise ValueError("window_cap must be positive")
        self.scoring_mode = scoring_mode
        self.p_floor = float(p_floor)
        self.per_flow_cap = float(per_flow_cap)
        self.window_cap = float(window_cap)
        if scoring_mode == "calibrated":
            # The single-flow invariant is the entire point of this mode: a
            # capped flow must not be able to open an incident on its own.
            if self.per_flow_cap >= float(incident_threshold):
                raise ValueError(
                    "calibrated mode requires per_flow_cap < incident_threshold "
                    f"({self.per_flow_cap} >= {incident_threshold}); otherwise a "
                    "single flow could open an incident"
                )
            if self.window_cap < float(incident_threshold):
                raise ValueError(
                    "calibrated mode requires window_cap >= incident_threshold "
                    f"({self.window_cap} < {incident_threshold}); otherwise no "
                    "window could ever open an incident"
                )
            # Calibrated mode is a single-signal accumulator by construction.
            min_signals = 1
        self.window_seconds = int(window_seconds)
        self.incident_threshold = float(incident_threshold)
        self.weights = {**DEFAULT_WEIGHTS, **(weights or {})}
        self.minimums = {**DEFAULT_MINIMUMS, **(minimums or {})}
        self.min_signals = max(1, int(min_signals))
        self.max_destination_tracking = int(max_destination_tracking)
        self.max_windows_per_source = int(max_windows_per_source)
        self._windows: dict[tuple, _SourceWindow] = {}
        self._lock = threading.Lock()

    # -- signal contribution -------------------------------------------------
    def _signal_cap(self, signal: str) -> float:
        """Per-window ceiling for one signal under the active scoring mode."""
        if signal == "supervised" and self.scoring_mode == "calibrated":
            return self.window_cap
        return self.weights[signal]

    def _supervised_points(self, probability: float | None) -> float:
        if probability is None or not math.isfinite(probability):
            return 0.0
        p = min(max(float(probability), 0.0), 1.0)
        if self.scoring_mode == "calibrated":
            excess = (p - self.p_floor) / max(1e-12, 1.0 - self.p_floor)
            return min(
                self.per_flow_cap, CALIBRATED_POINT_SCALE * max(0.0, excess)
            )
        minimum = self.minimums["supervised"]
        if p < minimum:
            return 0.0
        return self.weights["supervised"] * (p - minimum) / max(1e-12, 1.0 - minimum)

    def _unsupervised_points(self, confidence: float | None) -> float:
        if confidence is None or not math.isfinite(confidence):
            return 0.0
        c = min(max(float(confidence), 0.0), 1.0)
        minimum = self.minimums["unsupervised"]
        if c < minimum:
            return 0.0
        return self.weights["unsupervised"] * (c - minimum) / max(1e-12, 1.0 - minimum)

    def _reputation_points(self, score: float | None) -> float:
        if score is None or not math.isfinite(score):
            return 0.0
        value = min(max(float(score), 0.0), 100.0)
        if value < self.minimums["reputation"]:
            return 0.0
        return self.weights["reputation"] * value / 100.0

    # -- observation ---------------------------------------------------------
    def observe(self, observation: Observation) -> dict[str, Any]:
        """Add one observation and return the affected window summary."""
        if not observation.source_ip or observation.source_ip == "—":
            raise ValueError("source_ip is required for evidence accumulation")
        timestamp = (
            float(observation.timestamp)
            if observation.timestamp is not None and math.isfinite(observation.timestamp)
            else time.time()
        )
        window_start = math.floor(timestamp / self.window_seconds) * self.window_seconds
        key = (observation.tenant_id, observation.source_ip, int(window_start))

        contributions = {
            "supervised": self._supervised_points(observation.supervised_probability),
            "unsupervised": self._unsupervised_points(
                observation.unsupervised_confidence
            ),
            "reputation": self._reputation_points(observation.reputation_score),
        }

        with self._lock:
            window = self._windows.get(key)
            if window is None:
                window = _SourceWindow(
                    tenant_id=observation.tenant_id,
                    source_ip=observation.source_ip,
                    window_start=window_start,
                    window_seconds=self.window_seconds,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
                self._windows[key] = window
                self._evict_old_windows(observation.tenant_id, observation.source_ip)

            window.flow_count += 1
            window.first_seen = min(window.first_seen, timestamp)
            window.last_seen = max(window.last_seen, timestamp)
            if observation.destination_port is not None:
                if len(window.destination_ports) < self.max_destination_tracking:
                    window.destination_ports.add(int(observation.destination_port))
            if observation.destination_ip and observation.destination_ip != "—":
                if len(window.destination_ips) < self.max_destination_tracking:
                    window.destination_ips.add(observation.destination_ip)
            if observation.flow_id and len(window.sample_flow_ids) < 10:
                window.sample_flow_ids.append(observation.flow_id)

            for signal, points in contributions.items():
                if points <= 0.0:
                    continue
                # Cap each signal once per window. More flows from the same host
                # strengthen the count but cannot inflate the score indefinitely.
                cap = self._signal_cap(signal)
                remaining = max(0.0, cap - window.points[signal])
                applied = min(points, remaining)
                if applied <= 0.0:
                    continue
                window.points[signal] += applied
                window.signal_hits[signal] += 1
                window.last_values[signal] = (
                    observation.supervised_probability
                    if signal == "supervised"
                    else observation.unsupervised_confidence
                    if signal == "unsupervised"
                    else observation.reputation_score
                )
                window.evidence.append(self._evidence_text(signal, applied, observation))

            total = round(sum(window.points.values()), 4)
            window.max_risk_points = max(window.max_risk_points, total)
            active_signals = sum(1 for value in window.points.values() if value > 0.0)
            incident = total >= self.incident_threshold and active_signals >= self.min_signals
            if incident and not window.incident_open:
                window.incident_open = True
                window.incident_opened_at = timestamp
            return self._serialize(window, active_signals=active_signals)

    def _evidence_text(
        self, signal: str, points: float, observation: Observation
    ) -> str:
        if signal == "supervised":
            return (
                f"supervised score {observation.supervised_probability:.3f} "
                f"({observation.supervised_calibration}) +{points:.1f}"
            )
        if signal == "unsupervised":
            return (
                f"isolation-forest confidence "
                f"{observation.unsupervised_confidence:.3f} +{points:.1f}"
            )
        return f"reputation {observation.reputation_score:.0f}/100 +{points:.1f}"

    def _evict_old_windows(self, tenant_id: int | None, source_ip: str) -> None:
        keys = [
            key
            for key in self._windows
            if key[0] == tenant_id and key[1] == source_ip
        ]
        if len(keys) <= self.max_windows_per_source:
            return
        keys.sort(key=lambda key: key[2])
        for key in keys[: len(keys) - self.max_windows_per_source]:
            del self._windows[key]

    def _serialize(self, window: _SourceWindow, *, active_signals: int) -> dict[str, Any]:
        total = round(sum(window.points.values()), 4)
        return {
            "incident_id": f"{window.source_ip}:{int(window.window_start)}",
            "tenant_id": window.tenant_id,
            "source_ip": window.source_ip,
            "window_start": _iso(window.window_start),
            "window_seconds": window.window_seconds,
            "first_seen": _iso(window.first_seen),
            "last_seen": _iso(window.last_seen),
            "risk_points": total,
            "max_risk_points": round(window.max_risk_points, 4),
            "incident_open": window.incident_open,
            "incident_opened_at": (
                _iso(window.incident_opened_at)
                if window.incident_opened_at is not None
                else None
            ),
            "active_signals": active_signals,
            "requires_signals": self.min_signals,
            "points": {key: round(value, 4) for key, value in window.points.items()},
            "signal_hits": dict(window.signal_hits),
            "last_values": dict(window.last_values),
            "flow_count": window.flow_count,
            "distinct_destination_ports": len(window.destination_ports),
            "distinct_destination_ips": len(window.destination_ips),
            "sample_flow_ids": list(window.sample_flow_ids),
            "evidence": list(window.evidence[-12:]),
        }

    # -- read paths ----------------------------------------------------------
    def snapshot(
        self,
        *,
        tenant_id: int | None = None,
        open_only: bool = True,
        limit: int = 100,
    ) -> dict[str, Any]:
        with self._lock:
            windows = list(self._windows.values())
        if tenant_id is not None:
            windows = [window for window in windows if window.tenant_id == tenant_id]
        if open_only:
            windows = [window for window in windows if window.incident_open]
        windows.sort(key=lambda window: (window.max_risk_points, window.last_seen), reverse=True)
        rows = [
            self._serialize(
                window,
                active_signals=sum(1 for value in window.points.values() if value > 0.0),
            )
            for window in windows[: max(0, int(limit))]
        ]
        return {
            "count": len(rows),
            "window_seconds": self.window_seconds,
            "incident_threshold": self.incident_threshold,
            "min_signals": self.min_signals,
            "scoring_mode": self.scoring_mode,
            "p_floor": self.p_floor if self.scoring_mode == "calibrated" else None,
            "per_flow_cap": (
                self.per_flow_cap if self.scoring_mode == "calibrated" else None
            ),
            "window_cap": self.window_cap if self.scoring_mode == "calibrated" else None,
            "signals": list(self.points_signals()),
            "incidents": rows,
        }

    @staticmethod
    def points_signals() -> Iterable[str]:
        return ("supervised", "unsupervised", "reputation")

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()


def _iso(timestamp: float) -> str:
    import datetime

    return (
        datetime.datetime.fromtimestamp(
            float(timestamp), tz=datetime.timezone.utc
        ).isoformat().replace("+00:00", "Z")
    )


# ---------------------------------------------------------------------------
# Calibration helpers
# ---------------------------------------------------------------------------
def load_calibrator(path: str) -> tuple[Any, dict[str, Any]]:
    """Load an isotonic or Platt calibration artifact.

    Returns ``(callable, metadata)``. The callable maps a raw attack score to a
    calibrated probability. Unknown artifact shapes raise ``ValueError`` so a
    caller cannot silently claim calibration.
    """
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    method = str(payload.get("method", "")).lower()
    parameters = payload.get("parameters", {})
    if method == "isotonic":
        x = parameters.get("isotonic_x")
        y = parameters.get("isotonic_y")
        if not isinstance(x, list) or not isinstance(y, list) or not x or len(x) != len(y):
            raise ValueError("isotonic calibration artifact is malformed")
        xs = [float(value) for value in x]
        ys = [float(value) for value in y]

        def calibrate(score: float) -> float:
            import bisect

            value = min(max(float(score), xs[0]), xs[-1])
            index = bisect.bisect_right(xs, value) - 1
            index = min(max(index, 0), len(xs) - 1)
            return float(ys[index])

        return calibrate, payload
    if method in {"platt", "sigmoid"}:
        a = parameters.get("platt_a", parameters.get("a"))
        b = parameters.get("platt_b", parameters.get("b"))
        if a is None or b is None:
            raise ValueError("Platt calibration artifact is malformed")

        def calibrate(score: float) -> float:
            return float(1.0 / (1.0 + math.exp(-(float(a) * float(score) + float(b)))))

        return calibrate, payload
    raise ValueError(f"unsupported calibration method: {payload.get('method')!r}")


def isolation_confidence(
    raw_score: float | None,
    threshold: float,
    scale: float | None = None,
) -> float | None:
    """Map an Isolation Forest decision score to a 0-1 confidence.

    The raw ``-decision_function`` score is unbounded. The threshold is the
    validation-selected operating point. A score at the threshold maps to 0.5;
    higher scores approach 1.0. This is a monotone presentation transform, not
    a calibrated probability.
    """
    if raw_score is None or not math.isfinite(raw_score):
        return None
    threshold = float(threshold)
    span = float(scale) if scale is not None else max(0.05, abs(threshold))
    return float(0.5 + 0.5 * math.tanh((float(raw_score) - threshold) / span))
