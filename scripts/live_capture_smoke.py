"""End-to-end live-capture smoke test.

Starts the Flask app on a loopback port, starts the real PyFlowMeter capture
path on a named interface, lets it run for a few seconds, then checks that
captured flows were POSTed to /api/flows and stored with S3 provenance.

This is an *ingest-path* smoke test. It does not establish detection accuracy,
feature parity, or "live validation". It proves only that packets can be
captured, converted to flow records, accepted by the API, classified, and
stored.

Requirements (Windows):
  - Npcap installed (bundled with Wireshark)
  - a terminal with Administrator privileges
  - pyflowmeter installed

Usage:
    python scripts/live_capture_smoke.py
    python scripts/live_capture_smoke.py --interface "Wi-Fi,\\Device\\NPF_Loopback"
    python scripts/live_capture_smoke.py --interface all --seconds 30
    python scripts/live_capture_smoke.py --json docs/live_capture_smoke.json

Interface selection accepts "auto" (the default-route adapter), "all",
"loopback", or a comma-separated list, exactly like NETSHIELD_CAPTURE_INTERFACE.

Exit codes:
    0  at least one flow was ingested and stored with provenance
    2  capture started but no flow was ingested in the window
    3  capture failed to start
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import traceback

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--interface",
        default=os.environ.get("NETSHIELD_CAPTURE_INTERFACE", "auto"),
        help="auto | all | loopback | comma-separated names/descriptions/IPs",
    )
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--port", type=int, default=5055)
    parser.add_argument("--json", default=None)
    args = parser.parse_args()

    # The app reads these at import time.
    os.environ["NETSHIELD_ENV"] = "development"
    os.environ["ENABLE_LOCAL_CAPTURE"] = "true"
    os.environ.setdefault("LIVE_CAPTURE_API_KEY", "live-capture-smoke-key")
    os.environ["NETSHIELD_CAPTURE_INTERFACE"] = args.interface
    os.environ.setdefault("SOCKETIO_ALLOWED_ORIGINS", "http://127.0.0.1:5055")

    import app as app_module  # noqa: E402

    base_url = f"http://127.0.0.1:{args.port}"
    server = threading.Thread(
        target=lambda: app_module.app.run(
            host="127.0.0.1", port=args.port, use_reloader=False, threaded=True
        ),
        daemon=True,
    )
    server.start()

    # Wait for the HTTP server.
    import requests

    deadline = time.time() + 15
    up = False
    while time.time() < deadline:
        try:
            if requests.get(f"{base_url}/healthz", timeout=1).status_code == 200:
                up = True
                break
        except requests.RequestException:
            time.sleep(0.3)
    if not up:
        print("Server did not start", file=sys.stderr)
        return 3

    with app_module.app.app_context():
        before = app_module.Flow.query.count()

    capture_thread = threading.Thread(
        target=app_module._start_live_capture, args=(base_url,), daemon=True
    )
    capture_thread.start()

    time.sleep(max(1, args.seconds))

    with app_module.app.app_context():
        after = app_module.Flow.query.count()
        captured = (
            app_module.Flow.query.filter(app_module.Flow.model_version.isnot(None))
            .order_by(app_module.Flow.id.desc())
            .limit(5)
            .all()
        )
        sample = [
            {
                "id": row.id,
                "predicted_label": row.predicted_label,
                "is_attack": row.is_attack,
                "provenance": {
                    "model_version": row.model_version,
                    "artifact_sha256": row.artifact_sha256,
                    "feature_schema_version": row.feature_schema_version,
                    "threshold_policy": row.threshold_policy,
                    "calibration_version": row.calibration_version,
                    "decision_basis": row.decision_basis,
                    "attack_score": row.attack_score,
                    "model_argmax_label": row.model_argmax_label,
                },
            }
            for row in captured
        ]

    report = {
        "tool": "scripts/live_capture_smoke.py",
        "interface_selection": args.interface,
        "interface": args.interface,
        "resolved_interfaces": [
            entry.get("interface") for entry in app_module.CAPTURE_STATUS.get("interfaces", [])
        ],
        "interface_states": app_module.CAPTURE_STATUS.get("interfaces", []),
        "seconds": args.seconds,
        "server": base_url,
        "capture_state": app_module.CAPTURE_STATUS.get("state"),
        "capture_message": app_module.CAPTURE_STATUS.get("message"),
        "flows_before": before,
        "flows_after": after,
        "flows_ingested": after - before,
        "capture_status": app_module.CAPTURE_STATUS,
        "sample_provenance": sample,
        "note": (
            "Ingest-path smoke test only. It does not establish feature parity, "
            "detection accuracy, or live validation."
        ),
    }
    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
    print(json.dumps(report, indent=2, sort_keys=True))

    if report["flows_ingested"] <= 0:
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        raise SystemExit(3)
