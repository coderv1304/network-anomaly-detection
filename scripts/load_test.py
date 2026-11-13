"""Declared-rate load test for the NetShield ingest and console paths.

This is deliberately dependency-light (requests + threads) because Locust is
not installed in this environment. It drives the real HTTP surface, including
rate limits and bounded ingest admission, so a saturation result reflects the
deployed process rather than an in-process shortcut.

Example (server must already be running with a known key):

    LIVE_CAPTURE_API_KEY=loadtest-key DATABASE_URL=sqlite:///loadtest.db \
        venv/Scripts/python.exe app.py

    venv/Scripts/python.exe scripts/load_test.py \
        --base-url http://127.0.0.1:5050 \
        --api-key loadtest-key \
        --rates 20,50,100,200,400 \
        --duration 10 \
        --workers 8 \
        --batch-size 10

Outputs:
    docs/LOAD_TEST_RESULTS.md
    docs/load_test_results.json
"""

from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import requests

PYFLOWMETER_KEYS = {
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "src_port": 12345,
    "dst_port": 80,
    "src_mac": "aa:bb:cc:dd:ee:ff",
    "dst_mac": "11:22:33:44:55:66",
    "protocol": 6,
    "timestamp": 0.0,
    "flow_duration": 1000.0,
    "flow_byts_s": 100.0,
    "flow_pkts_s": 5.0,
    "fwd_pkts_s": 3.0,
    "bwd_pkts_s": 2.0,
    "tot_fwd_pkts": 3.0,
    "tot_bwd_pkts": 2.0,
    "totlen_fwd_pkts": 300.0,
    "totlen_bwd_pkts": 200.0,
    "fwd_pkt_len_max": 100.0,
    "fwd_pkt_len_min": 80.0,
    "fwd_pkt_len_mean": 90.0,
    "fwd_pkt_len_std": 5.0,
    "bwd_pkt_len_max": 100.0,
    "bwd_pkt_len_min": 80.0,
    "bwd_pkt_len_mean": 90.0,
    "bwd_pkt_len_std": 5.0,
    "pkt_len_max": 100.0,
    "pkt_len_min": 80.0,
    "pkt_len_mean": 90.0,
    "pkt_len_std": 5.0,
    "pkt_len_var": 25.0,
    "fwd_header_len": 20.0,
    "bwd_header_len": 20.0,
    "fwd_seg_size_min": 20.0,
    "fwd_act_data_pkts": 2.0,
    "flow_iat_mean": 10.0,
    "flow_iat_max": 20.0,
    "flow_iat_min": 1.0,
    "flow_iat_std": 2.0,
    "fwd_iat_tot": 30.0,
    "fwd_iat_max": 20.0,
    "fwd_iat_min": 1.0,
    "fwd_iat_mean": 10.0,
    "fwd_iat_std": 2.0,
    "bwd_iat_tot": 20.0,
    "bwd_iat_max": 15.0,
    "bwd_iat_min": 1.0,
    "bwd_iat_mean": 8.0,
    "bwd_iat_std": 2.0,
    "fwd_psh_flags": 0.0,
    "bwd_psh_flags": 0.0,
    "fwd_urg_flags": 0.0,
    "bwd_urg_flags": 0.0,
    "fin_flag_cnt": 0.0,
    "syn_flag_cnt": 1.0,
    "rst_flag_cnt": 0.0,
    "psh_flag_cnt": 1.0,
    "ack_flag_cnt": 1.0,
    "urg_flag_cnt": 0.0,
    "ece_flag_cnt": 0.0,
    "down_up_ratio": 0.66,
    "pkt_size_avg": 90.0,
    "init_fwd_win_byts": 29200.0,
    "init_bwd_win_byts": 29200.0,
    "active_max": 100.0,
    "active_min": 10.0,
    "active_mean": 50.0,
    "active_std": 20.0,
    "idle_max": 100.0,
    "idle_min": 10.0,
    "idle_mean": 50.0,
    "idle_std": 20.0,
    "fwd_byts_b_avg": 0.0,
    "fwd_pkts_b_avg": 0.0,
    "bwd_byts_b_avg": 0.0,
    "bwd_pkts_b_avg": 0.0,
    "fwd_blk_rate_avg": 0.0,
    "bwd_blk_rate_avg": 0.0,
    "fwd_seg_size_avg": 90.0,
    "bwd_seg_size_avg": 90.0,
    "cwe_flag_count": 0.0,
    "subflow_fwd_pkts": 3.0,
    "subflow_bwd_pkts": 2.0,
    "subflow_fwd_byts": 300.0,
    "subflow_bwd_byts": 200.0,
}


def make_flow(seed: int) -> dict:
    flow = dict(PYFLOWMETER_KEYS)
    rng = random.Random(seed)
    flow["src_port"] = rng.randint(1024, 65535)
    flow["dst_port"] = rng.choice([80, 443, 22, 21, 8080, 53, 3389])
    flow["src_ip"] = f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    flow["dst_ip"] = f"192.168.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    flow["flow_duration"] = float(rng.randint(10, 5_000_000))
    flow["tot_fwd_pkts"] = float(rng.randint(1, 50))
    flow["tot_bwd_pkts"] = float(rng.randint(0, 50))
    flow["totlen_fwd_pkts"] = float(rng.randint(40, 5000))
    flow["totlen_bwd_pkts"] = float(rng.randint(0, 5000))
    return flow


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def run_step(base_url: str, api_key: str, rate: float, duration: float, workers: int, batch_size: int) -> dict:
    total_request_rate = rate / batch_size
    worker_count = max(1, min(workers, max(1, int(total_request_rate))))
    per_worker_interval = worker_count / total_request_rate
    stop = threading.Event()
    lock = threading.Lock()
    latencies: list[float] = []
    statuses: dict[int, int] = {}
    errors: list[str] = []
    sent_flows = 0

    session = requests.Session()
    session.headers.update({"X-API-Key": api_key, "Content-Type": "application/json"})
    url = f"{base_url.rstrip('/')}/api/flows"

    def worker(worker_id: int) -> None:
        nonlocal sent_flows
        rng = random.Random(worker_id * 1_000_003 + int(rate))
        next_at = time.perf_counter()
        sequence = 0
        while not stop.is_set():
            flows = [make_flow(rng.randint(0, 2**31 - 1)) for _ in range(batch_size)]
            started = time.perf_counter()
            try:
                response = session.post(url, json={"flows": flows}, timeout=10)
                elapsed = time.perf_counter() - started
                with lock:
                    latencies.append(elapsed)
                    statuses[response.status_code] = statuses.get(response.status_code, 0) + 1
                    sent_flows += len(flows)
                if response.status_code >= 400 and len(errors) < 5:
                    with lock:
                        errors.append(f"{response.status_code}: {response.text[:200]}")
            except requests.RequestException as exc:
                with lock:
                    statuses[0] = statuses.get(0, 0) + 1
                    if len(errors) < 5:
                        errors.append(type(exc).__name__)
            sequence += 1
            next_at += per_worker_interval
            sleep_for = next_at - time.perf_counter()
            if sleep_for > 0:
                time.sleep(sleep_for)
            elif sleep_for < -1:
                next_at = time.perf_counter()

    started_at = time.perf_counter()
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = [pool.submit(worker, index) for index in range(worker_count)]
        time.sleep(duration)
        stop.set()
        for future in futures:
            future.result(timeout=30)
    elapsed = time.perf_counter() - started_at

    total_requests = sum(statuses.values())
    success = statuses.get(201, 0) + statuses.get(200, 0)
    rate_limited = statuses.get(429, 0)
    unavailable = statuses.get(503, 0)
    other_errors = total_requests - success - rate_limited - unavailable
    return {
        "declared_flow_rate": rate,
        "batch_size": batch_size,
        "workers": worker_count,
        "duration_seconds": round(elapsed, 3),
        "requests": total_requests,
        "achieved_flow_rate": round(sent_flows / elapsed, 1) if elapsed else 0.0,
        "success_requests": success,
        "success_ratio": round(success / total_requests, 4) if total_requests else 0.0,
        "rate_limited": rate_limited,
        "unavailable": unavailable,
        "other_errors": other_errors,
        "latency_ms": {
            "p50": round(percentile(latencies, 0.50) * 1000, 1),
            "p95": round(percentile(latencies, 0.95) * 1000, 1),
            "p99": round(percentile(latencies, 0.99) * 1000, 1),
            "max": round(max(latencies) * 1000, 1) if latencies else 0.0,
        },
        "sample_errors": errors,
    }


def failure_reason(step: dict) -> str | None:
    if step["unavailable"]:
        return f"503 backpressure at {step['declared_flow_rate']} flows/s"
    if step["success_ratio"] < 0.99:
        return f"success ratio {step['success_ratio']:.2%} below 99% at {step['declared_flow_rate']} flows/s"
    if step["latency_ms"]["p95"] > 1000:
        return f"p95 {step['latency_ms']['p95']} ms above 1000 ms at {step['declared_flow_rate']} flows/s"
    return None


def write_markdown(report: dict, path: str) -> None:
    lines = [
        "# Ingest Load Test Results",
        "",
        f"*Generated: {report['generated_at']}*",
        "",
        "## Scope and honest limits",
        "",
        "- Single-process Flask/SocketIO deployment with SQLite and the default bounded ingest admission (4 concurrent requests, 250 ms admission timeout).",
        "- Traffic is synthetic flow JSON sent to `POST /api/flows`; it exercises auth, rate limiting, feature mapping, model inference, database insert, audit write, and SocketIO emit.",
        "- This is not a production capacity claim. SQLite, a single process, and one host are deliberate bottlenecks.",
        "- Success means HTTP 201. HTTP 429 means the rate limiter engaged. HTTP 503 means bounded admission rejected the request with `Retry-After`.",
        "",
        "## Declared-rate results",
        "",
        "| Declared flows/s | Achieved flows/s | Requests | Success | 429 | 503 | Other errors | p50 ms | p95 ms | p99 ms | Max ms |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for step in report["steps"]:
        lines.append(
            f"| {step['declared_flow_rate']:.0f} | {step['achieved_flow_rate']:.1f} | "
            f"{step['requests']} | {step['success_ratio'] * 100:.1f}% | "
            f"{step['rate_limited']} | {step['unavailable']} | {step['other_errors']} | "
            f"{step['latency_ms']['p50']} | {step['latency_ms']['p95']} | "
            f"{step['latency_ms']['p99']} | {step['latency_ms']['max']} |"
        )

    lines.extend([
        "",
        "## Failure point",
        "",
        f"**{report['failure_point'] or 'No failure inside the declared range.'}**",
        "",
        "## Observations",
        "",
    ])
    for observation in report["observations"]:
        lines.append(f"- {observation}")

    lines.extend([
        "",
        "## Reproduce",
        "",
        "```bash",
        "LIVE_CAPTURE_API_KEY=loadtest-key DATABASE_URL=sqlite:///loadtest.db \\",
        "  NETSHIELD_DEMO_STREAM=false PORT=5050 venv/Scripts/python.exe app.py",
        "",
        "venv/Scripts/python.exe scripts/load_test.py \\",
        "  --base-url http://127.0.0.1:5050 --api-key loadtest-key \\",
        f"  --rates {','.join(str(int(step['declared_flow_rate'])) for step in report['steps'])} \\",
        f"  --duration {report['config']['duration']} --workers {report['config']['workers']} \\",
        f"  --batch-size {report['config']['batch_size']}",
        "```",
        "",
    ])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser(description="Declared-rate load test for NetShield.")
    parser.add_argument("--base-url", default="http://127.0.0.1:5050")
    parser.add_argument("--api-key", default=os.environ.get("LIVE_CAPTURE_API_KEY", "loadtest-key"))
    parser.add_argument("--rates", default="20,50,100,200,400")
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--output-dir", default="docs")
    args = parser.parse_args()

    rates = [float(value) for value in args.rates.split(",") if value.strip()]
    readiness = requests.get(f"{args.base_url.rstrip('/')}/readyz", timeout=5)
    readiness.raise_for_status()

    steps = []
    for rate in rates:
        print(f"[load] rate={rate:.0f} flows/s for {args.duration:.0f}s ...", flush=True)
        step = run_step(
            args.base_url,
            args.api_key,
            rate,
            args.duration,
            args.workers,
            args.batch_size,
        )
        steps.append(step)
        print(
            f"[load] achieved={step['achieved_flow_rate']:.1f} flows/s "
            f"success={step['success_ratio']:.1%} p95={step['latency_ms']['p95']}ms "
            f"429={step['rate_limited']} 503={step['unavailable']}",
            flush=True,
        )
        time.sleep(1)

    failure = next((failure_reason(step) for step in steps if failure_reason(step)), None)
    observations = []
    if any(step["rate_limited"] for step in steps):
        observations.append(
            "The rate limiter engaged; sustained ingest above the configured request rate is rejected with HTTP 429 rather than silently dropped."
        )
    if any(step["unavailable"] for step in steps):
        observations.append(
            "Bounded admission returned HTTP 503 with Retry-After when concurrent classify+persist work exceeded the configured ceiling."
        )
    if any(step["latency_ms"]["p95"] > 1000 for step in steps):
        observations.append(
            "p95 request latency exceeded 1 second, so the console/ingest SLO is not met at that rate."
        )
    if not observations:
        observations.append("No saturation was observed inside the declared range; this does not establish a higher capacity.")

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "config": {
            "base_url": args.base_url,
            "rates": rates,
            "duration": args.duration,
            "workers": args.workers,
            "batch_size": args.batch_size,
        },
        "steps": steps,
        "failure_point": failure,
        "observations": observations,
    }
    os.makedirs(args.output_dir, exist_ok=True)
    json_path = os.path.join(args.output_dir, "load_test_results.json")
    md_path = os.path.join(args.output_dir, "LOAD_TEST_RESULTS.md")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    write_markdown(report, md_path)
    print(f"[load] wrote {json_path}")
    print(f"[load] wrote {md_path}")


if __name__ == "__main__":
    main()
