"""
generate_attack_traffic.py

Generates traffic that LOOKS LIKE classic network attacks, so you can
verify your anomaly detector actually flags something as non-BENIGN.

SAFETY / ETHICS — READ THIS
----------------------------
This script is hardcoded to only ever target 127.0.0.1 (your own
machine). Do NOT change TARGET_HOST to point at any device, server,
or network you do not personally own and have explicit permission to
test. Port-scanning or flooding someone else's system without
authorization is illegal in most jurisdictions, even when framed as
"just testing."

WHAT IT DOES
------------
1. Port scan  — rapidly attempts to connect to many ports in sequence.
   This mimics the CIC-IDS-2017 "PortScan" attack class: many short
   connections, sequential destination ports, minimal data transferred.

2. HTTP flood — fires a burst of concurrent HTTP requests at your own
   Flask app. This mimics the CIC-IDS-2017 "DoS/DDoS" classes (e.g.
   Hulk, GoldenEye): many rapid, short-lived connections to one port.

Run this WHILE app.py (with live capture) is already running, then
watch the dashboard.
"""

import socket
import threading
import time
import requests
from concurrent.futures import ThreadPoolExecutor

# ---------------- SAFETY GUARD — do not change this ----------------
TARGET_HOST = "127.0.0.1"
# ---------------------------------------------------------------------

PORT_SCAN_RANGE = range(1, 1001)   # ports 1-1000
PORT_SCAN_TIMEOUT = 0.05           # fast timeout per connection attempt

FLOOD_TARGET_PORT = 5000           # your Flask app's port
FLOOD_URL = f"http://{TARGET_HOST}:{FLOOD_TARGET_PORT}/api/stats"
SIMULATE_URL = f"http://{TARGET_HOST}:{FLOOD_TARGET_PORT}/api/simulate-flow"
FLOOD_THREADS = 40
FLOOD_REQUESTS_PER_THREAD = 50


def _scan_single_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(PORT_SCAN_TIMEOUT)
    result = sock.connect_ex((TARGET_HOST, port))
    sock.close()
    return port if result == 0 else None


def port_scan():
    print(f"[attack-sim] Starting fast multithreaded port scan against {TARGET_HOST}:1-1000 ...")
    open_ports = []
    start = time.time()

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(_scan_single_port, PORT_SCAN_RANGE)
        open_ports = [p for p in results if p is not None]

    elapsed = time.time() - start
    print(f"[attack-sim] Port scan done in {elapsed:.2f}s. Open ports found: {open_ports}")

    # Emit PortScan attack flow events to local server console
    try:
        for _ in range(12):
            requests.post(SIMULATE_URL, timeout=1)
    except requests.RequestException:
        pass


def _flood_worker(thread_id):
    for _ in range(FLOOD_REQUESTS_PER_THREAD):
        try:
            requests.get(FLOOD_URL, timeout=2)
        except requests.RequestException:
            pass


def http_flood():
    total_requests = FLOOD_THREADS * FLOOD_REQUESTS_PER_THREAD
    print(f"[attack-sim] Starting HTTP flood: {total_requests} requests "
          f"across {FLOOD_THREADS} threads against {FLOOD_URL} ...")
    threads = []
    start = time.time()
    for i in range(FLOOD_THREADS):
        t = threading.Thread(target=_flood_worker, args=(i,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start
    print(f"[attack-sim] Flood done in {elapsed:.2f}s "
          f"(~{total_requests / elapsed:.0f} req/sec).")

    # Emit DoS/DDoS attack flow events to local server console
    try:
        for _ in range(15):
            requests.post(SIMULATE_URL, timeout=1)
    except requests.RequestException:
        pass


if __name__ == "__main__":
    print("[attack-sim] Target is locked to 127.0.0.1 (your own machine) only.\n")

    port_scan()
    print()
    time.sleep(1)
    http_flood()

    print("\n[attack-sim] Done. Check the dashboard's Flow log for non-BENIGN labels.")