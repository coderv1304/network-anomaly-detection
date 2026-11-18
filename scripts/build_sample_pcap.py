"""Build the tiny deterministic PCAP used by the parser parity check.

The capture holds exactly two behaviours and no real host traffic:

* one normal TCP handshake (SYN, SYN-ACK, ACK, data, ACK) between a simulated
  client and server;
* one 20-port TCP SYN scan burst from a simulated scanner.

Every address is documentation or RFC1918 space. The file is small on purpose:
it exercises the dissector, not detection accuracy.

Usage:
    venv/Scripts/python.exe scripts/build_sample_pcap.py
"""

from __future__ import annotations

import argparse
import os

from scapy.all import IP, TCP, Raw, wrpcap

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_OUTPUT = os.path.join(PROJECT_ROOT, "tests", "fixtures", "sample_synthetic.pcap")
BASE_TIME = 1_767_225_600.0  # 2026-01-01T00:00:00Z, an epoch multiple of 300

CLIENT = "192.168.10.21"
SERVER = "198.51.100.50"
CLIENT_PORT = 54321
SERVER_PORT = 443
SCANNER = "172.16.0.11"
SCAN_TARGET = "192.168.10.50"
SCAN_PORTS = range(20, 40)


def packets() -> list:
    """Return the handshake followed by the scan burst."""
    client_tcp = dict(sport=CLIENT_PORT, dport=SERVER_PORT, window=64240)
    server_tcp = dict(sport=SERVER_PORT, dport=CLIENT_PORT, window=65160)
    exchange = [
        # SYN
        IP(src=CLIENT, dst=SERVER) / TCP(flags="S", seq=1000, **client_tcp),
        # SYN-ACK
        IP(src=SERVER, dst=CLIENT) / TCP(flags="SA", seq=5000, ack=1001, **server_tcp),
        # ACK
        IP(src=CLIENT, dst=SERVER) / TCP(flags="A", seq=1001, ack=5001, **client_tcp),
        # Application data (200 bytes) and its acknowledgement.
        IP(src=CLIENT, dst=SERVER)
        / TCP(flags="PA", seq=1001, ack=5001, **client_tcp)
        / Raw(load=b"x" * 200),
        IP(src=SERVER, dst=CLIENT) / TCP(flags="A", seq=5001, ack=1201, **server_tcp),
    ]
    captured = []
    for index, packet in enumerate(exchange):
        packet.time = BASE_TIME + index * 0.05
        captured.append(packet)

    for index, port in enumerate(SCAN_PORTS):
        packet = IP(src=SCANNER, dst=SCAN_TARGET) / TCP(
            flags="S", sport=40000 + index, dport=port, seq=7000 + index, window=1024
        )
        packet.time = BASE_TIME + 1.0 + index * 0.02
        captured.append(packet)
    return captured


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    captured = packets()
    wrpcap(args.output, captured)
    size = os.path.getsize(args.output)
    print({"path": args.output, "packets": len(captured), "bytes": size})
    if size >= 50 * 1024:
        raise SystemExit("Synthetic PCAP exceeds the 50 KB budget")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
