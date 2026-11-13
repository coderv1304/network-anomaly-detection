"""
live_capture.py

Standalone live-traffic collector. Sniffs live network traffic on one or more
adapters, groups packets into bidirectional flows, computes
CICFlowMeter-style statistical features per flow, and POSTs each completed
flow to the Flask backend's /api/flows endpoint for real-time classification,
storage, and dashboard push.

Works on any connectivity — Wi-Fi, Ethernet, mobile hotspot / USB tethering,
VPN, virtual adapters, and loopback — because interface selection goes
through ``capture_interfaces``:

    NETSHIELD_CAPTURE_INTERFACE=auto        default-route adapter (recommended)
    NETSHIELD_CAPTURE_INTERFACE=all          every adapter with an IP address
    NETSHIELD_CAPTURE_INTERFACE=loopback    loopback only
    NETSHIELD_CAPTURE_INTERFACE="Wi-Fi, Ethernet"   explicit list

Run ``python live_capture.py --list`` to see every adapter this machine can
capture on.

REQUIREMENTS
------------
- Wireshark/Npcap installed (Npcap is bundled with the Wireshark
  installer — make sure "Install Npcap" was checked).
- pip install pyflowmeter
- app.py must already be running (python app.py) before you start this.
- MUST be run from a terminal with Administrator privileges on
  Windows — packet capture needs privileged access.

If pyflowmeter's create_sniffer() signature differs from what's used
below (it's a small, infrequently-updated package), run:
    python -c "from pyflowmeter.sniffer import create_sniffer; help(create_sniffer)"
and adjust the keyword arguments in main() to match.
"""

import argparse
import os
import sys
import time
from urllib.parse import quote

APP_ENV = os.environ.get("NETSHIELD_ENV", "development").strip().lower()
if APP_ENV == "production":
    raise SystemExit(
        "The bundled PyFlowMeter client is for local demos only. "
        "Production collectors must use TLS and an X-API-Key header."
    )
API_KEY = os.environ.get("LIVE_CAPTURE_API_KEY", "").strip()
if not API_KEY:
    raise SystemExit("Set LIVE_CAPTURE_API_KEY to the same value used by app.py before starting capture.")

try:
    from pyflowmeter.sniffer import create_sniffer
except ImportError:
    print("pyflowmeter is not installed. Run: pip install pyflowmeter")
    sys.exit(1)

try:
    from capture_interfaces import (
        format_capture_interfaces,
        resolve_capture_interfaces,
    )
except ImportError:
    print("scapy is not installed. Run: pip install scapy")
    sys.exit(1)


# ---------------------------------------------------------------------
# Runtime patch for a known pyflowmeter bug: get_bulk_rate() divides by
# *_bulk_duration without checking it's non-zero (it only checks
# *_bulk_count), causing a ZeroDivisionError crash on short flows with
# no real bulk transfer. This patches the bug in memory every time this
# script runs, so the fix travels with the project instead of only
# living inside venv/ (which pip install would overwrite anyway).
# ---------------------------------------------------------------------
def _patch_pyflowmeter_bulk_rate_bug():
    from pyflowmeter.features.context.packet_direction import PacketDirection
    from pyflowmeter.features.flow_bytes import FlowBytes

    def patched_get_bulk_rate(self, packet_direction):
        if packet_direction == PacketDirection.FORWARD:
            if self.feature.forward_bulk_count != 0 and self.feature.forward_bulk_duration != 0:
                return self.feature.forward_bulk_size / self.feature.forward_bulk_duration
        else:
            if self.feature.backward_bulk_count != 0 and self.feature.backward_bulk_duration != 0:
                return self.feature.backward_bulk_size / self.feature.backward_bulk_duration
        return 0

    FlowBytes.get_bulk_rate = patched_get_bulk_rate
    print("[live_capture] Applied patch for pyflowmeter get_bulk_rate ZeroDivisionError.")


_patch_pyflowmeter_bulk_rate_bug()

# Configure the same explicit key for app.py and this local-only collector.
# PyFlowMeter cannot send an API-key header, so the loopback demo passes the
# key in the query string. Production service keys are header-only.
BACKEND_URL = f"http://127.0.0.1:5000/api/flows?api_key={quote(API_KEY, safe='')}"

POLL_SECONDS = 1  # how often this script stays alive to check for Ctrl+C


def main():
    parser = argparse.ArgumentParser(
        description="Standalone live-capture collector for the NetShield backend.",
        epilog="Interface selection accepts 'auto' (default-route adapter), "
        "'all', 'loopback', or a comma-separated list of names/descriptions/IPs.",
    )
    parser.add_argument(
        "--interface",
        default=os.environ.get("NETSHIELD_CAPTURE_INTERFACE", "auto"),
        help="Interface selection (default: NETSHIELD_CAPTURE_INTERFACE or 'auto').",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List every adapter this machine can capture on and exit.",
    )
    args = parser.parse_args()

    if args.list:
        print(format_capture_interfaces())
        return 0

    resolved, unknown = resolve_capture_interfaces(args.interface)
    if unknown:
        print(f"[live_capture] WARNING: entries not in the adapter list: {', '.join(unknown)}")
    if not resolved:
        print(f"[live_capture] No capture interface matched {args.interface!r}.")
        print("[live_capture] Adapters on this machine:")
        print(format_capture_interfaces())
        return 3

    print(f"[live_capture] Interface(s): {', '.join(resolved)}")
    print(f"[live_capture] Sending flows to: {BACKEND_URL.split('?')[0]}")
    print("[live_capture] Press Ctrl+C to stop.\n")

    sniffers = []
    for name in resolved:
        try:
            sniffer = create_sniffer(
                input_interface=name,
                to_csv=False,
                server_endpoint=BACKEND_URL,
            )
            sniffers.append(sniffer)
            sniffer.start()
            print(f"[live_capture] listening on {name}")
        except Exception as err:  # noqa: BLE001 - keep other adapters running
            print(f"[live_capture] FAILED to start capture on {name}: {err}")

    if not sniffers:
        print("[live_capture] All interfaces failed to start.")
        return 3

    try:
        while True:
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("\n[live_capture] Stopping...")
        for sniffer in sniffers:
            try:
                sniffer.stop()
                sniffer.join()
            except Exception as err:  # noqa: BLE001
                print(f"[live_capture] Error stopping a sniffer: {err}")
        print("[live_capture] Stopped cleanly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
