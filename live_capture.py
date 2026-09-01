"""
live_capture.py

Sniffs live network traffic, groups packets into bidirectional flows,
computes CICFlowMeter-style statistical features per flow, and POSTs
each completed flow to the Flask backend's /api/flows endpoint for
real-time classification, storage, and dashboard push.

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

import sys
import time

try:
    from pyflowmeter.sniffer import create_sniffer
except ImportError:
    print("pyflowmeter is not installed. Run: pip install pyflowmeter")
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

# ---------------- CONFIGURE THIS ----------------
# On Windows, list your interfaces first if you're not sure of the
# exact name — see the execution guide for the command. Common values
# look like "Wi-Fi" or "Ethernet", but Npcap sometimes requires the
# full adapter GUID instead.
INTERFACE = "MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz PCIe Adapter"  # confirmed active adapter

# Must match LIVE_CAPTURE_API_KEY set on the app.py side. pyflowmeter
# can't set custom HTTP headers, so the key is passed as a URL query
# param instead — app.py accepts either form.
API_KEY = "dev-only-change-me"
BACKEND_URL = f"http://127.0.0.1:5000/api/flows?api_key={API_KEY}"

POLL_SECONDS = 1  # how often this script stays alive to check for Ctrl+C
# --------------------------------------------------


def main():
    print(f"[live_capture] Interface : {INTERFACE}")
    print(f"[live_capture] Sending flows to: {BACKEND_URL.split('?')[0]}")
    print("[live_capture] Press Ctrl+C to stop.\n")

    sniffer = create_sniffer(
        input_interface=INTERFACE,
        to_csv=False,
        server_endpoint=BACKEND_URL,
    )

    sniffer.start()
    try:
        while True:
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("\n[live_capture] Stopping...")
        sniffer.stop()
        sniffer.join()
        print("[live_capture] Stopped cleanly.")


if __name__ == "__main__":
    main()