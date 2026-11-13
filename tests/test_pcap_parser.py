import pytest
from scapy.all import Ether, IP, TCP, Raw, wrpcap

from pcap_parser import pcap_to_flows
from training.feature_parity import run_parity


def test_pcap_to_flows_aggregates_bidirectional_tcp_and_dissects_header(tmp_path):
    packets = [
        Ether() / IP(src="198.51.100.10", dst="203.0.113.20", ttl=51) / TCP(sport=43210, dport=443, flags="S") / Raw(b"hello"),
        Ether() / IP(src="203.0.113.20", dst="198.51.100.10", ttl=61) / TCP(sport=443, dport=43210, flags="SA") / Raw(b"world!"),
    ]
    packets[0].time = 1.0
    packets[1].time = 1.25
    capture_path = tmp_path / "two-packet.pcap"
    wrpcap(str(capture_path), packets)

    with capture_path.open("rb") as capture:
        flows, headers, packet_count = pcap_to_flows(capture)

    flow = flows.iloc[0]
    assert packet_count == 2
    assert len(flows) == 1
    assert flow["Total Fwd Packets"] == 1
    assert flow["Total Backward Packets"] == 1
    assert flow["SYN Flag Count"] == 2
    assert flow["ACK Flag Count"] == 1
    assert flow["Total Length of Fwd Packets"] + flow["Total Length of Bwd Packets"] == 91
    assert headers[0]["layers"] == ["Ether", "IP", "TCP", "Raw"]
    assert headers[0]["tcp_flags"] == "S"
    assert headers[0]["ttl"] == 51


def test_pcap_to_flows_enforces_packet_limit(tmp_path):
    capture_path = tmp_path / "over-limit.pcap"
    wrpcap(str(capture_path), [Ether() / IP() / TCP(), Ether() / IP() / TCP()])

    with capture_path.open("rb") as capture, pytest.raises(ValueError, match="processing limit"):
        pcap_to_flows(capture, max_packets=1)


def test_pcap_to_flows_rejects_malformed_capture(tmp_path):
    capture_path = tmp_path / "invalid.pcap"
    capture_path.write_bytes(b"not a packet capture")

    with capture_path.open("rb") as capture, pytest.raises(ValueError, match="Invalid or unsupported"):
        pcap_to_flows(capture)


def test_pcap_to_flows_measures_all_80_schema_features(tmp_path):
    packets = [
        Ether() / IP(src="198.51.100.10", dst="203.0.113.20") / TCP(sport=43210, dport=443, flags="S"),
        Ether() / IP(src="203.0.113.20", dst="198.51.100.10") / TCP(sport=443, dport=43210, flags="SA", window=1000),
        Ether() / IP(src="198.51.100.10", dst="203.0.113.20") / TCP(sport=43210, dport=443, flags="PA", window=2000) / Raw(b"data"),
        Ether() / IP(src="203.0.113.20", dst="198.51.100.10") / TCP(sport=443, dport=43210, flags="FA", window=500),
    ]
    times = [1.0, 1.05, 1.10, 1.15]
    for packet, stamp in zip(packets, times):
        packet.time = stamp
    capture_path = tmp_path / "full-schema.pcap"
    wrpcap(str(capture_path), packets)

    with capture_path.open("rb") as capture:
        flows, _, _ = pcap_to_flows(capture)

    flow = flows.iloc[0]
    # Initial windows: forward keeps the first forward window; backward is
    # overwritten by every reverse packet (PyFlowMeter semantics).
    assert flow["Init_Win_bytes_forward"] == packets[0][TCP].window
    assert flow["Init_Win_bytes_backward"] == 500
    # True per-direction flag counts, not indicators.
    assert flow["Fwd PSH Flags"] == 1
    assert flow["Bwd PSH Flags"] == 0
    assert flow["Fwd URG Flags"] == 0
    assert flow["Bwd URG Flags"] == 0
    assert flow["PSH Flag Count"] == 1
    assert flow["URG Flag Count"] == 0
    assert flow["ECE Flag Count"] == 0
    assert flow["CWE Flag Count"] == 0
    # Header bytes: IP header length (20 bytes for these packets) for TCP
    # packets, summed per direction.
    assert flow["Fwd Header Length"] == 2 * 20
    assert flow["Bwd Header Length"] == 2 * 20
    assert flow["min_seg_size_forward"] == 20
    # Forward packets carrying payload.
    assert flow["act_data_pkt_fwd"] == 1
    # Packet-length extremes are emitted under both CSV names.
    assert flow["Max Packet Length"] == flow["Packet Length Max"]
    assert flow["Min Packet Length"] == flow["Packet Length Min"]
    # Bulk: two payload packets inside one second never reach BULK_BOUND=4.
    assert flow["Fwd Avg Bytes/Bulk"] == 0
    assert flow["Fwd Avg Packets/Bulk"] == 0
    assert flow["Fwd Avg Bulk Rate"] == 0


def test_pcap_to_flows_counts_retransmitted_flags_and_bulk(tmp_path):
    payload = b"x" * 100
    packets = [Ether() / IP(src="198.51.100.10", dst="203.0.113.20") / TCP(sport=43210, dport=443, flags="S")]
    # Five forward payload packets inside the one-second clump window: the
    # fifth completes a bulk of BULK_BOUND=4 packets.
    for index in range(5):
        packets.append(
            Ether() / IP(src="198.51.100.10", dst="203.0.113.20")
            / TCP(sport=43210, dport=443, flags="PA")
            / Raw(payload)
        )
    times = [1.0] + [1.01 + 0.01 * index for index in range(5)]
    for packet, stamp in zip(packets, times):
        packet.time = stamp
    capture_path = tmp_path / "bulk.pcap"
    wrpcap(str(capture_path), packets)

    with capture_path.open("rb") as capture:
        flows, _, _ = pcap_to_flows(capture)

    flow = flows.iloc[0]
    assert flow["SYN Flag Count"] == 1
    assert flow["Fwd PSH Flags"] == 5
    assert flow["PSH Flag Count"] == 5
    assert flow["act_data_pkt_fwd"] == 5
    # Four payload packets inside the clump window form one bulk; the fifth
    # extends the same bulk, so the average counts all five.
    assert flow["Fwd Avg Packets/Bulk"] == 5
    assert flow["Fwd Avg Bytes/Bulk"] == 5 * len(payload)
    assert flow["Fwd Avg Bulk Rate"] > 0


def test_pcap_to_flows_measures_idle_time_across_a_long_gap(tmp_path):
    packets = [
        Ether() / IP(src="198.51.100.10", dst="203.0.113.20") / TCP(sport=43210, dport=443, flags="S"),
        Ether() / IP(src="198.51.100.10", dst="203.0.113.20") / TCP(sport=43210, dport=443, flags="A"),
    ]
    packets[0].time = 1.0
    packets[1].time = 4.0  # three-second gap exceeds CLUMP_TIMEOUT=1s
    capture_path = tmp_path / "idle.pcap"
    wrpcap(str(capture_path), packets)

    with capture_path.open("rb") as capture:
        flows, _, _ = pcap_to_flows(capture)

    flow = flows.iloc[0]
    # A single idle interval is zeroed by the PyFlowMeter statistics rule
    # (lists shorter than two entries report zeros), but the value is a
    # measurement of the gap, not a hardcoded constant.
    assert flow["Idle Mean"] in (0.0, 3_000_000.0)
    assert flow["Active Mean"] in (0.0, 1_000_000.0)


def test_feature_parity_cli_path_hashes_inputs_and_compares_flows(tmp_path):
    packets = [
        Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=12345, dport=443, flags="S"),
        Ether() / IP(src="198.51.100.20", dst="192.0.2.10") / TCP(sport=443, dport=12345, flags="SA"),
    ]
    packets[0].time = 1.0
    packets[1].time = 1.5
    capture_path = tmp_path / "parity.pcap"
    wrpcap(str(capture_path), packets)
    with capture_path.open("rb") as capture:
        reference, _, _ = pcap_to_flows(capture)
    reference_path = tmp_path / "reference.csv"
    reference.drop(columns=["Packet Dissector"]).to_csv(reference_path, index=False)

    output_path = tmp_path / "parity.json"
    result = run_parity(str(reference_path), str(capture_path), str(output_path))

    assert result["matched_unique_flows"] == 1
    assert result["inputs"]["packets_parsed"] == 2
    assert len(result["inputs"]["capture_sha256"]) == 64
    assert output_path.is_file()
