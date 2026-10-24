import pytest
from scapy.all import Ether, IP, TCP, Raw, wrpcap

from pcap_parser import pcap_to_flows


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