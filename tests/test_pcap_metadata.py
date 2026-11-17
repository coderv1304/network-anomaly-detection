"""PCAP metadata describes only what the capture records."""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

from pcap_parser import dissect_pcap, pcap_to_flows


def _capture(tmp_path, name="meta.pcap"):
    packets = [
        Ether() / IP(src="198.51.100.10", dst="203.0.113.20") / TCP(sport=43210, dport=443, flags="S") / Raw(b"hello"),
        Ether() / IP(src="203.0.113.20", dst="198.51.100.10") / TCP(sport=443, dport=43210, flags="SA") / Raw(b"world!"),
    ]
    packets[0].time = 10.0
    packets[1].time = 10.5
    path = tmp_path / name
    wrpcap(str(path), packets)
    return path


def test_dissect_pcap_reports_container_link_type_and_counts(tmp_path):
    path = _capture(tmp_path)
    with path.open("rb") as capture:
        flows, details, metadata = dissect_pcap(capture)

    assert len(flows) == 1
    assert len(details) == 1
    assert metadata["format"] == "pcap"
    assert metadata["reader"] == "PcapReader"
    assert metadata["link_type"]["value"] == 1
    assert metadata["link_type"]["vector"] == "ethernet"
    assert metadata["interface_vector"] == "ethernet"
    assert metadata["interface_vector_basis"] == "link_type"
    assert metadata["frame_count"] == 2
    assert metadata["captured_bytes"] > 0
    assert metadata["wire_bytes"] >= metadata["captured_bytes"]
    assert metadata["truncated_frames"] == 0
    assert metadata["non_ip_frames"] == 0
    assert metadata["duration_seconds"] == 0.5
    assert metadata["protocol_counts"]["TCP"] == 2
    assert metadata["flow_count"] == 1
    assert metadata["capture_interface"] is None
    assert metadata["snaplen"] == 65535


def test_legacy_wrapper_preserves_three_tuple_shape(tmp_path):
    path = _capture(tmp_path, "legacy.pcap")
    with path.open("rb") as capture:
        flows, details, count = pcap_to_flows(capture)
    assert len(flows) == 1
    assert len(details) == 1
    assert count == 2
