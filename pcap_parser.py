"""PCAP/PCAPNG packet dissection and bidirectional flow feature extraction."""

import numpy as np
import pandas as pd


def pcap_to_flows(file_stream, max_packets=250_000):
    """Dissect a capture stream into bidirectional model feature rows."""
    try:
        from scapy.error import Scapy_Exception
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
        from scapy.utils import PcapReader
    except ImportError as exc:
        raise RuntimeError("PCAP parsing requires Scapy. Install requirements.txt and retry.") from exc

    flows = {}
    packet_count = 0
    try:
        reader = PcapReader(file_stream)
    except (Scapy_Exception, EOFError, OSError) as exc:
        raise ValueError("Invalid or unsupported PCAP/PCAPNG capture.") from exc
    try:
        for packet in reader:
            packet_count += 1
            if packet_count > max_packets:
                raise ValueError(f"Capture exceeds the {max_packets:,}-packet processing limit.")

            if IP in packet:
                network = packet[IP]
                ip_version = 4
                source_ip, destination_ip = network.src, network.dst
                hop_limit = int(network.ttl)
                ip_header_length = int(network.ihl or 5) * 4
                ip_id = int(network.id)
                ip_flags = str(network.flags)
                ip_protocol = int(network.proto)
                ip_total_length = int(network.len or len(network))
            elif IPv6 in packet:
                network = packet[IPv6]
                ip_version = 6
                source_ip, destination_ip = network.src, network.dst
                hop_limit = int(network.hlim)
                ip_header_length = 40
                ip_id = None
                ip_flags = ""
                ip_protocol = int(network.nh)
                ip_total_length = 40 + int(network.plen or max(0, len(network) - 40))
            else:
                continue

            source_port = destination_port = 0
            transport_name = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(ip_protocol, str(ip_protocol))
            tcp_flags = 0
            tcp_window = None
            udp_length = None
            icmp_type = icmp_code = None

            if TCP in packet:
                transport = packet[TCP]
                source_port, destination_port = int(transport.sport), int(transport.dport)
                tcp_flags = int(transport.flags)
                tcp_window = int(transport.window)
            elif UDP in packet:
                transport = packet[UDP]
                source_port, destination_port = int(transport.sport), int(transport.dport)
                udp_length = int(transport.len or 8)
            elif ICMP in packet:
                transport = packet[ICMP]
                icmp_type, icmp_code = int(transport.type), int(transport.code)
            elif ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet:
                transport = packet[ICMPv6EchoRequest] if ICMPv6EchoRequest in packet else packet[ICMPv6EchoReply]
                icmp_type, icmp_code = int(transport.type), int(transport.code)

            source_endpoint = (source_ip, source_port)
            destination_endpoint = (destination_ip, destination_port)
            endpoints = tuple(sorted((source_endpoint, destination_endpoint)))
            key = (ip_version, ip_protocol, endpoints)
            timestamp = float(packet.time)
            packet_length = int(len(network))

            if key not in flows:
                layers = [layer.__name__ for layer in packet.layers()]
                header = {
                    "summary": packet.summary(),
                    "layers": layers,
                    "ip_version": ip_version,
                    "source": source_ip,
                    "destination": destination_ip,
                    "ttl": hop_limit,
                    "ip_header_length": ip_header_length,
                    "ip_total_length": ip_total_length,
                    "ip_id": ip_id,
                    "ip_flags": ip_flags,
                    "protocol": transport_name,
                    "source_port": source_port or None,
                    "destination_port": destination_port or None,
                    "tcp_flags": str(packet[TCP].flags) if TCP in packet else None,
                    "tcp_window": tcp_window,
                    "udp_length": udp_length,
                    "icmp_type": icmp_type,
                    "icmp_code": icmp_code,
                }
                flows[key] = {
                    "src_ip": source_ip,
                    "dst_ip": destination_ip,
                    "src_port": source_port,
                    "dst_port": destination_port,
                    "protocol": transport_name,
                    "protocol_number": ip_protocol,
                    "first_endpoint": source_endpoint,
                    "timestamps": [],
                    "fwd_times": [],
                    "bwd_times": [],
                    "fwd_sizes": [],
                    "bwd_sizes": [],
                    "fwd_bytes": 0,
                    "bwd_bytes": 0,
                    "syn": 0,
                    "ack": 0,
                    "rst": 0,
                    "fin": 0,
                    "header": header,
                }

            flow = flows[key]
            forward = source_endpoint == flow["first_endpoint"]
            direction = "fwd" if forward else "bwd"
            flow["timestamps"].append(timestamp)
            flow[f"{direction}_times"].append(timestamp)
            flow[f"{direction}_sizes"].append(packet_length)
            flow[f"{direction}_bytes"] += packet_length
            flow["syn"] += int(bool(tcp_flags & 0x02))
            flow["ack"] += int(bool(tcp_flags & 0x10))
            flow["rst"] += int(bool(tcp_flags & 0x04))
            flow["fin"] += int(bool(tcp_flags & 0x01))
    except (Scapy_Exception, EOFError, OSError) as exc:
        raise ValueError("Capture could not be fully decoded as PCAP/PCAPNG.") from exc
    finally:
        reader.close()

    if not flows:
        raise ValueError("No IPv4 or IPv6 packets were found in this capture.")

    def stats(values):
        if not values:
            return 0.0, 0.0, 0.0, 0.0
        return float(np.mean(values)), float(np.std(values)), float(max(values)), float(min(values))

    def inter_arrivals(values):
        ordered = sorted(values)
        return [max(0.0, (right - left) * 1_000_000) for left, right in zip(ordered, ordered[1:])]

    records = []
    details = []
    for flow in flows.values():
        timestamps = flow["timestamps"]
        duration_us = max(0.0, (max(timestamps) - min(timestamps)) * 1_000_000)
        duration_seconds = duration_us / 1_000_000
        fwd_mean, fwd_std, fwd_max, fwd_min = stats(flow["fwd_sizes"])
        bwd_mean, bwd_std, bwd_max, bwd_min = stats(flow["bwd_sizes"])
        all_sizes = flow["fwd_sizes"] + flow["bwd_sizes"]
        packet_mean, packet_std, packet_max, packet_min = stats(all_sizes)
        flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = stats(inter_arrivals(timestamps))
        fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = stats(inter_arrivals(flow["fwd_times"]))
        bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = stats(inter_arrivals(flow["bwd_times"]))
        total_packets = len(timestamps)
        total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]
        row = {
            "Source IP": flow["src_ip"], "Destination IP": flow["dst_ip"],
            "Source Port": flow["src_port"], "Destination Port": flow["dst_port"],
            "Protocol": flow["protocol_number"], "Flow Duration": duration_us,
            "Total Fwd Packets": len(flow["fwd_sizes"]), "Total Backward Packets": len(flow["bwd_sizes"]),
            "Subflow Fwd Packets": len(flow["fwd_sizes"]), "Subflow Bwd Packets": len(flow["bwd_sizes"]),
            "Total Length of Fwd Packets": flow["fwd_bytes"], "Total Length of Bwd Packets": flow["bwd_bytes"],
            "Subflow Fwd Bytes": flow["fwd_bytes"], "Subflow Bwd Bytes": flow["bwd_bytes"],
            "Flow Bytes/s": total_bytes / duration_seconds if duration_seconds else 0,
            "Flow Packets/s": total_packets / duration_seconds if duration_seconds else 0,
            "Fwd Packets/s": len(flow["fwd_sizes"]) / duration_seconds if duration_seconds else 0,
            "Bwd Packets/s": len(flow["bwd_sizes"]) / duration_seconds if duration_seconds else 0,
            "Fwd Packet Length Mean": fwd_mean, "Fwd Packet Length Std": fwd_std,
            "Fwd Packet Length Max": fwd_max, "Fwd Packet Length Min": fwd_min,
            "Bwd Packet Length Mean": bwd_mean, "Bwd Packet Length Std": bwd_std,
            "Bwd Packet Length Max": bwd_max, "Bwd Packet Length Min": bwd_min,
            "Flow IAT Mean": flow_iat_mean, "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max, "Flow IAT Min": flow_iat_min,
            "Fwd IAT Total": sum(inter_arrivals(flow["fwd_times"])), "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std, "Fwd IAT Max": fwd_iat_max, "Fwd IAT Min": fwd_iat_min,
            "Bwd IAT Total": sum(inter_arrivals(flow["bwd_times"])), "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std, "Bwd IAT Max": bwd_iat_max, "Bwd IAT Min": bwd_iat_min,
            "Packet Length Mean": packet_mean, "Packet Length Std": packet_std,
            "Packet Length Max": packet_max, "Packet Length Min": packet_min,
            "Packet Length Variance": packet_std ** 2, "Average Packet Size": packet_mean,
            "Avg Fwd Segment Size": fwd_mean, "Avg Bwd Segment Size": bwd_mean,
            "Down/Up Ratio": len(flow["bwd_sizes"]) / max(1, len(flow["fwd_sizes"])),
            "SYN Flag Count": flow["syn"], "ACK Flag Count": flow["ack"],
            "RST Flag Count": flow["rst"], "FIN Flag Count": flow["fin"],
            "Active Mean": duration_us, "Active Std": 0, "Active Max": duration_us,
            "Active Min": duration_us, "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0,
            "Packet Dissector": flow["header"],
        }
        records.append(row)
        details.append(flow["header"])

    return pd.DataFrame(records), details, packet_count