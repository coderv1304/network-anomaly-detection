"""PCAP/PCAPNG packet dissection and bidirectional flow feature extraction.

The upload path emits the full 80-feature CIC-IDS-2017 serving schema. Features
that this module computes per packet (bulk statistics, active/idle times,
per-direction header bytes, initial TCP windows, data-packet counts) port the
PyFlowMeter reference implementation semantics so the upload path and the
live capture path measure the same things; see ``training/parity_live_capture.py``.

Known, documented divergences from PyFlowMeter (kept deliberately because the
upload path follows the training CSV semantics):

* TCP flag features are true per-flow counts here; PyFlowMeter's
  ``FlagCount.has_flag`` returns a 0/1 indicator, so it under-counts flags on
  flows with retransmissions.
* ``CWE Flag Count`` counts CWR packets here; PyFlowMeter aliases it to
  ``fwd_urg_flags`` (an upstream bug).
* IPv6 flows are retained here; the live path's BPF filter drops them.
"""

import numpy as np
import pandas as pd

from capture_metadata import describe_pcap_link_type

# Reference state-machine constants, mirrored from pyflowmeter.constants so the
# upload path and the live path agree by construction.
CLUMP_TIMEOUT = 1.0  # seconds between packets that split subflows/bulks
ACTIVE_TIMEOUT = 0.005  # seconds
BULK_BOUND = 4  # packets that must pile up before a bulk is recognised


def pcap_to_flows(file_stream, max_packets=250_000):
    """Dissect a capture into model rows, preserving the legacy return shape.

    Returns ``(flows, packet_headers, packet_count)``. New callers that need
    capture provenance should use :func:`dissect_pcap`, which returns the same
    first two values plus a metadata dictionary.
    """
    flows, details, metadata = dissect_pcap(file_stream, max_packets=max_packets)
    return flows, details, metadata["frame_count"]


def dissect_pcap(file_stream, max_packets=250_000):
    """Dissect a capture stream into rows, headers, and capture metadata.

    ``metadata`` describes only what the capture actually records: container
    format, link type, snaplen, frame/byte counts, truncation, timestamps and
    protocol mix. It deliberately does not name a capture interface, because a
    PCAP file does not reliably carry one. It also does not claim wire bytes
    when the capture was truncated; ``wire_bytes`` and ``captured_bytes`` are
    reported separately.
    """
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

    reader_class = type(reader).__name__
    container_format = "pcapng" if "ng" in reader_class.lower() else "pcap"
    link_type = getattr(reader, "linktype", None)
    if isinstance(link_type, (set, list, tuple)):
        link_type = sorted(link_type)[0] if link_type else None
    snaplen = getattr(reader, "snaplen", None)
    if isinstance(snaplen, (set, list, tuple)):
        snaplen = min(snaplen) if snaplen else None
    metadata = {
        **describe_pcap_link_type(container_format, link_type),
        "reader": reader_class,
        "snaplen": snaplen,
        "frame_count": 0,
        "captured_bytes": 0,
        "wire_bytes": 0,
        "truncated_frames": 0,
        "non_ip_frames": 0,
        "first_packet_at": None,
        "last_packet_at": None,
        "duration_seconds": None,
        "protocol_counts": {},
        "capture_interface": None,
        "capture_interface_note": (
            "A PCAP/PCAPNG file does not reliably carry the capture adapter name. "
            "The interface is reported as unknown rather than guessed."
        ),
    }

    def _bump(name):
        metadata["protocol_counts"][name] = metadata["protocol_counts"].get(name, 0) + 1

    try:
        for packet in reader:
            packet_count += 1
            if packet_count > max_packets:
                raise ValueError(f"Capture exceeds the {max_packets:,}-packet processing limit.")

            captured_length = len(packet)
            wire_length = int(getattr(packet, "wirelen", captured_length) or captured_length)
            timestamp = float(packet.time)
            metadata["frame_count"] += 1
            metadata["captured_bytes"] += captured_length
            metadata["wire_bytes"] += wire_length
            if wire_length > captured_length:
                metadata["truncated_frames"] += 1
            if metadata["first_packet_at"] is None or timestamp < metadata["first_packet_at"]:
                metadata["first_packet_at"] = timestamp
            if metadata["last_packet_at"] is None or timestamp > metadata["last_packet_at"]:
                metadata["last_packet_at"] = timestamp

            if IP in packet:
                _bump("IPv4")
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
                _bump("IPv6")
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
                metadata["non_ip_frames"] += 1
                continue

            source_port = destination_port = 0
            transport_name = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(ip_protocol, str(ip_protocol))
            _bump(transport_name)
            tcp_flags = 0
            tcp_window = None
            udp_length = None
            icmp_type = icmp_code = None
            payload_size = 0

            if TCP in packet:
                transport = packet[TCP]
                source_port, destination_port = int(transport.sport), int(transport.dport)
                tcp_flags = int(transport.flags)
                tcp_window = int(transport.window)
                payload_size = len(bytes(transport.payload))
            elif UDP in packet:
                transport = packet[UDP]
                source_port, destination_port = int(transport.sport), int(transport.dport)
                udp_length = int(transport.len or 8)
                payload_size = len(bytes(transport.payload))
            elif ICMP in packet:
                transport = packet[ICMP]
                icmp_type, icmp_code = int(transport.type), int(transport.code)
            elif ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet:
                transport = packet[ICMPv6EchoRequest] if ICMPv6EchoRequest in packet else packet[ICMPv6EchoReply]
                icmp_type, icmp_code = int(transport.type), int(transport.code)

            # PyFlowMeter's _header_size(): IP header bytes for TCP packets,
            # the fixed 8-byte UDP/transport header otherwise.
            header_size = ip_header_length if TCP in packet else 8

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
                    # True per-direction flag counts (training-CSV semantics).
                    "fwd_psh": 0, "bwd_psh": 0, "fwd_urg": 0, "bwd_urg": 0,
                    "psh": 0, "urg": 0, "ece": 0, "cwr": 0,
                    # Initial TCP windows, PyFlowMeter semantics: forward is the
                    # first forward window while it is still 0; backward is
                    # overwritten by every reverse packet.
                    "init_fwd_win": 0,
                    "init_bwd_win": 0,
                    # Per-packet measurements in arrival order.
                    "fwd_header_bytes": 0,
                    "bwd_header_bytes": 0,
                    "fwd_header_sizes": [],
                    "fwd_payload_pkts": 0,
                    # Bulk state machines (PyFlowMeter semantics).
                    "bulk": {
                        "fwd": _new_bulk_state(),
                        "bwd": _new_bulk_state(),
                    },
                    # Active/idle state machine (PyFlowMeter semantics).
                    "latest_ts": 0.0,
                    "active_state": {"start_active": 0.0, "last_active": 0.0},
                    "active_list": [],
                    "idle_list": [],
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
            flow["psh"] += int(bool(tcp_flags & 0x08))
            flow["urg"] += int(bool(tcp_flags & 0x20))
            flow["ece"] += int(bool(tcp_flags & 0x40))
            flow["cwr"] += int(bool(tcp_flags & 0x80))
            if forward:
                flow["fwd_psh"] += int(bool(tcp_flags & 0x08))
                flow["fwd_urg"] += int(bool(tcp_flags & 0x20))
                flow["fwd_header_bytes"] += header_size
                flow["fwd_header_sizes"].append(header_size)
                if payload_size > 0:
                    flow["fwd_payload_pkts"] += 1
            else:
                flow["bwd_psh"] += int(bool(tcp_flags & 0x08))
                flow["bwd_urg"] += int(bool(tcp_flags & 0x20))
                flow["bwd_header_bytes"] += header_size

            # Bulk accounting runs before the subflow/active-idle update, in
            # the same per-packet order as PyFlowMeter's Flow.add_packet().
            _update_bulk(flow, forward, payload_size, timestamp)

            # Subflow / active-idle update uses the previous packet's time.
            last_ts = flow["latest_ts"] if flow["latest_ts"] != 0 else timestamp
            gap = timestamp - last_ts
            if gap > CLUMP_TIMEOUT:
                _update_active_idle(flow, gap)

            flow["latest_ts"] = max(timestamp, flow["latest_ts"])

            if TCP in packet:
                if forward and flow["init_fwd_win"] == 0:
                    flow["init_fwd_win"] = tcp_window
                elif not forward:
                    flow["init_bwd_win"] = tcp_window
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

    def pyfm_stats(values):
        """PyFlowMeter get_statistics(): zeroed unless the list has 2+ entries."""
        if len(values) > 1:
            return {
                "mean": float(np.mean(values)),
                "std": float(np.sqrt(np.var(values))),
                "max": max(values),
                "min": min(values),
            }
        return {"mean": 0.0, "std": 0.0, "max": 0, "min": 0}

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

        active_stat = pyfm_stats(flow["active_list"])
        idle_stat = pyfm_stats(flow["idle_list"])
        fwd_bulk = _bulk_summary(flow["bulk"]["fwd"])
        bwd_bulk = _bulk_summary(flow["bulk"]["bwd"])

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
            "Fwd PSH Flags": flow["fwd_psh"], "Bwd PSH Flags": flow["bwd_psh"],
            "Fwd URG Flags": flow["fwd_urg"], "Bwd URG Flags": flow["bwd_urg"],
            "PSH Flag Count": flow["psh"], "URG Flag Count": flow["urg"],
            "ECE Flag Count": flow["ece"], "CWE Flag Count": flow["cwr"],
            "Init_Win_bytes_forward": flow["init_fwd_win"],
            "Init_Win_bytes_backward": flow["init_bwd_win"],
            "act_data_pkt_fwd": flow["fwd_payload_pkts"],
            "Fwd Header Length": flow["fwd_header_bytes"],
            "Bwd Header Length": flow["bwd_header_bytes"],
            "min_seg_size_forward": min(flow["fwd_header_sizes"]) if flow["fwd_header_sizes"] else 0,
            "Fwd Avg Bytes/Bulk": fwd_bulk["bytes_per_bulk"],
            "Fwd Avg Packets/Bulk": fwd_bulk["packets_per_bulk"],
            "Fwd Avg Bulk Rate": fwd_bulk["bulk_rate"],
            "Bwd Avg Bytes/Bulk": bwd_bulk["bytes_per_bulk"],
            "Bwd Avg Packets/Bulk": bwd_bulk["packets_per_bulk"],
            "Bwd Avg Bulk Rate": bwd_bulk["bulk_rate"],
            "Active Mean": float(active_stat["mean"]), "Active Std": float(active_stat["std"]),
            "Active Max": float(active_stat["max"]), "Active Min": float(active_stat["min"]),
            "Idle Mean": float(idle_stat["mean"]), "Idle Std": float(idle_stat["std"]),
            "Idle Max": float(idle_stat["max"]), "Idle Min": float(idle_stat["min"]),
            "Packet Dissector": flow["header"],
        }
        # The training CSV duplicates the packet-length extremes under second
        # names; emit both so the schema is complete without mapper tricks.
        row["Max Packet Length"] = packet_max
        row["Min Packet Length"] = packet_min
        # CICFlowMeter exports "Fwd Header Length" twice (pandas renames the
        # second copy "Fwd Header Length.1") and the two columns are identical
        # in the published CSVs. Mirroring the duplicate keeps the upload
        # schema at 80 features instead of leaving the column to imputation.
        row["Fwd Header Length.1"] = flow["fwd_header_bytes"]
        records.append(row)
        details.append(flow["header"])

    if metadata["first_packet_at"] is not None and metadata["last_packet_at"] is not None:
        metadata["duration_seconds"] = round(
            max(0.0, metadata["last_packet_at"] - metadata["first_packet_at"]), 6
        )
    metadata["flow_count"] = len(records)
    metadata["interface_vector"] = metadata["link_type"]["vector"]
    metadata["interface_vector_basis"] = "link_type"
    return pd.DataFrame(records), details, metadata


def _new_bulk_state():
    return {
        "start_tmp": 0.0,
        "last_timestamp": 0.0,
        "count_tmp": 0,
        "size_tmp": 0,
        "count": 0,
        "packet_count": 0,
        "size": 0,
        "duration": 0.0,
    }


def _update_bulk(flow, forward, payload_size, timestamp):
    """Port of PyFlowMeter Flow.update_flow_bulk()."""
    if payload_size == 0:
        return
    state = flow["bulk"]["fwd" if forward else "bwd"]
    other_last = flow["bulk"]["bwd" if forward else "fwd"]["last_timestamp"]
    if other_last > state["start_tmp"]:
        state["start_tmp"] = 0.0
    if state["start_tmp"] == 0:
        state["start_tmp"] = timestamp
        state["last_timestamp"] = timestamp
        state["count_tmp"] = 1
        state["size_tmp"] = payload_size
    else:
        if (timestamp - state["last_timestamp"]) > CLUMP_TIMEOUT:
            state["start_tmp"] = timestamp
            state["last_timestamp"] = timestamp
            state["count_tmp"] = 1
            state["size_tmp"] = payload_size
        else:  # Add to bulk
            state["count_tmp"] += 1
            state["size_tmp"] += payload_size
            if state["count_tmp"] == BULK_BOUND:
                state["count"] += 1
                state["packet_count"] += state["count_tmp"]
                state["size"] += state["size_tmp"]
                state["duration"] += timestamp - state["start_tmp"]
            elif state["count_tmp"] > BULK_BOUND:
                state["packet_count"] += 1
                state["size"] += payload_size
                state["duration"] += timestamp - state["last_timestamp"]
        state["last_timestamp"] = timestamp


def _update_active_idle(flow, gap):
    """Port of PyFlowMeter Flow.update_active_idle(), gap in seconds."""
    state = flow["active_state"]
    if (gap - state["last_active"]) > ACTIVE_TIMEOUT:
        duration = abs(float(state["last_active"] - state["start_active"]))
        if duration > 0:
            flow["active_list"].append(1e6 * duration)
        flow["idle_list"].append(1e6 * (gap - state["last_active"]))
        state["start_active"] = gap
        state["last_active"] = gap
    else:
        state["last_active"] = gap


def _bulk_summary(state):
    """Port of PyFlowMeter FlowBytes bulk aggregators (patched rate guard)."""
    count = state["count"]
    bytes_per_bulk = state["size"] / count if count != 0 else 0
    packets_per_bulk = state["packet_count"] / count if count != 0 else 0
    bulk_rate = state["size"] / state["duration"] if count != 0 and state["duration"] != 0 else 0
    return {
        "bytes_per_bulk": float(bytes_per_bulk),
        "packets_per_bulk": float(packets_per_bulk),
        "bulk_rate": float(bulk_rate),
    }
