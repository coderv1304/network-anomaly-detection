"""Capture-vector and ingestion-label classification tests."""

from domain.capture_metadata import (
    classify_ingestion_vector,
    ingestion_label,
    link_type_metadata,
)


def test_adapter_name_heuristics_cover_enterprise_vectors():
    assert classify_ingestion_vector("eth0")["vector"] == "ethernet"
    assert classify_ingestion_vector("enp3s0")["vector"] == "ethernet"
    assert classify_ingestion_vector("Wi-Fi")["vector"] == "wlan"
    assert classify_ingestion_vector("wlan0")["vector"] == "wlan"
    assert classify_ingestion_vector("wwan0")["vector"] == "wwan"
    assert classify_ingestion_vector("rmnet_data0")["vector"] == "wwan"
    assert classify_ingestion_vector("wg0")["vector"] == "vpn"
    assert classify_ingestion_vector("tun0")["vector"] == "vpn"
    assert classify_ingestion_vector("vEthernet (Default Switch)")["vector"] == "virtual"
    assert classify_ingestion_vector("lo")["vector"] == "loopback"


def test_unknown_adapter_is_not_guessed():
    result = classify_ingestion_vector("mystery0")
    assert result["vector"] == "unknown"
    assert result["basis"] == "name_heuristic_no_match"
    assert result["matched"] is None


def test_link_type_maps_dlt_without_claiming_physical_medium():
    assert link_type_metadata(1)["vector"] == "ethernet"
    assert link_type_metadata(105)["vector"] == "wlan"
    assert link_type_metadata(127)["vector"] == "wlan"
    assert link_type_metadata(108)["vector"] == "loopback"
    unknown = link_type_metadata(9999)
    assert unknown["vector"] == "unknown"
    assert "9999" in unknown["name"]


def test_ingestion_labels_describe_schema_not_marketing():
    zeek = ingestion_label("conn.log.csv", ["id.orig_h", "id.resp_h", "uid"])
    assert "Zeek" in zeek
    cic = ingestion_label("flows.csv", ["Destination Port", "Flow Duration", "Total Fwd Packets"])
    assert "CICFlowMeter" in cic
    generic = ingestion_label("flows.csv", ["src_ip", "dst_ip", "bytes"])
    assert generic == "Generic flow CSV"
    assert ingestion_label("flows.csv", ["whatever"]) == "CSV flow export"

