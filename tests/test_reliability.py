"""Reliability controls for S2: readiness, request IDs, metrics, limits,
backpressure, structured logs, and full feature-mapper coverage."""

import json
import logging
import os

from prometheus_client import REGISTRY

import app as app_module
from feature_mapper import normalize_flow_features
from monitoring.structured_logging import JsonFormatter


def _client():
    return app_module.app.test_client()


def _sample(name, labels=None):
    return REGISTRY.get_sample_value(name, labels or {})


def _valid_flow():
    return {
        "src_ip": "10.1.2.3",
        "dst_ip": "10.9.8.7",
        "src_port": 51515,
        "dst_port": 443,
        "protocol": 6,
        "flow_duration": 1200,
        "tot_fwd_pkts": 4,
        "tot_bwd_pkts": 3,
        "flow_byts_s": 120.0,
        "flow_pkts_s": 6.0,
    }


def test_healthz_and_readyz():
    client = _client()
    assert client.get("/healthz").status_code == 200

    response = client.get("/readyz")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ready"
    assert payload["ingest"]["max_inflight"] >= 1


def test_request_id_is_echoed_and_generated():
    client = _client()

    echoed = client.get("/healthz", headers={"X-Request-ID": "trace-abc-123"})
    assert echoed.headers.get("X-Request-ID") == "trace-abc-123"

    generated = client.get("/healthz")
    assert generated.headers.get("X-Request-ID")


def test_ingest_updates_metrics_and_request_id():
    client = _client()
    before = _sample("netshield_ingest_requests_total", {"outcome": "accepted"}) or 0.0

    response = client.post("/api/flows", json=_valid_flow())
    assert response.status_code == 201, response.get_data(as_text=True)
    assert response.headers.get("X-Request-ID")

    after = _sample("netshield_ingest_requests_total", {"outcome": "accepted"}) or 0.0
    assert after == before + 1

    assert _sample("netshield_ingest_flows_total", {"outcome": "accepted"}) >= 1
    assert _sample("netshield_flow_store_rows") >= 1


def test_backpressure_returns_503_with_retry_after():
    client = _client()
    slots = app_module.INGEST_MAX_INFLIGHT
    acquired = 0
    try:
        for _ in range(slots):
            if app_module._INGEST_ADMISSION.acquire(blocking=False):
                acquired += 1
        assert acquired == slots, "could not saturate the admission semaphore"

        response = client.post("/api/flows", json=_valid_flow())
        assert response.status_code == 503
        assert response.headers.get("Retry-After")
        payload = response.get_json()
        assert payload["retry_after_seconds"] >= 1
        assert payload["request_id"]
    finally:
        for _ in range(acquired):
            app_module._INGEST_ADMISSION.release()


def test_rate_limit_handler_returns_json_and_retry_after():
    class _Limited(Exception):
        retry_after = 60

    with app_module.app.test_request_context("/api/flows", method="POST"):
        response, status, headers = app_module.rate_limit_exceeded(_Limited())

    assert status == 429
    assert headers["Retry-After"] == "60"
    payload = json.loads(response.get_data(as_text=True))
    assert payload["error"]
    assert payload["retry_after_seconds"] == 60


def test_json_formatter_emits_one_object_with_fields():
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="ingest.accepted",
        args=(),
        exc_info=None,
    )
    record.event = "ingest"
    record.outcome = "accepted"
    record.flow_count = 3

    payload = json.loads(JsonFormatter().format(record))
    assert payload["message"] == "ingest.accepted"
    assert payload["level"] == "INFO"
    assert payload["event"] == "ingest"
    assert payload["outcome"] == "accepted"
    assert payload["flow_count"] == 3
    assert "ts" in payload


PYFLOWMETER_KEYS = """
src_ip dst_ip src_port dst_port src_mac dst_mac protocol timestamp
flow_duration flow_byts_s flow_pkts_s fwd_pkts_s bwd_pkts_s tot_fwd_pkts
tot_bwd_pkts totlen_fwd_pkts totlen_bwd_pkts fwd_pkt_len_max fwd_pkt_len_min
fwd_pkt_len_mean fwd_pkt_len_std bwd_pkt_len_max bwd_pkt_len_min
bwd_pkt_len_mean bwd_pkt_len_std pkt_len_max pkt_len_min pkt_len_mean
pkt_len_std pkt_len_var fwd_header_len bwd_header_len fwd_seg_size_min
fwd_act_data_pkts flow_iat_mean flow_iat_max flow_iat_min flow_iat_std
fwd_iat_tot fwd_iat_max fwd_iat_min fwd_iat_mean fwd_iat_std bwd_iat_tot
bwd_iat_max bwd_iat_min bwd_iat_mean bwd_iat_std fwd_psh_flags bwd_psh_flags
fwd_urg_flags bwd_urg_flags fin_flag_cnt syn_flag_cnt rst_flag_cnt psh_flag_cnt
ack_flag_cnt urg_flag_cnt ece_flag_cnt down_up_ratio pkt_size_avg
init_fwd_win_byts init_bwd_win_byts active_max active_min active_mean
active_std idle_max idle_min idle_mean idle_std fwd_byts_b_avg fwd_pkts_b_avg
bwd_byts_b_avg bwd_pkts_b_avg fwd_blk_rate_avg bwd_blk_rate_avg fwd_seg_size_avg
bwd_seg_size_avg cwe_flag_count subflow_fwd_pkts subflow_bwd_pkts
subflow_fwd_byts subflow_bwd_byts
""".split()


def test_feature_mapper_produces_every_expected_feature():
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    manifest_path = os.path.join(
        project_root, "models", "model_manifest_rf_day_based_seed42.json"
    )
    with open(manifest_path, encoding="utf-8") as handle:
        expected = json.load(handle)["features"]

    raw = {key: 1.0 for key in PYFLOWMETER_KEYS}
    mapped = normalize_flow_features(raw, expected)

    missing = [feature for feature in expected if feature not in mapped]
    assert missing == []
    assert len(mapped) == len(expected) == 80
