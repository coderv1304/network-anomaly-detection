# D7 — External Validation and Real-Capture Report

**Status:** **incomplete.** The second-dataset gate is **blocked**, and the only real capture is an **unlabelled-traffic ingest test with operator-declared benign traffic**. Neither result is external detection evidence.
**Date:** 2026-11-10.
**Related:** [`EVALUATION_PROTOCOL_V2.md`](EVALUATION_PROTOCOL_V2.md), [`MODEL_CARD.md`](MODEL_CARD.md), [`LIVE_CAPTURE_OPERATIONS.md`](LIVE_CAPTURE_OPERATIONS.md), [`D6_EXPERIMENT_PROTOCOL.md`](D6_EXPERIMENT_PROTOCOL.md).

## 1. Honest summary

| Question | Answer |
| --- | --- |
| Is there a second independent public dataset? | **No.** No compatible dataset is present in the workspace or on the host. |
| Was the frozen serving artifact scored on a second public dataset? | **No.** The harness exists, but there is no dataset to feed it. |
| Was there a real traffic capture? | **Yes**, 11 flows on the `auto` (Wi-Fi) adapter. |
| Were those flows human-labelled with attack/benign ground truth? | **No.** They are operator-declared benign public-web/DNS traffic. |
| Did the detector flag any of the 11 flows? | **No.** All 11 were `BENIGN` at attack score 0.0. |
| Does that prove good false-positive behaviour? | **No.** 0/11 has a 95% Wilson upper bound near 25.9%; it is not a measured FPR. |
| Does this raise the detection score? | **No.** Detection stays 4/10. |

The external-validation requirement in [`EVALUATION_PROTOCOL_V2.md`](EVALUATION_PROTOCOL_V2.md) is therefore **not met**. No claim of generalization, external validity, or "live validated" is supported.

## 2. Second-dataset gate — blocked

### 2.1 What was searched

The workspace was searched for any dataset other than the CIC-IDS-2017 weekday CSVs:

- `find . -iname '*unsw*'`, `*cic*2018*`, `*nsl*kdd*`, `*kdd*cup*`, `*bot*iot*`, `*ton*iot*` — no matches.
- Every CSV under the project is either a CIC-IDS-2017 weekday file, the derived `data/samples/network_test_dataset.csv`, or `data/samples/test_dataset.csv`. Both sample files are CIC-IDS-derived subsets, not an independent public dataset.
- No parquet, pcap, or pcapng files are tracked in the repository.

### 2.2 Datasets that would be acceptable, and why they are absent

| Candidate | Why it could be external | Status |
| --- | --- | --- |
| UNSW-NB15 | Different capture, different feature extractor (Argus/Bro), different label taxonomy | Not downloaded; license/registration and size not handled |
| CIC-IDS-2018 | Same lab, different year and infrastructure | Not downloaded; it is not a clean independent replication |
| Bot-IoT / ToN-IoT | Purpose-built IoT botnet captures, relevant to the Bot question | Not downloaded; different feature schema |
| NSL-KDD | Classic benchmark, but 1998-era and heavily preprocessed | Not downloaded; weak external validity |

Downloading any of these requires network access, licence agreement, multi-GB storage, and a feature-mapping decision that could not be made automatically without inspecting the data. That work was **not** performed, so the gate is recorded as blocked rather than papered over.

### 2.3 The harness that is ready

`scripts/external_validation.py` scores the frozen serving bundle on any external CSV. It:

- reports expected, matched, missing, and extra columns **before** scoring;
- refuses to score by default when required features are missing, so a schema mismatch cannot be silently imputed;
- uses the **frozen threshold recorded in the registry-active serving artifact** and never retunes it;
- resolves the registry-active serving artifact by default (`--model-bundle` still overrides it);
- maps `BENIGN`/`Normal`/`background`/`0` to benign and everything else to attack, and reports per-family recall with Wilson intervals;
- states explicitly that the artifact is uncalibrated, so Brier/ECE are diagnostics, not calibrated probabilities;
- writes a `comparability` block that says whether the result is comparable to CIC-IDS-2017.

### 2.4 Harness self-test (not external validation)

To prove the harness runs end-to-end, it was pointed at `data/samples/test_dataset.csv` with `--max-rows 20000` (5,204 rows parsed, 4 attacks):

| Field | Value |
| --- | --- |
| Feature columns matched | 80/80 |
| Extra columns | `Flow ID`, `Source IP`, `Destination IP`, `Timestamp`, `Label` |
| Rows | 5,204 |
| Benign / attack rows | 5,200 / 4 |
| Frozen threshold | 0.002515048908954043 |
| FPR | 0.00346 |
| Recall | 0.5 (2/4 PortScan) |
| Precision | 0.1 |
| PR-AUC | 0.5004 |
| ROC-AUC | 0.7479 |

**This is a harness self-test on a CIC-IDS-2017-derived sample, not external validation.** Its purpose is to show the code path works. It must not be cited as generalization evidence, and its 4 attacks are far too few to estimate recall. Output: [`external_validation_harness_selftest.json`](external_validation_harness_selftest.json).
## 3. Real capture — ingest test, operator-declared benign

### 3.1 Procedure

- Tool: `scripts/live_capture_smoke.py --interface auto --seconds 35`.
- `auto` resolved to the **Wi-Fi** adapter (default route).
- Benign traffic was generated by ordinary HTTPS/DNS requests to public sites from the same host during the window.
- The app was started on a loopback port with the frozen serving artifact; captured flows were POSTed to `/api/flows` and classified by the served path.
- Artifacts: [`d7_real_capture_benign.json`](d7_real_capture_benign.json), [`d7_real_capture_benign.log`](d7_real_capture_benign.log).

### 3.2 Result (recorded 2026-11-10; historical artifact)

This capture was scored while the registry-active artifact was the legacy
Logistic Regression serving bundle. It is retained as an ingest/capture-path
test. It is **not** a validation of the current Random Forest serving artifact,
and its zero predicted attacks says nothing about RF behavior.

| Field | Value |
| --- | --- |
| Resolved interface | `Wi-Fi` |
| Capture state | `listening` |
| Flows before / after | 21,579 / 21,590 |
| Flows ingested | 11 |
| Predicted attack | 0 |
| Predicted benign | 11 |
| Max attack score | 0.0 |
| Model version at run time | `serving-lr-day-based-seed42-v1` (historical) |
| Artifact SHA-256 at run time | `f6d3a5c1e90008bf3ba8789591c46067d4b59f0523328f745aa536a8d0d2925d` |
| Feature schema | `cic-ids-2017-80f-45cd75ce849b` |
| Calibration version | `uncalibrated` |

Observed flows: HTTPS to `148.113.17.90`, `104.20.32.17`, `172.66.173.149`; DNS (UDP/53) to `10.83.104.40`. All were classified `BENIGN` with attack score 0.0.

### 3.3 What this does and does not show

**Shows:** packets can be captured on a real Wi-Fi interface, converted to flows, accepted by the API with provenance, classified, and stored under the frozen artifact. The ingest path and multi-interface selection work.

**Does not show:**

- Detection accuracy. There is no attack traffic and no independent ground truth.
- A trustworthy false-positive rate. 0/11 has a 95% Wilson upper bound of about **25.9%**; an FPR of 25% is fully consistent with this sample.
- Feature parity with CICFlowMeter. The live extractor still disagrees with the upload extractor on several numeric features and treats flag counts as 0/1 indicators.
- Anything about ICMP or IPv6, which the live BPF filter drops.
- That the 11 flows are truly benign beyond the operator's statement.

## 4. Feature mapping and schema

| Item | Finding |
| --- | --- |
| Required features | 80, from `models/feature_names.pkl`, schema `cic-ids-2017-80f-45cd75ce849b` |
| Upload/CSV path | All 80 names present; identifier columns and `Label` are extra; duplicate physical `Fwd Header Length` header handled upstream |
| Live path | All 80 names produced, but several numeric features are approximations and flag counts are 0/1 |
| Column matching | Stripped, case-sensitive exact match; unmatched columns are reported as missing |
| Label source | CIC-IDS-2017 provided labels for offline data; **none** for the real capture |
| Class coverage in training | `BENIGN`, `FTP-Patator`, `SSH-Patator` only |
| Class coverage in test | Adds Bot, DDoS, PortScan, Infiltration, and three Web Attack families |
| Schema mismatch risk | High for any second dataset; a different extractor will miss features and/or carry different semantics |

## 5. Non-comparability statement

Any number produced by the harness on a dataset that lacks all 80 features, or that was produced by a different flow extractor, is **not comparable** to the CIC-IDS-2017 results in [`BENCHMARK_RESULTS.md`](BENCHMARK_RESULTS.md) or [`D6`](UNSEEN_FAMILY_AND_BOTNET.md). The harness says so in its own output. The sample self-test is same-provenance and is likewise not external evidence.

The 11-flow real capture is **not comparable** to anything: it has no attack class and no independent labels.

## 6. What would close D7

1. Obtain one independent public dataset (preferably UNSW-NB15 or Bot-IoT for the Bot question) under a documented licence.
2. Write an explicit feature-mapping table from that dataset's extractor to the 80-feature schema, and mark unsupported features.
3. Run `scripts/external_validation.py` with the frozen artifact and **no threshold retuning**.
4. Repeat the real capture with a consented site, attack traffic generated in a lab, and **independent human labels**.
5. Report per-family recall, PR-AUC, FPR, alert rate, and calibration side by side, with the comparability caveats.

Until all five are done, D7 is blocked and detection remains **4/10**.
