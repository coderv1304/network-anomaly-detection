# Onboarding, Support, and Commercial Status (Phase S6)

**Status:** documentation only. **This project is not commercial, has no customers, takes no payment, and meters no usage.** Nothing here is an offer, a price, a service commitment, or a testimonial.
**Date:** 2026-11-10.
**Related:** [`PRODUCT_BOUNDARY_AND_THREAT_MODEL.md`](PRODUCT_BOUNDARY_AND_THREAT_MODEL.md), [`SCOPE_AND_CLAIMS.md`](SCOPE_AND_CLAIMS.md), [`SECURITY_AND_PRODUCT_GAPS.md`](SECURITY_AND_PRODUCT_GAPS.md), [`OPERATIONS_RUNBOOK.md`](OPERATIONS_RUNBOOK.md), [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md).

## 1. Commercial status: explicit

| Question | Answer |
| --- | --- |
| Is this a commercial product? | **No.** It is a research prototype and demonstration. |
| Are there paying customers? | **No.** |
| Is there a price list? | **No.** None is stated anywhere, and none should be invented. |
| Is there billing or usage metering in the code? | **No.** A repository search for billing, invoicing, subscription, Stripe, and usage-metering code returns no application matches. |
| Is there a service-level agreement? | **No.** |
| Are there customer testimonials or logos? | **No.** None are used, and none may be fabricated. |
| Can a third party deploy it? | Yes, under the repository licence and the upstream dataset terms; see §2. |
| Does deployment create a support relationship? | **No.** |

**Do not add pricing tables, "contact sales", trial banners, customer logos, or "trusted by" claims to the UI or docs unless a real commercial offering, real prices, and real customer consent exist.**

## 2. Licence and upstream terms

- The code is a research artifact. Check the repository licence before redistribution.
- The evaluation data is CIC-IDS-2017 from the Canadian Institute for Cybersecurity, University of New Brunswick. Its terms are **academic, non-commercial research use** with registration. Do not redistribute the CSVs or use them commercially.
- Any second dataset (UNSW-NB15, Bot-IoT, etc.) carries its own licence and must be handled separately.

## 3. What "onboarding" means here

Onboarding is a **developer integration path**, not a customer signup funnel. There is no self-serve signup, no tenant provisioning API for external users, and no account team.

### 3.1 Developer onboarding (supported)

1. **Read the boundary.** [`PRODUCT_BOUNDARY_AND_THREAT_MODEL.md`](PRODUCT_BOUNDARY_AND_THREAT_MODEL.md) and [`SCOPE_AND_CLAIMS.md`](SCOPE_AND_CLAIMS.md) state what the prototype does and does not do. Do not skip them.
2. **Install.**
   ```bash
   python -m venv venv
   venv/Scripts/pip install -r requirements.txt      # Windows
   # source venv/bin/activate && pip install -r requirements.txt   # Linux/macOS
   ```
3. **Configure.** Copy `.env.example` to `.env` and replace the placeholders. Never commit `.env`.
4. **Run the checks.**
   ```bash
   venv/Scripts/python.exe -m pytest tests/ -q
   python scripts/secret_scan.py
   python scripts/deployment_check.py
   ```
5. **Run locally.**
   ```bash
   venv/Scripts/python.exe app.py
   # open http://127.0.0.1:5000
   ```
6. **Choose an input path.** Upload a CSV/PCAP, or opt into live capture with `ENABLE_LOCAL_CAPTURE=true` and `NETSHIELD_CAPTURE_INTERFACE=auto`. Live capture is **experimental**; read [`LIVE_CAPTURE_OPERATIONS.md`](LIVE_CAPTURE_OPERATIONS.md) first.
7. **Understand the output.** Predictions carry model version, artifact hash, feature schema, threshold policy, and calibration version. The serving model is the evaluated, uncalibrated three-class Random Forest. Treat scores as uncalibrated and as predictions, not confirmed attacks.
8. **Do not expose it to the internet.** See §6.

### 3.2 What a real design partner would additionally need (not built)

A design-partner pilot would require, at minimum:

- a completed external penetration test;
- managed secrets and a real IdP integration (TOTP MFA and an OIDC client exist but are not operated);
- encrypted, off-host, tested backups;
- measured SLO compliance and a staffed on-call rota;
- a signed data-handling agreement and deletion path that includes backups;
- the D8 prospective pilot protocol executed with human labels.

None of these is complete. Any "onboarding" that skips them is not supported.

## 4. Support model

| Tier | Who | Scope | Target |
| --- | --- | --- | --- |
| Community / best effort | Maintainer, as time permits | Bug reports, documentation questions, reproduction help | No commitment |
| Security reports | Maintainer | Vulnerability reports | Acknowledge as soon as practical |
| Paid support | **Does not exist** | — | — |
| 24/7 support | **Does not exist** | — | — |

There is no support portal, no ticket SLA, no phone line, and no on-call rotation. Do not promise one.

### 4.1 How to report a bug

Include: what you ran, the exact command, the output, the app version/commit, the artifact hash, the feature-schema version, and whether live capture was involved. Do not include real customer data, secrets, or packet captures containing personal data.

### 4.2 How to report a security issue

Follow the repository's security policy if one exists. Do not open a public issue with an exploit. Include a minimal reproduction and the affected version. See [`SECURITY_AND_COMPLIANCE.md`](SECURITY_AND_COMPLIANCE.md) and [`PENETRATION_TEST_PLAN.md`](PENETRATION_TEST_PLAN.md).

## 5. Escalation path

| Trigger | First contact | Then |
| --- | --- | --- |
| Usage or documentation question | Maintainer (best effort) | — |
| Bug with a workaround | Maintainer | — |
| Data-loss or integrity problem | Maintainer → site owner | [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) §6.2–6.3 |
| Suspected security incident | Maintainer → security owner | [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) §6.6–6.7 |
| Production outage (if someone deployed it) | Whoever operates it | This project provides no production support |

The escalation path is nominal. There is no staffed rota and no guaranteed response time.

## 6. Deployment responsibilities for anyone who runs it

If a third party deploys this prototype, **they** own:

- network exposure and TLS termination;
- identity, MFA, and account lifecycle;
- secret storage and rotation;
- backups, off-host storage, encryption, and restore testing;
- monitoring, on-call, and incident response;
- data-handling agreements, retention, and deletion;
- legal review of the dataset licence;
- an independent security assessment before handling real data.

The project does not transfer those responsibilities by being deployed, and does not accept them.

## 7. Billing and usage metering

**There is none.** Specifically:

- no payment processor integration;
- no plan, quota, or entitlement enforcement tied to payment;
- no usage records, invoices, or metered billing;
- no trial or signup flow;
- no customer accounts beyond the local tenant/user model used for access control.

The tenant model is an **isolation and access-control** mechanism, not a commercial account. Do not describe a tenant as a "customer" or a "subscription".

### 7.1 What would be required before charging anyone

1. A real product boundary and support commitment.
2. Completed external penetration test and resolved critical/high findings.
3. Managed secrets, a real IdP integration, and tenant isolation review.
4. Measured SLO compliance and a staffed on-call rota.
5. Encrypted off-host backups with tested restore and a defined RPO/RTO.
6. Billing/usage-metering design, tax handling, and refund policy.
7. A design-partner pilot with human labels (D8) that supports the value claim.
8. Legal review of dataset licensing for any commercial use.

Until then, the correct statement is: **"Not commercial. No customers. No price. No SLA."**

## 8. Honest summary

- Onboarding path: documented for developers, not for customers.
- Support: best effort, no commitment.
- Escalation: documented, nominal, not staffed.
- Billing: none, by design and by fact.
- Commercial claims: none supported.
