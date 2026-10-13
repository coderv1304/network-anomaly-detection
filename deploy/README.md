# Deployment & Infrastructure (`deploy/`)

This directory contains containerization, orchestration, and monitoring infrastructure.

## Roadmap & Milestones (Phase 3: Engineering Signals)
1. **Containerization (Docker)**:
   - Multi-stage Dockerfile for Go capture binary with minimal base image.
   - Non-root user execution, using only necessary Linux capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`).
   - Slim Python container for inference server.
   - `docker-compose.yml` linking capture service, inference service, and Prometheus/Grafana.
2. **Observability**:
   - Prometheus metrics for packet ingest rate, active flow count, buffer drops, and inference latency histograms.
   - Grafana dashboard JSON committed to version control.
3. **Kubernetes (Optional Platform Track)**:
   - DaemonSet for the capture agent.
   - Deployment & Horizontal Pod Autoscaler for the inference API.
   - Helm chart / Kustomize templates tested on local `kind` cluster.
