# Inference Service (`inference/`)

This directory houses the inference serving layer for model execution, feature normalization, and streaming anomaly detection.

## Architecture & Goals
1. **Shared Preprocessing Path**:
   - Uses an identical feature preprocessing transformer shared with offline training to guarantee numerical and structural consistency.
2. **Serving Protocols**:
   - REST API (FastAPI) and gRPC endpoints for high-throughput flow ingestion.
   - Health (`/healthz`) and Readiness (`/readyz`) probes.
3. **Optimized Inference**:
   - Model versioning with explicit metadata.
   - ONNX Runtime export (`skl2onnx`) for low-latency batch and single-flow scoring.
4. **Resilience**:
   - Input schema validation via Pydantic.
   - No leakage of raw traceback exceptions to clients.
   - Structured error logging and rate limiting.
