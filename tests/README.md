# Test Suite (`tests/`)

Automated tests validating preprocessing, feature extraction parity, API endpoints, and flow assembly.

## Running Tests
Run pytest from the repository root:
```bash
pytest tests/ -v
```

## Structure
- `test_preprocessing.py`: Validates cleaning, NaN/Inf handling, and column stripping.
- `test_feature_mapper.py`: Verifies normalization and mapping between live packet features and trained model feature names.
- `test_api.py`: Validates Flask/FastAPI inference endpoints and payload validation.
- `test_assembler.py` (Phase 2): Golden PCAP tests for flow state transitions and timeouts.
