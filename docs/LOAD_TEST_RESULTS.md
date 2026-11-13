# Ingest Load Test Results

*Generated: 2026-11-12T04:11:28.388537+00:00*

## Scope and honest limits

- Single-process Flask/SocketIO deployment with SQLite and the default bounded ingest admission (4 concurrent requests, 250 ms admission timeout).
- Traffic is synthetic flow JSON sent to `POST /api/flows`; it exercises auth, rate limiting, feature mapping, model inference, database insert, audit write, and SocketIO emit.
- This is not a production capacity claim. SQLite, a single process, and one host are deliberate bottlenecks.
- Success means HTTP 201. HTTP 429 means the rate limiter engaged. HTTP 503 means bounded admission rejected the request with `Retry-After`.

## Declared-rate results

| Declared flows/s | Achieved flows/s | Requests | Success | 429 | 503 | Other errors | p50 ms | p95 ms | p99 ms | Max ms |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 20 | 20.0 | 32 | 100.0% | 0 | 0 | 0 | 130.8 | 164.9 | 291.0 | 291.0 |

## Failure point

**No failure inside the declared range.**

## Observations

- No saturation was observed inside the declared range; this does not establish a higher capacity.

## Reproduce

```bash
LIVE_CAPTURE_API_KEY=loadtest-key DATABASE_URL=sqlite:///loadtest.db \
  NETSHIELD_DEMO_STREAM=false PORT=5050 venv/Scripts/python.exe app.py

venv/Scripts/python.exe scripts/load_test.py \
  --base-url http://127.0.0.1:5050 --api-key loadtest-key \
  --rates 20 \
  --duration 15.0 --workers 2 \
  --batch-size 10
```
