# Network Packet Capture & Flow Assembler (`capture/`)

This directory will host the high-performance live network capture and flow assembler service written in **Go**.

## Architecture & Goals (Phase 2 Roadmap)
1. **Engine**: Packet capture using `gopacket` / `pcap` binding.
2. **Flow Tracking Table**: Concurrent 5-tuple table (`SrcIP`, `DstIP`, `SrcPort`, `DstPort`, `Protocol`) tracking bidirectional flows.
3. **Timeout & State Engine**:
   - Active timeout (e.g., 120s max duration per flow).
   - Idle timeout (e.g., 5s inactivity).
   - TCP flag tracking (`FIN` and `RST` teardown handling).
4. **Bounded Queues & Drop Accounting**:
   - Goroutines communicating via buffered Go channels.
   - Explicit packet drop and queue overflow counters exposed as metrics (no hidden packet drops).
5. **Reduced Feature Extractor (15–20 features)**:
   - Derives a targeted subset of statistical flow features aligned with offline model training.
   - Parity validated against `CICFlowMeter` using golden PCAPs.
