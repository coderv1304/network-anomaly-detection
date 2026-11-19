// Command netshield-sensor is the NetShield packet-to-feature and inference
// sensor. It supports deterministic offline extraction and a live scoring mode
// with no CGo requirement in its default build.
package main

import (
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"

	"capture/internal/flow"
	"capture/internal/inference"
	"capture/internal/ingest"
	"capture/internal/metrics"
	"capture/internal/state"
)

const (
	modeExtract = "extract"
	modeSensor  = "sensor"

	windowDuration = 5 * time.Minute
)

type config struct {
	mode        string
	iface       string
	pcapPath    string
	outPath     string
	workers     int
	modelPath   string
	manifest    string
	metricsAddr string
	ingestURL   string
	redisURL    string
	apiKey      string
	sensorID    string
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "netshield-sensor:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.mode, "mode", modeExtract, "operation mode: extract or sensor")
	flag.StringVar(&cfg.iface, "iface", "", "live capture interface")
	flag.StringVar(&cfg.pcapPath, "pcap", "", "offline PCAP file for deterministic replay")
	flag.StringVar(&cfg.outPath, "out", "", "extract output path (default stdout)")
	flag.IntVar(&cfg.workers, "workers", runtime.NumCPU(), "number of flow shards/workers")
	flag.StringVar(&cfg.modelPath, "model", "", "path to netshield_flow.onnx")
	flag.StringVar(&cfg.manifest, "manifest", "", "path to netshield_flow_manifest.json")
	flag.StringVar(&cfg.metricsAddr, "metrics-addr", ":9100", "Prometheus listen address (empty disables)")
	flag.StringVar(&cfg.ingestURL, "ingest-url", "", "Flask ingest base URL, e.g. http://localhost:5000")
	flag.StringVar(&cfg.redisURL, "redis-url", "", "Redis URL for persistent host/window state")
	flag.StringVar(&cfg.apiKey, "api-key", "", "ingest API key (defaults to LIVE_CAPTURE_API_KEY)")
	flag.StringVar(&cfg.sensorID, "sensor-id", "", "sensor identity (defaults to hostname)")
	flag.Parse()

	if cfg.apiKey == "" {
		cfg.apiKey = os.Getenv("NETSHIELD_INGEST_API_KEY")
		if cfg.apiKey == "" {
			cfg.apiKey = os.Getenv("LIVE_CAPTURE_API_KEY")
		}
	}
	if cfg.sensorID == "" {
		if hostname, err := os.Hostname(); err == nil {
			cfg.sensorID = hostname
		} else {
			cfg.sensorID = "netshield-sensor"
		}
	}
	return cfg
}

func run(cfg config) error {
	switch cfg.mode {
	case modeExtract:
		return runExtract(cfg)
	case modeSensor:
		return runSensor(cfg)
	default:
		return fmt.Errorf("unknown --mode %q (expected %s or %s)", cfg.mode, modeExtract, modeSensor)
	}
}

func runExtract(cfg config) error {
	if cfg.pcapPath == "" && cfg.iface == "" {
		return ingest.ErrNoSource
	}
	source, err := ingest.OpenSource(cfg.iface, cfg.pcapPath)
	if err != nil {
		return err
	}
	defer source.Close()

	var mu sync.Mutex
	records := make([]flow.Snapshot, 0, 1024)
	engine := flow.NewEngine(cfg.workers, flow.DefaultIdleTimeout, flow.DefaultActiveTimeout, func(snapshot flow.Snapshot) {
		mu.Lock()
		records = append(records, snapshot)
		mu.Unlock()
	})
	engine.Start()

	packets := uint64(0)
	for {
		packet, err := source.NextPacket()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			engine.Close()
			return fmt.Errorf("read capture: %w", err)
		}
		packets++
		if err := engine.Process(packet); err != nil {
			engine.Close()
			return err
		}
	}
	engine.Close()

	sort.Slice(records, func(i, j int) bool {
		if records[i].StartUS != records[j].StartUS {
			return records[i].StartUS < records[j].StartUS
		}
		return string(records[i].Key.SortKey()) < string(records[j].Key.SortKey())
	})

	writer := io.Writer(os.Stdout)
	var file *os.File
	if cfg.outPath != "" {
		file, err = os.Create(cfg.outPath)
		if err != nil {
			return fmt.Errorf("create output %q: %w", cfg.outPath, err)
		}
		defer file.Close()
		writer = file
	}
	if err := writeExtractCSV(writer, records); err != nil {
		return err
	}
	stats := source.Stats()
	fmt.Fprintf(os.Stderr, "netshield-sensor: mode=extract packets=%d flows=%d received=%d output=%s\n",
		packets, len(records), stats.Received, outputName(cfg.outPath))
	return nil
}

func runSensor(cfg config) error {
	if cfg.pcapPath == "" && cfg.iface == "" {
		return ingest.ErrNoSource
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	modelPath, manifestPath, err := resolveArtifacts(cfg.modelPath, cfg.manifest)
	if err != nil {
		return err
	}

	metricSet := metrics.New()
	reloader, err := inference.NewReloader(modelPath, manifestPath, func(bundle *inference.BundleState) {
		metricSet.SetModel(bundle.ModelSHA256, bundle.Backend, bundle.Manifest.ModelVersion)
		logger.Info("model bundle reloaded",
			"model_sha256", bundle.ModelSHA256,
			"manifest_sha256", bundle.ManifestSHA256,
			"schema", bundle.SchemaSHA256,
			"backend", bundle.Backend,
			"version", bundle.Manifest.ModelVersion)
	})
	if err != nil {
		return fmt.Errorf("load model bundle: %w", err)
	}
	defer reloader.Close()
	metricSet.SetModel(reloader.Current().ModelSHA256, reloader.Current().Backend, reloader.Current().Manifest.ModelVersion)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store := state.NewWindowStore(ctx, cfg.redisURL, windowDuration, logger)
	defer store.Close()

	var sink *state.BatchAlertSink
	if cfg.ingestURL != "" {
		sink, err = state.NewBatchAlertSink(state.BatchAlertSinkOptions{
			URL:           normalizeIngestURL(cfg.ingestURL),
			APIKey:        cfg.apiKey,
			BatchSize:     256,
			FlushInterval: 2 * time.Second,
			Logger:        logger,
		})
		if err != nil {
			return fmt.Errorf("configure alert sink: %w", err)
		}
		sink.Start(ctx)
		defer sink.Close()
	}

	pipeline := inference.NewPipeline(inference.DefaultPipelineCapacity, metricSet)
	engine := flow.NewEngine(cfg.workers, flow.DefaultIdleTimeout, flow.DefaultActiveTimeout, func(snapshot flow.Snapshot) {
		metricSet.FlowsCompleted.Inc()
		// Submit never blocks; it sheds low-risk established flows above the
		// 85% watermark and counts any rejection.
		pipeline.Submit(snapshot)
	})
	engine.Start()

	scoreWorkers := maxInt(2, cfg.workers)
	var scoreWG sync.WaitGroup
	for i := 0; i < scoreWorkers; i++ {
		scoreWG.Add(1)
		go func() {
			defer scoreWG.Done()
			for snapshot := range pipeline.Chan() {
				scoreOne(ctx, snapshot, reloader, store, sink, metricSet, logger, cfg.sensorID, cfg.iface)
			}
		}()
	}

	source, err := ingest.OpenSource(cfg.iface, cfg.pcapPath)
	if err != nil {
		engine.Close()
		pipeline.Close()
		scoreWG.Wait()
		return err
	}
	defer source.Close()

	var metricsServer *http.Server
	if cfg.metricsAddr != "" {
		metricsServer, err = startMetricsServer(cfg.metricsAddr, metricSet)
		if err != nil {
			engine.Close()
			pipeline.Close()
			scoreWG.Wait()
			return err
		}
		defer shutdownMetricsServer(metricsServer)
	}

	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go reloader.Watch(stopWatch, 5*time.Second, func(err error) {
		logger.Warn("model reload failed", "error", err)
	})
	hup := make(chan os.Signal, 1)
	notifyHangup(hup)
	go func() {
		for {
			select {
			case <-stopWatch:
				return
			case <-hup:
				if err := reloader.Reload(); err != nil {
					logger.Warn("SIGHUP model reload failed", "error", err)
				}
			}
		}
	}()

	statsTicker := time.NewTicker(time.Second)
	defer statsTicker.Stop()
	go func() {
		var lastDropped, lastDecodeErrors uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-statsTicker.C:
				stats := source.Stats()
				if stats.DroppedKernel >= lastDropped {
					metricSet.PacketsDroppedKernel.Add(float64(stats.DroppedKernel - lastDropped))
				}
				lastDropped = stats.DroppedKernel
				if stats.DecodeErrors >= lastDecodeErrors {
					metricSet.PacketsDecodeErrors.Add(float64(stats.DecodeErrors - lastDecodeErrors))
				}
				lastDecodeErrors = stats.DecodeErrors
				metricSet.ActiveFlows.Set(float64(engine.ActiveFlows()))
			}
		}
	}()

	packets := uint64(0)
	for {
		packet, readErr := source.NextPacket()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			if ctx.Err() != nil {
				break
			}
			logger.Error("capture read failed", "error", readErr)
			break
		}
		if ctx.Err() != nil {
			break
		}
		packets++
		if err := engine.Process(packet); err != nil {
			break
		}
		metricSet.PacketsReceived.Inc()
	}

	engine.Close()
	metricSet.ActiveFlows.Set(0)
	pipeline.Close()
	scoreWG.Wait()
	if sink != nil {
		sink.Close()
	}
	_ = store.Close()
	_ = reloader.Close()
	logger.Info("sensor stopped",
		"packets", packets,
		"pipeline_dropped", pipeline.Dropped(),
		"pipeline_shed", pipeline.Shed(),
		"alerts_sent", sentCount(sink),
	)
	return nil
}

func scoreOne(
	ctx context.Context,
	snapshot flow.Snapshot,
	reloader *inference.Reloader,
	store state.WindowStore,
	sink *state.BatchAlertSink,
	metricSet *metrics.Metrics,
	logger *slog.Logger,
	sensorID, iface string,
) {
	bundle := reloader.Current()
	if bundle == nil || bundle.Scorer == nil {
		return
	}
	values := snapshot.FeatureValues()
	started := time.Now()
	result, err := bundle.Scorer.Score(values[:])
	metricSet.InferenceDuration.Observe(time.Since(started).Seconds())
	if err != nil {
		logger.Warn("flow scoring failed", "flow_id", snapshot.FlowID(), "error", err)
		return
	}
	if !result.IsAlert {
		return
	}

	sourceIP := snapshot.ForwardKey.SrcString()
	risk := result.RiskPoints
	window, err := store.Record(ctx, state.Event{
		SourceIP:    sourceIP,
		TimestampUS: snapshot.EndUS,
		Risk:        risk,
		FlowID:      snapshot.FlowID(),
	})
	if err != nil {
		logger.Warn("window accumulation failed", "source_ip", sourceIP, "error", err)
	}
	// One consolidated incident per host per crossing of the threshold, so a
	// burst of flagged flows from one host does not become a burst of alerts.
	incident := window.RiskSum >= state.IncidentThreshold && window.RiskSum-risk < state.IncidentThreshold
	if incident {
		logger.Info("host window incident threshold reached",
			"source_ip", sourceIP,
			"risk_points", window.RiskSum,
			"events", window.Count,
			"backend", window.Backend)
	}

	if sink == nil {
		return
	}
	payload := snapshot.CICMap()
	payload["sensor_id"] = sensorID
	payload["interface"] = iface
	payload["kind"] = "flow"
	payload["attack_probability"] = result.Probability
	payload["risk_points"] = risk
	if sink.Enqueue(state.Alert{
		FlowID:      snapshot.FlowID(),
		SourceIP:    sourceIP,
		Risk:        risk,
		TimestampUS: snapshot.EndUS,
		Payload:     payload,
	}) {
		metricSet.AlertsEmitted.Inc()
	}

	if !incident {
		return
	}
	incidentPayload := map[string]any{
		"flow_id":      snapshot.FlowID() + "-incident",
		"kind":         "incident",
		"src_ip":       sourceIP,
		"risk_points":  window.RiskSum,
		"window_count": window.Count,
		"window_start": float64(window.WindowStartUS) / 1e6,
		"timestamp":    float64(window.WindowEndUS) / 1e6,
		"sensor_id":    sensorID,
		"interface":    iface,
	}
	if sink.Enqueue(state.Alert{
		FlowID:      snapshot.FlowID() + "-incident",
		SourceIP:    sourceIP,
		Risk:        window.RiskSum,
		TimestampUS: window.WindowEndUS,
		Payload:     incidentPayload,
	}) {
		metricSet.AlertsEmitted.Inc()
	}
}

func resolveArtifacts(modelPath, manifestPath string) (string, string, error) {
	if modelPath != "" || manifestPath != "" {
		if modelPath == "" || manifestPath == "" {
			return "", "", errors.New("--model and --manifest must be supplied together")
		}
		return modelPath, manifestPath, nil
	}
	candidates := []string{
		".",
		"..",
		filepathJoin("..", ".."),
	}
	for _, dir := range candidates {
		model := filepathJoin(dir, "models", "netshield_flow.onnx")
		manifest := filepathJoin(dir, "models", "netshield_flow_manifest.json")
		if fileExists(model) && fileExists(manifest) {
			return model, manifest, nil
		}
	}
	return "", "", errors.New("model artifacts not found; pass --model and --manifest")
}

func normalizeIngestURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/api/ingest"
	}
	return parsed.String()
}

func startMetricsServer(addr string, metricSet *metrics.Metrics) (*http.Server, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", metricSet.Handler())
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "netshield-sensor: metrics server:", serveErr)
		}
	}()
	return server, nil
}

func shutdownMetricsServer(server *http.Server) {
	if server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func sentCount(sink *state.BatchAlertSink) uint64 {
	if sink == nil {
		return 0
	}
	return sink.Sent()
}

func outputName(path string) string {
	if path == "" {
		return "stdout"
	}
	return path
}

// writeExtractCSV writes the canonical SchemaVersion column layout. Records are
// already ordered by (start time, canonical five-tuple), so repeated runs and
// different worker counts produce byte-identical files.
func writeExtractCSV(writer io.Writer, records []flow.Snapshot) error {
	csvWriter := csv.NewWriter(writer)
	if err := csvWriter.Write(flow.CSVHeader()); err != nil {
		return fmt.Errorf("write extract header: %w", err)
	}
	for i := range records {
		if err := csvWriter.Write(records[i].CSVRow()); err != nil {
			return fmt.Errorf("write extract record: %w", err)
		}
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return fmt.Errorf("flush extract output: %w", err)
	}
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func filepathJoin(parts ...string) string {
	result := ""
	for i, part := range parts {
		if i == 0 {
			result = part
			continue
		}
		result = result + string(os.PathSeparator) + part
	}
	return result
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
