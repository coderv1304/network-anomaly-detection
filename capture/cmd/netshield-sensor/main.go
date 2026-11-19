// Command netshield-sensor is the NetShield packet-to-feature and inference
// sensor. It supports deterministic offline extraction and a live scoring mode
// with no CGo requirement in its default build.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
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
	incidentScore  = 70.0
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

type extractRecord struct {
	FlowID     string             `json:"flow_id"`
	SrcIP      string             `json:"src_ip"`
	SrcPort    int                `json:"src_port"`
	DstIP      string             `json:"dst_ip"`
	DstPort    int                `json:"dst_port"`
	Protocol   int                `json:"protocol"`
	StartUS    int64              `json:"start_us"`
	EndUS      int64              `json:"end_us"`
	Features   map[string]float64 `json:"features"`
	CICFeatures map[string]any    `json:"cic_features"`
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
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for i := range records {
		record := records[i]
		line := extractRecord{
			FlowID:      record.FlowID(),
			SrcIP:       record.ForwardKey.SrcString(),
			SrcPort:     int(record.ForwardKey.SrcPort),
			DstIP:       record.ForwardKey.DstString(),
			DstPort:     int(record.ForwardKey.DstPort),
			Protocol:    int(record.ForwardKey.Proto),
			StartUS:     record.StartUS,
			EndUS:       record.EndUS,
			Features:    record.FeatureMap(),
			CICFeatures: record.CICMap(),
		}
		if err := encoder.Encode(line); err != nil {
			return fmt.Errorf("write extract record: %w", err)
		}
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
	reloader, err := inference.NewReloader(modelPath, manifestPath, flow.FeatureNames, func(bundle *inference.ModelBundle) {
		metricSet.SetModel(bundle.SHA256, bundle.Backend, bundle.Manifest.ModelVersion)
		logger.Info("model bundle reloaded", "sha256", bundle.SHA256, "backend", bundle.Backend, "version", bundle.Manifest.ModelVersion)
	})
	if err != nil {
		return fmt.Errorf("load model bundle: %w", err)
	}
	defer reloader.Close()
	metricSet.SetModel(reloader.Current().SHA256, reloader.Current().Backend, reloader.Current().Manifest.ModelVersion)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	accumulator := state.NewAccumulator(ctx, cfg.redisURL, windowDuration, logger)
	defer accumulator.Close()

	var forwarder *state.Forwarder
	if cfg.ingestURL != "" {
		forwarder, err = state.NewForwarder(state.ForwarderOptions{
			URL:     normalizeIngestURL(cfg.ingestURL),
			APIKey:  cfg.apiKey,
			BatchSize: 256,
			FlushInterval: 2 * time.Second,
			Logger:  logger,
		})
		if err != nil {
			return fmt.Errorf("configure alert forwarder: %w", err)
		}
		forwarder.Start(ctx)
		defer forwarder.Close()
	}

	queue := inference.NewQueue(inference.DefaultQueueCapacity)
	engine := flow.NewEngine(cfg.workers, flow.DefaultIdleTimeout, flow.DefaultActiveTimeout, func(snapshot flow.Snapshot) {
		metricSet.FlowsCompleted.Inc()
		if !queue.Submit(snapshot) {
			metricSet.FlowsDroppedBackpressure.Inc()
		}
	})
	engine.Start()

	scoreWorkers := maxInt(2, cfg.workers)
	var scoreWG sync.WaitGroup
	for i := 0; i < scoreWorkers; i++ {
		scoreWG.Add(1)
		go func() {
			defer scoreWG.Done()
			for snapshot := range queue.Chan() {
				scoreOne(ctx, snapshot, reloader, accumulator, forwarder, metricSet, logger, cfg.sensorID, cfg.iface)
			}
		}()
	}

	source, err := ingest.OpenSource(cfg.iface, cfg.pcapPath)
	if err != nil {
		engine.Close()
		queue.Close()
		scoreWG.Wait()
		return err
	}
	defer source.Close()

	var metricsServer *http.Server
	if cfg.metricsAddr != "" {
		metricsServer, err = startMetricsServer(cfg.metricsAddr, metricSet)
		if err != nil {
			engine.Close()
			queue.Close()
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
		var lastDropped uint64
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
	queue.Close()
	scoreWG.Wait()
	if forwarder != nil {
		forwarder.Close()
	}
	_ = accumulator.Close()
	_ = reloader.Close()
	logger.Info("sensor stopped",
		"packets", packets,
		"queue_dropped", queue.Dropped(),
		"alerts_sent", sentCount(forwarder),
	)
	return nil
}

func scoreOne(
	ctx context.Context,
	snapshot flow.Snapshot,
	reloader *inference.Reloader,
	accumulator state.WindowAccumulator,
	forwarder *state.Forwarder,
	metricSet *metrics.Metrics,
	logger *slog.Logger,
	sensorID, iface string,
) {
	bundle := reloader.Current()
	if bundle == nil || bundle.Scorer == nil {
		return
	}
	started := time.Now()
	score, err := bundle.Scorer.Score(snapshot.FeatureVector())
	metricSet.InferenceDuration.Observe(time.Since(started).Seconds())
	if err != nil {
		logger.Warn("flow scoring failed", "flow_id", snapshot.FlowID(), "error", err)
		return
	}
	if score.AttackProbability < bundle.Manifest.Threshold {
		return
	}

	sourceIP := snapshot.ForwardKey.SrcString()
	risk := math.Min(100, score.AttackProbability*50)
	window, err := accumulator.Record(ctx, state.Event{
		SourceIP:    sourceIP,
		TimestampUS: snapshot.EndUS,
		Risk:        risk,
		Label:       score.Label,
		FlowID:      snapshot.FlowID(),
	})
	if err != nil {
		logger.Warn("window accumulation failed", "source_ip", sourceIP, "error", err)
	}
	if window.Score >= incidentScore {
		logger.Info("host window incident threshold reached",
			"source_ip", sourceIP, "score", window.Score, "events", window.Count, "backend", window.Backend)
	}

	if forwarder == nil {
		return
	}
	payload := snapshot.CICMap()
	payload["sensor_id"] = sensorID
	payload["interface"] = iface
	if forwarder.Enqueue(state.Alert{
		FlowID:      snapshot.FlowID(),
		SourceIP:    sourceIP,
		Risk:        risk,
		TimestampUS: snapshot.EndUS,
		Payload:     payload,
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

func sentCount(forwarder *state.Forwarder) uint64 {
	if forwarder == nil {
		return 0
	}
	return forwarder.Sent()
}

func outputName(path string) string {
	if path == "" {
		return "stdout"
	}
	return path
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
