package inference

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"capture/internal/flow"
)

func TestLinearManifestScorer(t *testing.T) {
	manifestPath := writeManifest(t, t.TempDir(), 0.5, 0.05)
	bundle, err := LoadBundle("", manifestPath, flow.ModelFeatureNames)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	defer bundle.Scorer.Close()
	if bundle.Backend != "linear-manifest" {
		t.Fatalf("expected linear backend, got %q", bundle.Backend)
	}
	features := make([]float32, flow.ModelFeatureCount)
	for i := range features {
		features[i] = 1
	}
	score, err := bundle.Scorer.Score(features)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if math.IsNaN(score.AttackProbability) || score.AttackProbability <= 0 || score.AttackProbability >= 1 {
		t.Fatalf("unexpected probability: %v", score.AttackProbability)
	}
	if score.Label != "ATTACK" {
		t.Fatalf("expected ATTACK above threshold, got %q (%v)", score.Label, score.AttackProbability)
	}
}

func TestLoadBundleRejectsSchemaMismatch(t *testing.T) {
	manifestPath := writeManifest(t, t.TempDir(), 0.5, 0.01)
	expected := append([]string(nil), flow.ModelFeatureNames...)
	expected[0] = "different_name"
	if _, err := LoadBundle("", manifestPath, expected); err == nil {
		t.Fatal("expected schema mismatch error")
	}
}

func TestLoadBundleRejectsNonFiniteWeight(t *testing.T) {
	weights := make([]float64, flow.ModelFeatureCount)
	weights[1] = math.Inf(1)
	manifest := Manifest{
		ModelID:      "test-model",
		ModelVersion: "test-v1",
		FeatureNames: append([]string(nil), flow.ModelFeatureNames...),
		Classes:      []string{"BENIGN", "ATTACK"},
		Threshold:    0.5,
		Fallback: &LinearFallback{
			Type:       "logistic",
			Weights:    weights,
			Activation: "sigmoid",
		},
	}
	if _, err := NewLinearManifestScorer(manifest); err == nil {
		t.Fatal("expected non-finite weight rejection")
	}
}

func TestReloaderSwapsOnManifestChange(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeManifest(t, dir, 0.5, 0.01)
	swaps := 0
	reloader, err := NewReloader("", manifestPath, flow.ModelFeatureNames, func(*ModelBundle) { swaps++ })
	if err != nil {
		t.Fatalf("NewReloader: %v", err)
	}
	defer reloader.Close()
	if reloader.Current().Manifest.Threshold != 0.5 {
		t.Fatalf("unexpected initial threshold: %v", reloader.Current().Manifest.Threshold)
	}
	writeManifest(t, dir, 0.2, 0.01)
	if err := reloader.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if reloader.Current().Manifest.Threshold != 0.2 {
		t.Fatalf("threshold was not swapped: %v", reloader.Current().Manifest.Threshold)
	}
	if swaps != 1 {
		t.Fatalf("expected one swap callback, got %d", swaps)
	}
	// An unchanged reload must not churn the scorer.
	if err := reloader.Reload(); err != nil {
		t.Fatalf("second Reload: %v", err)
	}
	if swaps != 1 {
		t.Fatalf("unchanged artifacts triggered a swap: %d", swaps)
	}
}

func TestQueueShedsElephantFlowsAboveWatermark(t *testing.T) {
	queue := NewQueue(100)
	for i := 0; i < 85; i++ {
		if !queue.Submit(flow.Snapshot{SynCnt: 1}) {
			t.Fatalf("non-elephant flow %d was rejected below the watermark", i)
		}
	}
	elephant := flow.Snapshot{FwdBytes: 2_000_000}
	if queue.Submit(elephant) {
		t.Fatal("elephant flow should be shed above the 85% watermark")
	}
	if queue.Dropped() != 1 {
		t.Fatalf("expected one drop, got %d", queue.Dropped())
	}
	if !queue.Submit(flow.Snapshot{SynCnt: 1}) {
		t.Fatal("non-elephant flow should still be admitted while capacity remains")
	}
	for queue.Len() < queue.Cap() {
		queue.Submit(flow.Snapshot{SynCnt: 1})
	}
	if queue.Submit(flow.Snapshot{SynCnt: 1}) {
		t.Fatal("full queue must reject new flows")
	}
	queue.Close()
	if queue.Submit(flow.Snapshot{SynCnt: 1}) {
		t.Fatal("closed queue must reject new flows")
	}
}

func TestSigmoidIsStableAtExtremes(t *testing.T) {
	if sigmoid(1000) != 1 {
		t.Fatalf("sigmoid overflow: %v", sigmoid(1000))
	}
	if sigmoid(-1000) != 0 {
		t.Fatalf("sigmoid underflow: %v", sigmoid(-1000))
	}
}

func TestRepositoryBundleLoadsAndScores(t *testing.T) {
	modelPath := filepath.Join("..", "..", "..", "models", "netshield_flow.onnx")
	manifestPath := filepath.Join("..", "..", "..", "models", "netshield_flow_manifest.json")
	bundle, err := LoadBundle(modelPath, manifestPath, flow.ModelFeatureNames)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	defer bundle.Scorer.Close()
	if bundle.SHA256 == "" || bundle.Manifest.Threshold <= 0 {
		t.Fatalf("incomplete bundle: sha=%q threshold=%v", bundle.SHA256, bundle.Manifest.Threshold)
	}
	features := make([]float32, flow.ModelFeatureCount)
	features[0] = 1.5
	features[1] = 3
	features[2] = 2
	features[16] = 333.33
	score, err := bundle.Scorer.Score(features)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if math.IsNaN(score.AttackProbability) || score.AttackProbability < 0 || score.AttackProbability > 1 {
		t.Fatalf("probability is not in [0,1]: %v", score.AttackProbability)
	}
	if len(score.Probabilities) != 2 {
		t.Fatalf("expected two class probabilities, got %v", score.Probabilities)
	}
}

func writeManifest(t *testing.T, dir string, threshold, weight float64) string {
	t.Helper()
	weights := make([]float64, flow.ModelFeatureCount)
	for i := range weights {
		weights[i] = weight
	}
	manifest := Manifest{
		ModelID:           "test-model",
		ModelVersion:      "test-v1",
		FeatureNames:      append([]string(nil), flow.ModelFeatureNames...),
		Classes:           []string{"BENIGN", "ATTACK"},
		Threshold:         threshold,
		CalibrationMethod: "test",
		Fallback: &LinearFallback{
			Type:       "logistic",
			Weights:    weights,
			Bias:       0,
			Activation: "sigmoid",
		},
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}
