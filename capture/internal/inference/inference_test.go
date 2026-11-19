package inference

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"capture/internal/flow"
)

func TestLinearManifestScorerScoresStandardizedFeatures(t *testing.T) {
	manifestPath := writeManifest(t, t.TempDir(), manifestFixture(0.5, 0.05))
	bundle, err := LoadBundle("", manifestPath)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if bundle.Backend != "linear-manifest" {
		t.Fatalf("expected the pure-Go fallback backend, got %q", bundle.Backend)
	}
	if bundle.SchemaSHA256 != flow.SchemaSHA256() {
		t.Fatalf("bundle schema digest %q does not match %q", bundle.SchemaSHA256, flow.SchemaSHA256())
	}
	if bundle.ManifestSHA256 == "" || bundle.Scorer.ManifestSHA256() != bundle.ManifestSHA256 {
		t.Fatal("scorer must expose the manifest digest it was loaded for")
	}

	result, err := bundle.Scorer.Score(testVector())
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if math.Abs(result.Probability-1) > 1e-6 {
		t.Fatalf("expected a saturated probability, got %v", result.Probability)
	}
	if !result.IsAlert {
		t.Fatal("probability above the threshold must alert")
	}
	if math.Abs(result.RiskPoints-result.Probability*100) > 1e-9 {
		t.Fatalf("risk points must mirror the probability scale: %v vs %v", result.RiskPoints, result.Probability)
	}

	negative := manifestFixture(0.5, -0.05)
	negativePath := writeManifest(t, t.TempDir(), negative)
	quiet, err := LoadBundle("", negativePath)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	quietResult, err := quiet.Scorer.Score(testVector())
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if quietResult.IsAlert || quietResult.Probability >= 0.5 {
		t.Fatalf("negative weights must stay below the threshold, got %+v", quietResult)
	}
}

func TestLoadBundleRejectsSchemaMismatch(t *testing.T) {
	manifest := manifestFixture(0.5, 0.05)
	manifest.SchemaSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	path := writeManifest(t, t.TempDir(), manifest)

	if _, err := LoadBundle("", path); err == nil {
		t.Fatal("expected a schema digest mismatch to be rejected")
	}
}

func TestLoadBundleRejectsSchemaVersionMismatch(t *testing.T) {
	manifest := manifestFixture(0.5, 0.05)
	manifest.SchemaVersion = "netshield-flow-v0"
	path := writeManifest(t, t.TempDir(), manifest)

	if _, err := LoadBundle("", path); err == nil {
		t.Fatal("expected a schema version mismatch to be rejected")
	}
}

func TestLoadBundleRejectsFeatureOrderMismatch(t *testing.T) {
	manifest := manifestFixture(0.5, 0.05)
	manifest.FeatureNames[3], manifest.FeatureNames[4] = manifest.FeatureNames[4], manifest.FeatureNames[3]
	path := writeManifest(t, t.TempDir(), manifest)

	if _, err := LoadBundle("", path); err == nil {
		t.Fatal("expected a feature order mismatch to be rejected")
	}
}

func TestLinearManifestScorerRejectsNonFiniteWeight(t *testing.T) {
	// JSON cannot carry Infinity, so this guard is exercised through the
	// constructor rather than through a manifest file.
	manifest := manifestFixture(0.5, 0.05)
	manifest.LinearFallback.Weights[2] = math.Inf(1)

	if _, err := NewLinearManifestScorer(manifest, "manifest-sha"); err == nil {
		t.Fatal("expected a non-finite weight to be rejected")
	}
}

func TestReloaderSwapsOnlyAfterValidatedChange(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, manifestFixture(0.5, 0.01))
	swaps := 0
	reloader, err := NewReloader("", path, func(*BundleState) { swaps++ })
	if err != nil {
		t.Fatalf("NewReloader: %v", err)
	}
	defer reloader.Close()
	if reloader.Current().Manifest.Threshold != 0.5 {
		t.Fatalf("unexpected initial threshold: %v", reloader.Current().Manifest.Threshold)
	}

	writeManifest(t, dir, manifestFixture(0.2, 0.01))
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

	// A broken manifest must leave the previous generation serving.
	broken := manifestFixture(0.2, 0.01)
	broken.SchemaSHA256 = "not-the-sensor-schema"
	writeManifest(t, dir, broken)
	if err := reloader.Reload(); err == nil {
		t.Fatal("expected a broken manifest to be rejected")
	}
	if reloader.Current().Manifest.Threshold != 0.2 || swaps != 1 {
		t.Fatal("a rejected reload must not disturb the active bundle")
	}
}

func TestPipelineShedsLowRiskEstablishedFlowsAboveWatermark(t *testing.T) {
	pipeline := NewPipeline(100, nil)
	defer pipeline.Close()

	for i := 0; i < 85; i++ {
		if !pipeline.Submit(flow.Snapshot{SynCnt: 1}) {
			t.Fatalf("flow %d was rejected below the watermark", i)
		}
	}
	established := flow.Snapshot{FwdBytes: 2_000_000}
	if pipeline.Submit(established) {
		t.Fatal("low-risk established flow must be shed at the 85% watermark")
	}
	if pipeline.Shed() != 1 || pipeline.Dropped() != 1 {
		t.Fatalf("expected one shed flow, got shed=%d dropped=%d", pipeline.Shed(), pipeline.Dropped())
	}
	if pipeline.Submit(flow.Snapshot{SynCnt: 1}) != true {
		t.Fatal("non-established flow should still be admitted while capacity remains")
	}
	// A teardown-free flow is only shed once the queue is saturated; below the
	// watermark it is queued normally.
	small := NewPipeline(100, nil)
	defer small.Close()
	if !small.Submit(established) || small.Shed() != 0 {
		t.Fatal("established flow must be admitted below the watermark")
	}

	for pipeline.Len() < pipeline.Cap() {
		pipeline.Submit(flow.Snapshot{SynCnt: 1})
	}
	if pipeline.Submit(flow.Snapshot{SynCnt: 1}) {
		t.Fatal("full pipeline must reject new flows")
	}
}

func TestRepositoryBundleLoadsAndScores(t *testing.T) {
	modelPath := filepath.Join("..", "..", "..", "models", "netshield_flow.onnx")
	manifestPath := filepath.Join("..", "..", "..", "models", "netshield_flow_manifest.json")
	bundle, err := LoadBundle(modelPath, manifestPath)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	defer closeScorer(bundle.Scorer)
	if bundle.ModelSHA256 == "" || bundle.Manifest.Threshold <= 0 {
		t.Fatalf("incomplete bundle: model_sha=%q threshold=%v", bundle.ModelSHA256, bundle.Manifest.Threshold)
	}
	if bundle.SchemaSHA256 != flow.SchemaSHA256() {
		t.Fatalf("repository bundle schema %q does not match sensor %q", bundle.SchemaSHA256, flow.SchemaSHA256())
	}
	if len(bundle.Manifest.FeatureNames) != flow.FeatureCount {
		t.Fatalf("expected %d features, got %d", flow.FeatureCount, len(bundle.Manifest.FeatureNames))
	}
	result, err := bundle.Scorer.Score(testVector())
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if math.IsNaN(result.Probability) || result.Probability < 0 || result.Probability > 1 {
		t.Fatalf("probability is not in [0,1]: %v", result.Probability)
	}
	if result.IsAlert != (result.Probability >= bundle.Manifest.Threshold) {
		t.Fatal("IsAlert must follow the calibrated threshold")
	}
}

func manifestFixture(threshold, weight float64) Manifest {
	count := flow.FeatureCount
	means := make([]float64, count)
	stds := make([]float64, count)
	weights := make([]float64, count)
	for i := 0; i < count; i++ {
		stds[i] = 1
		weights[i] = weight
	}
	return Manifest{
		SchemaVersion:     flow.SchemaVersion,
		SchemaSHA256:      flow.SchemaSHA256(),
		ModelID:           "test-model",
		ModelVersion:      "test-v1",
		FeatureNames:      append([]string(nil), flow.FeatureNames...),
		Classes:           []string{"BENIGN", "ATTACK"},
		Threshold:         threshold,
		CalibrationMethod: "test",
		LinearFallback: &LinearFallback{
			Type:       "logistic",
			Activation: "sigmoid",
			Means:      means,
			Stds:       stds,
			Weights:    weights,
			Bias:       0,
		},
	}
}

func writeManifest(t *testing.T, dir string, manifest Manifest) string {
	t.Helper()
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
