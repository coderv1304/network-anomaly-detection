// Package inference scores completed flows with an embedded ONNX model when it
// is compiled in, and with the manifest's standardized logistic fallback
// otherwise. The active model lives behind an atomic pointer so a reload never
// blocks the scoring path.
package inference

import (
	"errors"
	"fmt"
	"math"
)

// ErrONNXUnavailable is returned when the binary was built without the onnx
// build tag or the ONNX Runtime shared library cannot be loaded.
var ErrONNXUnavailable = errors.New("ONNX inference is not available in this build; rebuild with -tags onnx and install ONNX Runtime")

// ScoreResult is the sensor-facing verdict for one flow. Probability is the
// model output, IsAlert applies the calibrated threshold, and RiskPoints is the
// same probability on the 0-100 scale the host window accumulator uses.
type ScoreResult struct {
	Probability float64
	IsAlert     bool
	RiskPoints  float64
}

// FlowScorer maps one canonical feature vector to a result. Implementations are
// immutable after construction, which is what makes the atomic pointer swap
// safe for concurrent readers.
type FlowScorer interface {
	Score(features []float64) (ScoreResult, error)
	ManifestSHA256() string
	SchemaSHA256() string
}

// Manifest is the on-disk model contract written by training/export_onnx.py.
// SchemaSHA256 pins the canonical feature order, and ONNXSHA256 pins the model
// bytes the manifest describes.
type Manifest struct {
	SchemaVersion     string          `json:"schema_version"`
	SchemaSHA256      string          `json:"schema_sha256"`
	ModelID           string          `json:"model_id"`
	ModelVersion      string          `json:"model_version"`
	CreatedUTC        string          `json:"created_utc"`
	FeatureNames      []string        `json:"feature_names"`
	Classes           []string        `json:"classes"`
	Threshold         float64         `json:"threshold"`
	CalibrationMethod string          `json:"calibration_method"`
	ONNXSHA256        string          `json:"onnx_sha256"`
	ONNXInput         string          `json:"onnx_input"`
	ONNXOutput        string          `json:"onnx_output"`
	TargetOpset       int             `json:"target_opset"`
	LinearFallback    *LinearFallback `json:"linear_fallback"`
	ValidationMetrics map[string]any  `json:"validation_metrics,omitempty"`
}

// LinearFallback is a logistic model over standardized features. It is the
// default-build scorer, so the sensor can score without any C library.
type LinearFallback struct {
	Type       string    `json:"type"`
	Activation string    `json:"activation"`
	Means      []float64 `json:"means"`
	Stds       []float64 `json:"stds"`
	Weights    []float64 `json:"weights"`
	Bias       float64   `json:"bias"`
}

// BundleState is one validated model generation: the manifest, its scorer, and
// the digests that identify them. Nothing in it mutates after construction.
type BundleState struct {
	Manifest       Manifest
	Scorer         FlowScorer
	ManifestSHA256 string
	ModelSHA256    string
	SchemaSHA256   string
	Backend        string
}

// LinearManifestScorer is the zero-CGo scoring path. It evaluates
// z = bias + sum(weights[i] * (x[i]-means[i]) / stds[i]) and applies a sigmoid.
type LinearManifestScorer struct {
	means       []float64
	stds        []float64
	weights     []float64
	bias        float64
	threshold   float64
	manifestSHA string
	schemaSHA   string
}

// NewLinearManifestScorer validates the fallback coefficients and builds the
// pure-Go scorer. manifestSHA is the digest of the manifest file on disk.
func NewLinearManifestScorer(manifest Manifest, manifestSHA string) (FlowScorer, error) {
	fallback := manifest.LinearFallback
	if fallback == nil {
		return nil, errors.New("manifest has no linear_fallback coefficients")
	}
	count := len(manifest.FeatureNames)
	if len(fallback.Weights) != count || len(fallback.Means) != count || len(fallback.Stds) != count {
		return nil, fmt.Errorf(
			"linear_fallback must supply %d means/stds/weights (got %d/%d/%d)",
			count, len(fallback.Means), len(fallback.Stds), len(fallback.Weights),
		)
	}
	for i := 0; i < count; i++ {
		if !finite(fallback.Weights[i]) || !finite(fallback.Means[i]) || !finite(fallback.Stds[i]) {
			return nil, fmt.Errorf("linear_fallback coefficient %d is not finite", i)
		}
	}
	if !finite(fallback.Bias) {
		return nil, errors.New("linear_fallback bias is not finite")
	}
	return &LinearManifestScorer{
		means:       append([]float64(nil), fallback.Means...),
		stds:        append([]float64(nil), fallback.Stds...),
		weights:     append([]float64(nil), fallback.Weights...),
		bias:        fallback.Bias,
		threshold:   manifest.Threshold,
		manifestSHA: manifestSHA,
		schemaSHA:   manifest.SchemaSHA256,
	}, nil
}

// Score evaluates the standardized logistic model.
func (s *LinearManifestScorer) Score(features []float64) (ScoreResult, error) {
	if len(features) != len(s.weights) {
		return ScoreResult{}, fmt.Errorf("expected %d features, got %d", len(s.weights), len(features))
	}
	z := s.bias
	for i, value := range features {
		x := value
		if !finite(x) {
			x = 0
		}
		std := s.stds[i]
		if std == 0 || !finite(std) {
			std = 1
		}
		z += s.weights[i] * (x - s.means[i]) / std
	}
	probability := sigmoid(z)
	return ScoreResult{
		Probability: probability,
		IsAlert:     probability >= s.threshold,
		RiskPoints:  probability * 100,
	}, nil
}

// ManifestSHA256 returns the digest of the manifest this scorer was loaded for.
func (s *LinearManifestScorer) ManifestSHA256() string { return s.manifestSHA }

// SchemaSHA256 returns the canonical schema digest this scorer expects.
func (s *LinearManifestScorer) SchemaSHA256() string { return s.schemaSHA }

// Close releases any resources. The linear scorer holds none.
func (s *LinearManifestScorer) Close() error { return nil }

func sigmoid(value float64) float64 {
	if value >= 0 {
		z := math.Exp(-value)
		return 1 / (1 + z)
	}
	z := math.Exp(value)
	return z / (1 + z)
}

func finite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}
