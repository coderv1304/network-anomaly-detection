// Package inference scores completed flows with an embedded ONNX model when
// available and a pure-Go linear manifest scorer otherwise.
package inference

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultQueueCapacity is the bounded inference queue size from the sensor
// specification.
const DefaultQueueCapacity = 16384

// ErrONNXUnavailable is returned when the binary was built without the onnx
// build tag or the ONNX Runtime shared library cannot be loaded.
var ErrONNXUnavailable = errors.New("ONNX inference is not available in this build; rebuild with -tags onnx and install ONNX Runtime")

// Score is the result of scoring one flow.
type Score struct {
	AttackProbability float64
	Label             string
	Probabilities     []float64
	Backend           string
}

// FlowScorer scores a 24-element feature vector.
type FlowScorer interface {
	Score(features []float32) (Score, error)
	Backend() string
	Close() error
}

// LinearFallback is the pure-Go scoring path stored in the manifest. It uses
// the same coefficients as the Python logistic baseline so the default build
// can score flows without CGo.
type LinearFallback struct {
	Type       string    `json:"type"`
	Weights    []float64 `json:"weights"`
	Bias       float64   `json:"bias"`
	Activation string    `json:"activation"`
}

// Manifest describes a model artifact and its pure-Go fallback.
type Manifest struct {
	ModelID           string         `json:"model_id"`
	ModelVersion      string         `json:"model_version"`
	CreatedUTC        string         `json:"created_utc"`
	FeatureNames      []string       `json:"feature_names"`
	Classes           []string       `json:"classes"`
	Threshold         float64        `json:"threshold"`
	CalibrationMethod string         `json:"calibration_method"`
	SHA256            string         `json:"sha256"`
	ONNXInput         string         `json:"onnx_input"`
	ONNXOutput        string         `json:"onnx_output"`
	Fallback          *LinearFallback `json:"fallback"`
	ValidationMetrics map[string]any `json:"validation_metrics,omitempty"`
}

// ModelBundle is an immutable, atomically swappable model plus its scorer.
type ModelBundle struct {
	Manifest     Manifest
	Scorer       FlowScorer
	SHA256       string
	Backend      string
	ModelPath    string
	ManifestPath string
}

// FeatureNames returns the manifest feature order.
func (b *ModelBundle) FeatureNames() []string {
	if b == nil {
		return nil
	}
	return b.Manifest.FeatureNames
}

// LoadManifest reads and validates a manifest without loading the model.
func LoadManifest(path string) (Manifest, error) {
	var manifest Manifest
	data, err := os.ReadFile(path)
	if err != nil {
		return manifest, fmt.Errorf("read manifest %q: %w", path, err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, fmt.Errorf("decode manifest %q: %w", path, err)
	}
	if err := validateManifest(manifest); err != nil {
		return manifest, fmt.Errorf("validate manifest %q: %w", path, err)
	}
	return manifest, nil
}

// LoadBundle loads the manifest and the best scorer available in this build.
// expectedFeatures is the sensor's frozen schema; pass nil to skip the check.
func LoadBundle(modelPath, manifestPath string, expectedFeatures []string) (*ModelBundle, error) {
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	if len(expectedFeatures) > 0 && !sameStrings(manifest.FeatureNames, expectedFeatures) {
		return nil, fmt.Errorf(
			"manifest feature schema does not match the sensor schema (%d vs %d features)",
			len(manifest.FeatureNames), len(expectedFeatures),
		)
	}

	modelSHA, modelErr := FileSHA256(modelPath)
	artifactSHA := modelSHA
	if modelErr != nil {
		// A linear-only bundle is valid; the manifest itself is then the
		// pinned artifact.
		artifactSHA, err = FileSHA256(manifestPath)
		if err != nil {
			return nil, err
		}
	}
	if manifest.SHA256 != "" && modelErr == nil && !equalHex(manifest.SHA256, modelSHA) {
		return nil, fmt.Errorf("model SHA-256 mismatch: manifest=%s actual=%s", manifest.SHA256, modelSHA)
	}

	var scorer FlowScorer
	if modelErr == nil {
		scorer, err = newONNXScorer(modelPath, manifest)
		if err == nil {
			return &ModelBundle{
				Manifest:     manifest,
				Scorer:       scorer,
				SHA256:       artifactSHA,
				Backend:      scorer.Backend(),
				ModelPath:    modelPath,
				ManifestPath: manifestPath,
			}, nil
		}
		if manifest.Fallback == nil {
			return nil, fmt.Errorf("load ONNX model %q: %w", modelPath, err)
		}
	}
	if manifest.Fallback == nil {
		return nil, errors.New("manifest has no fallback scorer and no usable ONNX model was found")
	}
	scorer, err = NewLinearManifestScorer(manifest)
	if err != nil {
		return nil, err
	}
	return &ModelBundle{
		Manifest:     manifest,
		Scorer:       scorer,
		SHA256:       artifactSHA,
		Backend:      scorer.Backend(),
		ModelPath:    modelPath,
		ManifestPath: manifestPath,
	}, nil
}

// NewLinearManifestScorer builds the pure-Go scorer from manifest coefficients.
func NewLinearManifestScorer(manifest Manifest) (FlowScorer, error) {
	if manifest.Fallback == nil {
		return nil, errors.New("manifest has no linear fallback")
	}
	fallback := manifest.Fallback
	if len(fallback.Weights) != len(manifest.FeatureNames) {
		return nil, fmt.Errorf("fallback has %d weights for %d features", len(fallback.Weights), len(manifest.FeatureNames))
	}
	for i, weight := range fallback.Weights {
		if math.IsNaN(weight) || math.IsInf(weight, 0) {
			return nil, fmt.Errorf("fallback weight %d is not finite", i)
		}
	}
	activation := fallback.Activation
	if activation == "" {
		activation = "sigmoid"
	}
	if activation != "sigmoid" {
		return nil, fmt.Errorf("unsupported fallback activation %q", activation)
	}
	return &linearScorer{
		weights:   append([]float64(nil), fallback.Weights...),
		bias:      fallback.Bias,
		threshold: manifest.Threshold,
		classes:   classNames(manifest.Classes),
	}, nil
}

// FileSHA256 returns the lowercase hex SHA-256 of a file.
func FileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("hash %q: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// FilePairSHA256 hashes two files into one stable identity.
func FilePairSHA256(first, second string) (string, error) {
	h := sha256.New()
	for _, path := range []string{first, second} {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		h.Write([]byte(filepath.Base(path)))
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func validateManifest(manifest Manifest) error {
	if len(manifest.FeatureNames) == 0 {
		return errors.New("feature_names is required")
	}
	if math.IsNaN(manifest.Threshold) || math.IsInf(manifest.Threshold, 0) || manifest.Threshold < 0 || manifest.Threshold > 1 {
		return fmt.Errorf("threshold %v is outside [0,1]", manifest.Threshold)
	}
	for i, name := range manifest.FeatureNames {
		if name == "" {
			return fmt.Errorf("feature_names[%d] is empty", i)
		}
	}
	return nil
}

func classNames(classes []string) []string {
	if len(classes) == 0 {
		return []string{"BENIGN", "ATTACK"}
	}
	return append([]string(nil), classes...)
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalHex(a, b string) bool {
	return len(a) == len(b) && sha256HexEqual(a, b)
}

func artifactPairHash(modelPath, manifestPath string) string {
	if hash, err := FilePairSHA256(modelPath, manifestPath); err == nil {
		return hash
	}
	if hash, err := FileSHA256(manifestPath); err == nil {
		return hash
	}
	return ""
}

func sha256HexEqual(a, b string) bool {
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// linearScorer is a sigmoid over a manifest-provided weight vector.
type linearScorer struct {
	weights   []float64
	bias      float64
	threshold float64
	classes   []string
}

func (s *linearScorer) Backend() string { return "linear-manifest" }

func (s *linearScorer) Close() error { return nil }

func (s *linearScorer) Score(features []float32) (Score, error) {
	if len(features) != len(s.weights) {
		return Score{}, fmt.Errorf("expected %d features, got %d", len(s.weights), len(features))
	}
	z := s.bias
	for i, value := range features {
		v := float64(value)
		if math.IsNaN(v) || math.IsInf(v, 0) {
			v = 0
		}
		z += s.weights[i] * v
	}
	probability := sigmoid(z)
	label := "BENIGN"
	if probability >= s.threshold {
		label = "ATTACK"
	}
	return Score{
		AttackProbability: probability,
		Label:             label,
		Probabilities:     []float64{1 - probability, probability},
		Backend:           s.Backend(),
	}, nil
}

func sigmoid(value float64) float64 {
	if value >= 0 {
		z := math.Exp(-value)
		return 1 / (1 + z)
	}
	z := math.Exp(value)
	return z / (1 + z)
}

// atomicBundle is the lock-free holder for the active model.
type atomicBundle = atomic.Pointer[ModelBundle]

// Reloader owns the atomic model bundle and its SHA watch loop.
type Reloader struct {
	current      atomicBundle
	modelPath    string
	manifestPath string
	expected     []string
	hashMu       sync.Mutex
	lastHash     string
	onSwap       func(*ModelBundle)
	closeOnce    sync.Once
}

// NewReloader loads the initial bundle and stores it atomically.
func NewReloader(modelPath, manifestPath string, expected []string, onSwap func(*ModelBundle)) (*Reloader, error) {
	bundle, err := LoadBundle(modelPath, manifestPath, expected)
	if err != nil {
		return nil, err
	}
	r := &Reloader{
		modelPath:    modelPath,
		manifestPath: manifestPath,
		expected:     expected,
		onSwap:       onSwap,
	}
	r.current.Store(bundle)
	r.lastHash = artifactPairHash(modelPath, manifestPath)
	return r, nil
}

// Current returns the active bundle. The returned value is immutable.
func (r *Reloader) Current() *ModelBundle { return r.current.Load() }

// Reload re-reads both artifacts and swaps the bundle when they validate.
func (r *Reloader) Reload() error {
	hash, err := FilePairSHA256(r.modelPath, r.manifestPath)
	if err != nil {
		hash = artifactPairHash(r.modelPath, r.manifestPath)
	}
	r.hashMu.Lock()
	unchanged := hash == r.lastHash
	r.hashMu.Unlock()
	if unchanged && r.Current() != nil {
		return nil
	}
	bundle, err := LoadBundle(r.modelPath, r.manifestPath, r.expected)
	if err != nil {
		return err
	}
	previous := r.current.Swap(bundle)
	r.hashMu.Lock()
	r.lastHash = hash
	r.hashMu.Unlock()
	if r.onSwap != nil {
		r.onSwap(bundle)
	}
	if previous != nil && previous.Scorer != nil {
		// Give in-flight scores a grace period before releasing native
		// ONNX sessions.
		time.AfterFunc(5*time.Second, func() { _ = previous.Scorer.Close() })
	}
	return nil
}

// Watch polls the artifacts every interval until ctx is cancelled.
func (r *Reloader) Watch(ctxDone <-chan struct{}, interval time.Duration, report func(error)) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctxDone:
			return
		case <-ticker.C:
			if err := r.Reload(); err != nil && report != nil {
				report(err)
			}
		}
	}
}

// Close releases the active scorer.
func (r *Reloader) Close() error {
	var err error
	r.closeOnce.Do(func() {
		if bundle := r.current.Load(); bundle != nil && bundle.Scorer != nil {
			err = bundle.Scorer.Close()
		}
	})
	return err
}
