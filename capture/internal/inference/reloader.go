package inference

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"capture/internal/flow"
)

// LoadManifest reads and validates a manifest, returning its file digest.
func LoadManifest(path string) (Manifest, string, error) {
	var manifest Manifest
	data, err := os.ReadFile(path)
	if err != nil {
		return manifest, "", fmt.Errorf("read manifest %q: %w", path, err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, "", fmt.Errorf("decode manifest %q: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return manifest, hex.EncodeToString(sum[:]), nil
}

// LoadBundle loads and validates one model generation. It refuses a manifest
// whose schema digest or feature order does not match the sensor's canonical
// flow schema, and it refuses an ONNX artifact whose SHA-256 differs from the
// pinned value. When the onnx build tag is absent it scores with the manifest's
// standardized linear fallback.
func LoadBundle(modelPath, manifestPath string) (*BundleState, error) {
	manifest, manifestSHA, err := LoadManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	if err := verifySchema(manifest); err != nil {
		return nil, fmt.Errorf("validate manifest %q: %w", manifestPath, err)
	}

	modelSHA := ""
	if modelPath != "" {
		hash, hashErr := FileSHA256(modelPath)
		if hashErr == nil {
			modelSHA = hash
			if manifest.ONNXSHA256 != "" && !equalHex(manifest.ONNXSHA256, modelSHA) {
				return nil, fmt.Errorf("ONNX SHA-256 mismatch: manifest=%s actual=%s", manifest.ONNXSHA256, modelSHA)
			}
			scorer, onnxErr := newONNXScorer(modelPath, manifest, manifestSHA)
			if onnxErr == nil {
				if err := validateScorer(scorer, manifest); err != nil {
					closeScorer(scorer)
					return nil, err
				}
				return &BundleState{
					Manifest:       manifest,
					Scorer:         scorer,
					ManifestSHA256: manifestSHA,
					ModelSHA256:    modelSHA,
					SchemaSHA256:   manifest.SchemaSHA256,
					Backend:        "onnxruntime",
				}, nil
			}
			if manifest.LinearFallback == nil {
				return nil, fmt.Errorf("load ONNX model %q: %w", modelPath, onnxErr)
			}
		}
	}

	if manifest.LinearFallback == nil {
		return nil, errors.New("manifest has no linear_fallback and no usable ONNX model was found")
	}
	scorer, err := NewLinearManifestScorer(manifest, manifestSHA)
	if err != nil {
		return nil, err
	}
	if err := validateScorer(scorer, manifest); err != nil {
		closeScorer(scorer)
		return nil, err
	}
	return &BundleState{
		Manifest:       manifest,
		Scorer:         scorer,
		ManifestSHA256: manifestSHA,
		ModelSHA256:    modelSHA,
		SchemaSHA256:   manifest.SchemaSHA256,
		Backend:        "linear-manifest",
	}, nil
}

// verifySchema refuses a model trained on a different feature contract.
func verifySchema(manifest Manifest) error {
	if manifest.SchemaVersion != flow.SchemaVersion {
		return fmt.Errorf("schema_version %q does not match sensor schema %q", manifest.SchemaVersion, flow.SchemaVersion)
	}
	if manifest.SchemaSHA256 != flow.SchemaSHA256() {
		return fmt.Errorf("schema_sha256 %q does not match sensor schema digest %q", manifest.SchemaSHA256, flow.SchemaSHA256())
	}
	if !sameStrings(manifest.FeatureNames, flow.FeatureNames) {
		return fmt.Errorf("manifest feature order does not match %s", flow.SchemaVersion)
	}
	if !finite(manifest.Threshold) || manifest.Threshold < 0 || manifest.Threshold > 1 {
		return fmt.Errorf("threshold %v is outside [0,1]", manifest.Threshold)
	}
	for i, name := range manifest.FeatureNames {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("feature_names[%d] is empty", i)
		}
	}
	return nil
}

// validateScorer proves a freshly loaded scorer runs and returns a usable
// verdict before it is published to the atomic pointer.
func validateScorer(scorer FlowScorer, manifest Manifest) error {
	if scorer == nil {
		return errors.New("scorer is nil")
	}
	if scorer.SchemaSHA256() != flow.SchemaSHA256() {
		return fmt.Errorf("scorer schema digest %q does not match sensor schema %q", scorer.SchemaSHA256(), flow.SchemaSHA256())
	}
	if scorer.ManifestSHA256() == "" {
		return errors.New("scorer did not record a manifest digest")
	}
	result, err := scorer.Score(testVector())
	if err != nil {
		return fmt.Errorf("scorer test vector failed: %w", err)
	}
	if !finite(result.Probability) || result.Probability < 0 || result.Probability > 1 {
		return fmt.Errorf("scorer test vector returned probability %v", result.Probability)
	}
	if !finite(result.RiskPoints) || result.RiskPoints < 0 || result.RiskPoints > 100 {
		return fmt.Errorf("scorer test vector returned risk points %v", result.RiskPoints)
	}
	if result.IsAlert != (result.Probability >= manifest.Threshold) {
		return errors.New("scorer test vector ignored the manifest threshold")
	}
	return nil
}

// testVector is a deterministic, realistic feature row used to smoke-test a
// freshly loaded scorer before it accepts live traffic.
func testVector() []float64 {
	values := make([]float64, flow.FeatureCount)
	values[0] = 6       // protocol: TCP
	values[1] = 1.5     // duration_sec
	values[2] = 3       // fwd_pkts
	values[3] = 2       // bwd_pkts
	values[4] = 300     // fwd_bytes
	values[5] = 200     // bwd_bytes
	values[22] = 333.33 // bytes_per_sec
	return values
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

// artifactPairHash identifies the active model generation. It tolerates a
// missing ONNX artifact so a linear-only bundle still reloads.
func artifactPairHash(modelPath, manifestPath string) string {
	if hash, err := FilePairSHA256(modelPath, manifestPath); err == nil {
		return hash
	}
	if hash, err := FileSHA256(manifestPath); err == nil {
		return hash
	}
	return ""
}

func closeScorer(scorer FlowScorer) {
	if closer, ok := scorer.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
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
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
