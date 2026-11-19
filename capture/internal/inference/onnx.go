//go:build onnx

package inference

import (
	"fmt"
	"sync"

	ort "github.com/yalue/onnxruntime_go"
)

// onnxScorer runs the exported gradient-boosting graph in-process through the
// ONNX Runtime C API. It is compiled only with -tags onnx so the default build
// needs no shared library.
type onnxScorer struct {
	session     *ort.DynamicAdvancedSession
	inputName   string
	outputName  string
	features    int
	classes     int
	threshold   float64
	manifestSHA string
	schemaSHA   string
	mu          sync.Mutex
}

func newONNXScorer(path string, manifest Manifest, manifestSHA string) (FlowScorer, error) {
	if !ort.IsInitialized() {
		if err := ort.InitializeEnvironment(); err != nil {
			return nil, fmt.Errorf("initialize ONNX Runtime: %w", err)
		}
	}
	inputName := manifest.ONNXInput
	if inputName == "" {
		inputName = "X"
	}
	outputName := manifest.ONNXOutput
	if outputName == "" {
		outputName = "probabilities"
	}
	session, err := ort.NewDynamicAdvancedSession(path, []string{inputName}, []string{outputName}, nil)
	if err != nil {
		return nil, fmt.Errorf("create ONNX session: %w", err)
	}
	classes := len(manifest.Classes)
	if classes == 0 {
		classes = 2
	}
	return &onnxScorer{
		session:     session,
		inputName:   inputName,
		outputName:  outputName,
		features:    len(manifest.FeatureNames),
		classes:     classes,
		threshold:   manifest.Threshold,
		manifestSHA: manifestSHA,
		schemaSHA:   manifest.SchemaSHA256,
	}, nil
}

// ManifestSHA256 returns the digest of the manifest this session was built for.
func (s *onnxScorer) ManifestSHA256() string { return s.manifestSHA }

// SchemaSHA256 returns the canonical schema digest this session expects.
func (s *onnxScorer) SchemaSHA256() string { return s.schemaSHA }

// Close releases the native session.
func (s *onnxScorer) Close() error {
	if s.session == nil {
		return nil
	}
	err := s.session.Destroy()
	s.session = nil
	return err
}

// Score runs one inference. Non-finite inputs are zeroed first, matching the
// sensor's sanitized feature rows.
func (s *onnxScorer) Score(features []float64) (ScoreResult, error) {
	if len(features) != s.features {
		return ScoreResult{}, fmt.Errorf("expected %d features, got %d", s.features, len(features))
	}
	input := make([]float32, len(features))
	for i, value := range features {
		if !finite(value) {
			value = 0
		}
		input[i] = float32(value)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session == nil {
		return ScoreResult{}, fmt.Errorf("ONNX session is closed")
	}

	tensor, err := ort.NewTensor(ort.NewShape(1, int64(s.features)), input)
	if err != nil {
		return ScoreResult{}, fmt.Errorf("create input tensor: %w", err)
	}
	defer func() { _ = tensor.Destroy() }()

	output, err := ort.NewEmptyTensor[float32](ort.NewShape(1, int64(s.classes)))
	if err != nil {
		return ScoreResult{}, fmt.Errorf("create output tensor: %w", err)
	}
	defer func() { _ = output.Destroy() }()

	if err := s.session.Run([]ort.Value{tensor}, []ort.Value{output}); err != nil {
		return ScoreResult{}, fmt.Errorf("run ONNX session: %w", err)
	}
	raw := output.GetData()
	if len(raw) < s.classes {
		return ScoreResult{}, fmt.Errorf("ONNX output has %d values, expected %d", len(raw), s.classes)
	}
	probability := float64(raw[s.classes-1])
	return ScoreResult{
		Probability: probability,
		IsAlert:     probability >= s.threshold,
		RiskPoints:  probability * 100,
	}, nil
}
