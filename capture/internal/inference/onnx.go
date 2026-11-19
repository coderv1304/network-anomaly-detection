//go:build onnx

package inference

import (
	"fmt"
	"sync"

	ort "github.com/yalue/onnxruntime_go"
)

// onnxScorer runs the quantized HistGradientBoosting graph in-process through
// the ONNX Runtime C API. It is compiled only with -tags onnx so the default
// cross-platform build needs no shared library.
type onnxScorer struct {
	session    *ort.DynamicAdvancedSession
	inputName  string
	outputName string
	features   int
	classes    int
	threshold  float64
	classNames []string
	mu         sync.Mutex
}

func newONNXScorer(path string, manifest Manifest) (FlowScorer, error) {
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
		session:    session,
		inputName:  inputName,
		outputName: outputName,
		features:   len(manifest.FeatureNames),
		classes:    classes,
		threshold:  manifest.Threshold,
		classNames: classNames(manifest.Classes),
	}, nil
}

func (s *onnxScorer) Backend() string { return "onnxruntime" }

func (s *onnxScorer) Close() error {
	if s.session == nil {
		return nil
	}
	err := s.session.Destroy()
	s.session = nil
	return err
}

func (s *onnxScorer) Score(features []float32) (Score, error) {
	if len(features) != s.features {
		return Score{}, fmt.Errorf("expected %d features, got %d", s.features, len(features))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session == nil {
		return Score{}, fmt.Errorf("ONNX session is closed")
	}

	input, err := ort.NewTensor(ort.NewShape(1, int64(s.features)), features)
	if err != nil {
		return Score{}, fmt.Errorf("create input tensor: %w", err)
	}
	defer func() { _ = input.Destroy() }()

	output, err := ort.NewEmptyTensor[float32](ort.NewShape(1, int64(s.classes)))
	if err != nil {
		return Score{}, fmt.Errorf("create output tensor: %w", err)
	}
	defer func() { _ = output.Destroy() }()

	if err := s.session.Run([]ort.Value{input}, []ort.Value{output}); err != nil {
		return Score{}, fmt.Errorf("run ONNX session: %w", err)
	}
	raw := output.GetData()
	if len(raw) < s.classes {
		return Score{}, fmt.Errorf("ONNX output has %d values, expected %d", len(raw), s.classes)
	}
	probabilities := make([]float64, s.classes)
	for i := 0; i < s.classes; i++ {
		probabilities[i] = float64(raw[i])
	}
	probability := probabilities[len(probabilities)-1]
	label := "BENIGN"
	if probability >= s.threshold {
		label = "ATTACK"
	}
	return Score{
		AttackProbability: probability,
		Label:             label,
		Probabilities:     probabilities,
		Backend:           s.Backend(),
	}, nil
}
