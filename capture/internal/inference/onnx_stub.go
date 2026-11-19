//go:build !onnx

package inference

// newONNXScorer is compiled out of the default build so no ONNX Runtime shared
// library or C compiler is required. LoadBundle falls back to the manifest's
// linear_fallback coefficients when they are present.
func newONNXScorer(string, Manifest, string) (FlowScorer, error) {
	return nil, ErrONNXUnavailable
}
