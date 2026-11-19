package flow

import "math"

// Welford is an online mean/variance accumulator. Variance uses the sample
// (n-1) denominator, matching numpy.std(..., ddof=1) and the canonical feature
// contract. Fewer than two observations report zero variance, so single-packet
// flows never produce NaN or Inf.
type Welford struct {
	Count int64
	Mean  float64
	M2    float64
	Min   float64
	Max   float64
}

// Add incorporates one observation.
func (w *Welford) Add(value float64) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	w.Count++
	if w.Count == 1 {
		w.Mean = value
		w.M2 = 0
		w.Min = value
		w.Max = value
		return
	}
	if value < w.Min {
		w.Min = value
	}
	if value > w.Max {
		w.Max = value
	}
	delta := value - w.Mean
	w.Mean += delta / float64(w.Count)
	w.M2 += delta * (value - w.Mean)
}

// Variance returns the sample variance. A single observation has zero
// variance, which keeps the serialized feature vector finite.
func (w Welford) Variance() float64 {
	if w.Count < 2 {
		return 0
	}
	variance := math.Max(0, w.M2/float64(w.Count-1))
	if math.IsNaN(variance) || math.IsInf(variance, 0) {
		return 0
	}
	return variance
}

// Std returns the sample standard deviation.
func (w Welford) Std() float64 {
	if w.Count < 2 {
		return 0
	}
	return math.Sqrt(w.Variance())
}

// Summary is the finite, copyable view of a Welford accumulator.
type Summary struct {
	Count int64   `json:"count"`
	Mean  float64 `json:"mean"`
	Std   float64 `json:"std"`
	Min   float64 `json:"min"`
	Max   float64 `json:"max"`
}

// Summary returns a copy with all non-finite values replaced by zero.
func (w Welford) Summary() Summary {
	return Summary{
		Count: w.Count,
		Mean:  finite(w.Mean),
		Std:   finite(w.Std()),
		Min:   finite(w.Min),
		Max:   finite(w.Max),
	}
}

func finite(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	return value
}
