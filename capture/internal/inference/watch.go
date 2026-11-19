package inference

import (
	"sync"
	"sync/atomic"
	"time"
)

// DefaultWatchInterval is the SHA-256 poll cadence for both model artifacts.
const DefaultWatchInterval = 5 * time.Second

// Reloader owns the active BundleState behind an atomic pointer. Reload swaps
// the pointer only after the new generation passes schema, integrity, and
// test-vector validation, so scoring workers never observe a partial model.
type Reloader struct {
	current atomic.Pointer[BundleState]

	modelPath    string
	manifestPath string

	hashMu   sync.Mutex
	lastHash string

	onSwap    func(*BundleState)
	closeOnce sync.Once
}

// NewReloader loads the initial bundle and stores it atomically.
func NewReloader(modelPath, manifestPath string, onSwap func(*BundleState)) (*Reloader, error) {
	bundle, err := LoadBundle(modelPath, manifestPath)
	if err != nil {
		return nil, err
	}
	reloader := &Reloader{
		modelPath:    modelPath,
		manifestPath: manifestPath,
		onSwap:       onSwap,
	}
	reloader.current.Store(bundle)
	reloader.lastHash = artifactPairHash(modelPath, manifestPath)
	return reloader, nil
}

// Current returns the active bundle. The value is immutable.
func (r *Reloader) Current() *BundleState { return r.current.Load() }

// Reload re-reads both artifacts and swaps the bundle when they validate.
func (r *Reloader) Reload() error {
	hash := artifactPairHash(r.modelPath, r.manifestPath)
	r.hashMu.Lock()
	unchanged := hash != "" && hash == r.lastHash
	r.hashMu.Unlock()
	if unchanged && r.Current() != nil {
		return nil
	}
	bundle, err := LoadBundle(r.modelPath, r.manifestPath)
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
		// Give in-flight scores a grace period before releasing native ONNX
		// sessions.
		time.AfterFunc(5*time.Second, func() { closeScorer(previous.Scorer) })
	}
	return nil
}

// Watch polls the artifacts until done is closed.
func (r *Reloader) Watch(done <-chan struct{}, interval time.Duration, report func(error)) {
	if interval <= 0 {
		interval = DefaultWatchInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
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
	if bundle := r.current.Load(); bundle != nil && bundle.Scorer != nil {
		closeScorer(bundle.Scorer)
	}
	return nil
}
