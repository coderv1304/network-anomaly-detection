// Package metrics exposes the sensor's Prometheus collectors.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics owns an isolated Prometheus registry. Isolation keeps tests from
// double-registering collectors and lets one process host several sensors.
type Metrics struct {
	registry *prometheus.Registry

	PacketsReceived          prometheus.Counter
	PacketsDecodeErrors      prometheus.Counter
	PacketsDroppedKernel     prometheus.Counter
	ActiveFlows              prometheus.Gauge
	FlowsCompleted           prometheus.Counter
	FlowsDroppedBackpressure prometheus.Counter
	AlertsEmitted            prometheus.Counter
	InferenceDuration        prometheus.Histogram
	ModelInfo                *prometheus.GaugeVec
}

// New creates and registers the sensor collectors.
func New() *Metrics {
	registry := prometheus.NewRegistry()
	m := &Metrics{
		registry: registry,
		PacketsReceived: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netshield_packets_received_total",
			Help: "Total IPv4/IPv6 packets delivered by the capture source.",
		}),
		PacketsDecodeErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netshield_packets_decode_errors_total",
			Help: "Total captured frames that failed link/network/transport decoding.",
		}),
		PacketsDroppedKernel: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netshield_packets_dropped_kernel_total",
			Help: "Total packets dropped by the kernel capture buffer.",
		}),
		ActiveFlows: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "netshield_active_flows",
			Help: "Current number of active bidirectional flows.",
		}),
		FlowsCompleted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netshield_flows_completed_total",
			Help: "Total flows evicted, timed out, or terminated cleanly.",
		}),
		FlowsDroppedBackpressure: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netshield_flows_dropped_backpressure_total",
			Help: "Total completed flows shed by the bounded inference queue.",
		}),
		AlertsEmitted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netshield_alerts_emitted_total",
			Help: "Total flagged flows admitted to the alert forwarder.",
		}),
		InferenceDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "netshield_inference_duration_seconds",
			Help:    "Time spent scoring one completed flow.",
			Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1},
		}),
		ModelInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "netshield_model_info",
			Help: "Active model identity; the value is always 1.",
		}, []string{"sha256", "backend", "version"}),
	}
	registry.MustRegister(
		m.PacketsReceived,
		m.PacketsDecodeErrors,
		m.PacketsDroppedKernel,
		m.ActiveFlows,
		m.FlowsCompleted,
		m.FlowsDroppedBackpressure,
		m.AlertsEmitted,
		m.InferenceDuration,
		m.ModelInfo,
	)
	m.ModelInfo.WithLabelValues("unloaded", "none", "none").Set(0)
	return m
}

// Registry exposes the underlying registry for tests.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// Handler returns the `/metrics` HTTP handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// SetModel publishes the active model identity and removes stale label sets.
func (m *Metrics) SetModel(sha256, backend, version string) {
	m.ModelInfo.Reset()
	m.ModelInfo.WithLabelValues(sha256, backend, version).Set(1)
}
