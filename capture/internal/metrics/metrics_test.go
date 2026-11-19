package metrics

import "testing"

func TestCollectorNames(t *testing.T) {
	m := New()
	m.PacketsReceived.Inc()
	m.PacketsDroppedKernel.Inc()
	m.ActiveFlows.Set(3)
	m.FlowsCompleted.Inc()
	m.FlowsDroppedBackpressure.Inc()
	m.AlertsEmitted.Inc()
	m.InferenceDuration.Observe(0.001)
	m.SetModel("abc123", "linear-manifest", "v1")

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	names := make(map[string]bool, len(families))
	for _, family := range families {
		names[family.GetName()] = true
	}
	for _, expected := range []string{
		"netshield_packets_received_total",
		"netshield_packets_dropped_kernel_total",
		"netshield_active_flows",
		"netshield_flows_completed_total",
		"netshield_flows_dropped_backpressure_total",
		"netshield_alerts_emitted_total",
		"netshield_inference_duration_seconds",
		"netshield_model_info",
	} {
		if !names[expected] {
			t.Errorf("missing collector %s", expected)
		}
	}
}
