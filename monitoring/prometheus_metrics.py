from prometheus_client import Counter, Histogram, start_http_server

# Counters
PACKETS_TOTAL = Counter('packets_total', 'Total processed packets')
ACTIVE_FLOWS = Counter('active_flows', 'Current active flows')
DROPPED_PACKETS = Counter('dropped_packets', 'Packets dropped due to errors or caps')

# Histogram for inference latency (seconds)
INFERENCE_LATENCY = Histogram('inference_latency_seconds',
                              'Latency of inference (seconds)',
                              buckets=[0.001,0.005,0.01,0.05,0.1,0.5,1,5])

def start_metrics_server(port=8000):
    '''Expose Prometheus metrics on the given port.'''
    start_http_server(port)
