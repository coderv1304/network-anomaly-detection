//go:build !cgo || windows || no_pcap

package ingest

// openLibpcap is unavailable in this build. Use --pcap for deterministic
// replay, or rebuild with CGO enabled and libpcap installed on Unix.
func openLibpcap(string) (PacketSource, error, bool) {
	return nil, nil, false
}
