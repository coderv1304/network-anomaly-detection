//go:build !linux

package ingest

// openAfpacket is unavailable outside Linux. The bool distinguishes "this
// backend is not compiled in" from "the backend was tried and failed".
func openAfpacket(string) (PacketSource, error, bool) {
	return nil, nil, false
}
