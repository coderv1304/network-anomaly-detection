//go:build linux

package ingest

import (
	"fmt"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

// afpacketSource uses Linux AF_PACKET with TPACKET_V3. It requests the v3
// version explicitly so block retirement semantics are identical on every
// kernel that supports it.
type afpacketSource struct {
	handle   *afpacket.TPacket
	received atomic.Uint64
	closed   atomic.Bool
}

func openAfpacket(iface string) (PacketSource, error, bool) {
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
		afpacket.OptBlockSize(4*1024*1024),
		afpacket.OptFrameSize(64*1024),
		afpacket.OptNumBlocks(64),
		afpacket.OptBlockTimeout(10_000_000), // 10 ms retire timeout
		afpacket.OptPollTimeout(100_000_000), // 100 ms poll timeout
	)
	if err != nil {
		return nil, fmt.Errorf("open AF_PACKET interface %q: %w", iface, err), true
	}
	return &afpacketSource{handle: handle}, nil, true
}

func (s *afpacketSource) NextPacket() (Packet, error) {
	if s.closed.Load() {
		return Packet{}, fmt.Errorf("capture source is closed")
	}
	for {
		data, ci, err := s.handle.ZeroCopyReadPacketData()
		if err != nil {
			return Packet{}, err
		}
		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		normalized, ok := FromGopacket(pkt)
		if !ok {
			continue
		}
		// Use the kernel capture timestamp; it is the only clock that is
		// stable across kernel buffer boundaries.
		normalized.TimestampUS = ci.Timestamp.UnixMicro()
		normalized.CaptureLen = ci.CaptureLength
		s.received.Add(1)
		return normalized, nil
	}
}

func (s *afpacketSource) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	if s.handle != nil {
		s.handle.Close()
	}
	return nil
}

func (s *afpacketSource) Stats() SourceStats {
	stats := SourceStats{Received: s.received.Load()}
	if s.handle != nil {
		if _, v3, err := s.handle.SocketStats(); err == nil {
			stats.DroppedKernel = uint64(v3.Drops())
		}
	}
	return stats
}
