//go:build cgo && !windows && !no_pcap

package ingest

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// libpcapSource is the portable live backend for Unix-like systems that have
// libpcap development headers installed. Windows is excluded because the
// Npcap SDK headers are not part of the zero-friction build; use the
// AF_PACKET backend on Linux or a PCAP file on Windows.
type libpcapSource struct {
	handle   *pcap.Handle
	received atomic.Uint64
	closed   atomic.Bool
}

func openLibpcap(iface string) (PacketSource, error, bool) {
	handle, err := pcap.OpenLive(iface, 262144, true, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open libpcap interface %q: %w", iface, err), true
	}
	if err := handle.SetBPFFilter("ip or ip6"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("install libpcap BPF filter: %w", err), true
	}
	return &libpcapSource{handle: handle}, nil, true
}

func (s *libpcapSource) NextPacket() (Packet, error) {
	if s.closed.Load() {
		return Packet{}, fmt.Errorf("capture source is closed")
	}
	for {
		data, ci, err := s.handle.ReadPacketData()
		if err != nil {
			return Packet{}, err
		}
		pkt := gopacket.NewPacket(data, s.handle.LinkType(), gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		normalized, ok := FromGopacket(pkt)
		if !ok {
			continue
		}
		normalized.TimestampUS = ci.Timestamp.UnixMicro()
		normalized.CaptureLen = ci.CaptureLength
		s.received.Add(1)
		return normalized, nil
	}
}

func (s *libpcapSource) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	if s.handle != nil {
		s.handle.Close()
	}
	return nil
}

func (s *libpcapSource) Stats() SourceStats {
	stats := SourceStats{Received: s.received.Load()}
	if s.handle != nil {
		if pcapStats, err := s.handle.Stats(); err == nil {
			stats.DroppedKernel = uint64(pcapStats.PacketsDropped)
		}
	}
	return stats
}
