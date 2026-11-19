package ingest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// SourceStats reports capture counters for a packet source.
type SourceStats struct {
	// Received is the number of normalized IP packets delivered.
	Received uint64
	// DecodeErrors is the number of frames that failed decoding and were
	// discarded instead of producing a normalized packet.
	DecodeErrors uint64
	// DroppedKernel is the number of packets the kernel dropped before the
	// sensor could read them (live AF_PACKET only).
	DroppedKernel uint64
}

// PacketSource yields normalized packets. NextPacket returns io.EOF exactly
// once no more packets are available (offline replay), and may return
// context.Canceled or a closed-source error for live capture.
type PacketSource interface {
	NextPacket() (Packet, error)
	Close() error
	Stats() SourceStats
}

// ErrLiveCaptureUnsupported is returned when the binary was built without a
// live capture backend for the current platform.
var ErrLiveCaptureUnsupported = errors.New("live capture is not available in this build; use --pcap or rebuild with a supported backend")

// ErrNoSource is returned when neither an interface nor a PCAP path is given.
var ErrNoSource = errors.New("no capture source configured: pass --pcap or --iface")

// OpenSource opens a PCAP file when path is non-empty, otherwise a live
// interface. This is the single entry point used by the CLI.
func OpenSource(iface, pcapPath string) (PacketSource, error) {
	if pcapPath != "" {
		return OpenPcapFile(pcapPath)
	}
	if iface == "" {
		return nil, ErrNoSource
	}
	return OpenLive(iface)
}

// OpenLive opens the best live backend available on this platform.
func OpenLive(iface string) (PacketSource, error) {
	if iface == "" {
		return nil, ErrNoSource
	}
	if source, err, ok := openAfpacket(iface); ok {
		return source, err
	}
	if source, err, ok := openLibpcap(iface); ok {
		return source, err
	}
	return nil, ErrLiveCaptureUnsupported
}

// PcapFileSource replays a classic PCAP file with the pure-Go pcapgo reader.
// No CGo, Npcap, or libpcap installation is required.
type PcapFileSource struct {
	file         *os.File
	reader       *pcapgo.Reader
	linkType     layers.LinkType
	received     atomic.Uint64
	decodeErrors atomic.Uint64
	closed       atomic.Bool
}

// OpenPcapFile opens a classic `.pcap` file for deterministic offline replay.
func OpenPcapFile(path string) (*PcapFileSource, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pcap %q: %w", path, err)
	}
	reader, err := pcapgo.NewReader(file)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("read pcap header %q: %w", path, err)
	}
	return &PcapFileSource{
		file:     file,
		reader:   reader,
		linkType: decodeLinkType(reader.LinkType()),
	}, nil
}

// decodeLinkType maps PCAP link types that gopacket does not register (notably
// LINKTYPE_IPV4=228 and LINKTYPE_IPV6=229 emitted by some capture tools) onto
// the raw IP decoder, which dispatches on the IP version nibble.
func decodeLinkType(linkType layers.LinkType) layers.LinkType {
	if linkType == layers.LinkTypeIPv4 || linkType == layers.LinkTypeIPv6 {
		return layers.LinkTypeRaw
	}
	if layers.LinkTypeMetadata[linkType].Name == "" {
		return layers.LinkTypeRaw
	}
	return linkType
}

// NextPacket reads the next IP packet, skipping frames without an IPv4/IPv6
// network layer. Timestamps come from the capture file, never from time.Now.
func (s *PcapFileSource) NextPacket() (Packet, error) {
	if s.closed.Load() {
		return Packet{}, io.EOF
	}
	for {
		data, ci, err := s.reader.ReadPacketData()
		if err != nil {
			return Packet{}, err
		}
		opts := gopacket.DecodeOptions{Lazy: true, NoCopy: true}
		pkt := gopacket.NewPacket(data, s.linkType, opts)
		normalized, ok := FromGopacket(pkt)
		if !ok {
			if DecodeFailed(pkt) {
				s.decodeErrors.Add(1)
			}
			continue
		}
		// pcapgo already applies the capture timestamp; trust it over any
		// decoded metadata to keep replay byte-identical across platforms.
		normalized.TimestampUS = ci.Timestamp.UnixMicro()
		normalized.CaptureLen = ci.CaptureLength
		s.received.Add(1)
		return normalized, nil
	}
}

// Close releases the underlying file.
func (s *PcapFileSource) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	if s.file == nil {
		return nil
	}
	return s.file.Close()
}

// Stats returns how many normalized IP packets were delivered.
func (s *PcapFileSource) Stats() SourceStats {
	return SourceStats{Received: s.received.Load(), DecodeErrors: s.decodeErrors.Load()}
}
