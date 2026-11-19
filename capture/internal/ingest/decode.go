package ingest

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Packet is the normalized, allocation-free representation of one captured
// frame. All feature math is driven by TimestampUS, never by the wall clock.
type Packet struct {
	TimestampUS int64
	SrcIP       [16]byte
	DstIP       [16]byte
	SrcPort     uint16
	DstPort     uint16
	Proto       uint8
	IsIPv6      bool
	TCPFlags    uint8
	TCPWindow   uint16
	// Length is the IP total length in bytes (header plus payload).
	Length int
	// HeaderLen follows PyFlowMeter/CICFlowMeter semantics: the IP header
	// length for TCP and the fixed 8-byte transport header otherwise.
	HeaderLen int
	// PayloadLen is the transport payload length.
	PayloadLen int
	// CaptureLen is the captured frame length, useful for truncation checks.
	CaptureLen int
}

// Key returns the directional five-tuple for the packet.
func (p *Packet) Key() FlowKey {
	return FlowKey{
		Src:    Endpoint{IP: p.SrcIP, Port: p.SrcPort},
		Dst:    Endpoint{IP: p.DstIP, Port: p.DstPort},
		Proto:  p.Proto,
		IsIPv6: p.IsIPv6,
	}
}

// DecodeFailed reports whether gopacket recorded a decode failure for a frame,
// which the sources report as a decode error instead of silently skipping it.
func DecodeFailed(pkt gopacket.Packet) bool {
	return pkt != nil && pkt.ErrorLayer() != nil
}

// HasFlag reports whether every bit in mask is set in the TCP flags byte.
func (p *Packet) HasFlag(mask uint8) bool {
	return p.TCPFlags&mask == mask
}

// FromGopacket converts a decoded gopacket packet into the sensor's normalized
// form. It returns false for frames that carry no IPv4/IPv6 network layer.
func FromGopacket(pkt gopacket.Packet) (Packet, bool) {
	if pkt == nil {
		return Packet{}, false
	}
	ci := pkt.Metadata().CaptureInfo
	ts := ci.Timestamp
	if ts.IsZero() {
		ts = time.Unix(0, 0)
	}
	return fromNetwork(pkt, ts.UnixMicro(), ci.CaptureLength)
}

func fromNetwork(pkt gopacket.Packet, timestampUS int64, captureLen int) (Packet, bool) {
	out := Packet{TimestampUS: timestampUS, CaptureLen: captureLen}

	var ipProto uint8
	switch ip := pkt.NetworkLayer().(type) {
	case *layers.IPv4:
		if ip == nil {
			return Packet{}, false
		}
		copy(out.SrcIP[:4], ip.SrcIP.To4())
		copy(out.DstIP[:4], ip.DstIP.To4())
		out.IsIPv6 = false
		ipProto = uint8(ip.Protocol)
		ihl := int(ip.IHL) * 4
		if ihl <= 0 {
			ihl = 20
		}
		total := int(ip.Length)
		if total <= 0 {
			total = ihl + len(ip.Payload)
		}
		out.Length = total
		out.HeaderLen = ihl
	case *layers.IPv6:
		if ip == nil {
			return Packet{}, false
		}
		copy(out.SrcIP[:], ip.SrcIP.To16())
		copy(out.DstIP[:], ip.DstIP.To16())
		out.IsIPv6 = true
		ipProto = uint8(ip.NextHeader)
		out.Length = 40 + int(ip.Length)
		out.HeaderLen = 40
	default:
		return Packet{}, false
	}

	// gopacket may or may not decode a transport layer depending on the link
	// type, fragmentation, and extension headers. Prefer the concrete layers,
	// then fall back to the IP protocol number.
	if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		out.Proto = ProtoTCP
		out.SrcPort = uint16(tcp.SrcPort)
		out.DstPort = uint16(tcp.DstPort)
		out.TCPFlags = tcpFlags(tcp)
		out.TCPWindow = uint16(tcp.Window)
		out.PayloadLen = len(tcp.Payload)
		out.HeaderLen = ipHeaderLengthForTransport(pkt, out.IsIPv6)
		return out, true
	}
	if udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		out.Proto = ProtoUDP
		out.SrcPort = uint16(udp.SrcPort)
		out.DstPort = uint16(udp.DstPort)
		out.PayloadLen = len(udp.Payload)
		out.HeaderLen = 8
		return out, true
	}
	if _, ok := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
		out.Proto = ProtoICMP
		out.HeaderLen = 8
		out.PayloadLen = maxInt(0, out.Length-out.HeaderLen)
		return out, true
	}
	if _, ok := pkt.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6); ok {
		out.Proto = ProtoICMPv6
		out.HeaderLen = 8
		out.PayloadLen = maxInt(0, out.Length-out.HeaderLen)
		return out, true
	}
	// Unknown transport (for example an undecoded fragment). Keep the network
	// layer so the flow still exists, but expose no ports or flags.
	out.Proto = ipProto
	out.PayloadLen = maxInt(0, out.Length-out.HeaderLen)
	return out, true
}

func ipHeaderLengthForTransport(pkt gopacket.Packet, isIPv6 bool) int {
	if isIPv6 {
		return 40
	}
	if ip, ok := pkt.NetworkLayer().(*layers.IPv4); ok && ip.IHL > 0 {
		return int(ip.IHL) * 4
	}
	return 20
}

func tcpFlags(tcp *layers.TCP) uint8 {
	var flags uint8
	if tcp.FIN {
		flags |= TCPFlagFIN
	}
	if tcp.SYN {
		flags |= TCPFlagSYN
	}
	if tcp.RST {
		flags |= TCPFlagRST
	}
	if tcp.PSH {
		flags |= TCPFlagPSH
	}
	if tcp.ACK {
		flags |= TCPFlagACK
	}
	if tcp.URG {
		flags |= TCPFlagURG
	}
	if tcp.ECE {
		flags |= TCPFlagECE
	}
	if tcp.CWR {
		flags |= TCPFlagCWR
	}
	return flags
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
