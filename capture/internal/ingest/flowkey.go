// Package ingest turns captured frames into normalized packets and provides
// packet sources for live interfaces and offline PCAP replay.
package ingest

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"net"
)

// Protocol numbers used by the sensor. The wire format is authoritative; these
// constants only exist so call sites do not grow magic numbers.
const (
	ProtoICMP   uint8 = 1
	ProtoTCP    uint8 = 6
	ProtoUDP    uint8 = 17
	ProtoICMPv6 uint8 = 58
)

// TCP flag bits as they appear on the wire.
const (
	TCPFlagFIN uint8 = 0x01
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagPSH uint8 = 0x08
	TCPFlagACK uint8 = 0x10
	TCPFlagURG uint8 = 0x20
	TCPFlagECE uint8 = 0x40
	TCPFlagCWR uint8 = 0x80
)

// FlowKey is a fixed-size directional five-tuple. It is deliberately a value
// type with no pointers so it can be used directly as a Go map key and copied
// without allocation on the packet hot path.
//
// IPv4 addresses are stored in the first four bytes of the 16-byte arrays with
// the remaining bytes zero. IPv6 addresses use all sixteen bytes. IsIPv6 keeps
// the two families distinct even if an address happens to be IPv4-mapped.
type FlowKey struct {
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	IsIPv6  bool
}

// Canonical returns the flow key with endpoints in a stable lexicographic
// order. Both directions of a conversation map to the same canonical key, so a
// hash of it routes every packet of the flow to one worker.
func (k FlowKey) Canonical() FlowKey {
	if endpointLess(k.DstIP, k.DstPort, k.SrcIP, k.SrcPort) {
		return FlowKey{
			SrcIP:   k.DstIP,
			DstIP:   k.SrcIP,
			SrcPort: k.DstPort,
			DstPort: k.SrcPort,
			Proto:   k.Proto,
			IsIPv6:  k.IsIPv6,
		}
	}
	return k
}

// Reverse returns the flow key with source and destination swapped.
func (k FlowKey) Reverse() FlowKey {
	return FlowKey{
		SrcIP:   k.DstIP,
		DstIP:   k.SrcIP,
		SrcPort: k.DstPort,
		DstPort: k.SrcPort,
		Proto:   k.Proto,
		IsIPv6:  k.IsIPv6,
	}
}

// ShardIndex returns a deterministic worker index in [0, workers). A->B and
// B->A always resolve to the same shard because the canonical form is hashed.
func (k FlowKey) ShardIndex(workers int) int {
	if workers <= 1 {
		return 0
	}
	canonical := k.Canonical()
	var buf [38]byte
	copy(buf[0:16], canonical.SrcIP[:])
	copy(buf[16:32], canonical.DstIP[:])
	binary.BigEndian.PutUint16(buf[32:34], canonical.SrcPort)
	binary.BigEndian.PutUint16(buf[34:36], canonical.DstPort)
	buf[36] = canonical.Proto
	if canonical.IsIPv6 {
		buf[37] = 1
	}
	h := fnv.New64a()
	_, _ = h.Write(buf[:])
	return int(h.Sum64() % uint64(workers))
}

// Hash returns the FNV-1a 64-bit hash of the canonical key. Tests use it to
// assert that both directions hash identically.
func (k FlowKey) Hash() uint64 {
	canonical := k.Canonical()
	var buf [38]byte
	copy(buf[0:16], canonical.SrcIP[:])
	copy(buf[16:32], canonical.DstIP[:])
	binary.BigEndian.PutUint16(buf[32:34], canonical.SrcPort)
	binary.BigEndian.PutUint16(buf[34:36], canonical.DstPort)
	buf[36] = canonical.Proto
	if canonical.IsIPv6 {
		buf[37] = 1
	}
	h := fnv.New64a()
	_, _ = h.Write(buf[:])
	return h.Sum64()
}

// SrcString renders the source address in canonical human-readable form.
func (k FlowKey) SrcString() string { return ipString(k.SrcIP, k.IsIPv6) }

// DstString renders the destination address in canonical human-readable form.
func (k FlowKey) DstString() string { return ipString(k.DstIP, k.IsIPv6) }

// String is a stable, log-friendly representation of the directional key.
func (k FlowKey) String() string {
	return fmt.Sprintf("%s:%d->%s:%d/%d", k.SrcString(), k.SrcPort, k.DstString(), k.DstPort, k.Proto)
}

// SortKey is a byte representation suitable for deterministic ordering of
// flows in extract output. It is intentionally independent of map iteration.
func (k FlowKey) SortKey() []byte {
	canonical := k.Canonical()
	buf := make([]byte, 0, 40)
	buf = append(buf, canonical.SrcIP[:]...)
	buf = append(buf, canonical.DstIP[:]...)
	buf = binary.BigEndian.AppendUint16(buf, canonical.SrcPort)
	buf = binary.BigEndian.AppendUint16(buf, canonical.DstPort)
	buf = append(buf, canonical.Proto)
	if canonical.IsIPv6 {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	return buf
}

// Hex returns a compact hex identity used for flow IDs and Redis members.
func (k FlowKey) Hex() string {
	return hex.EncodeToString(k.SortKey())
}

func endpointLess(aIP [16]byte, aPort uint16, bIP [16]byte, bPort uint16) bool {
	if cmp := bytes.Compare(aIP[:], bIP[:]); cmp != 0 {
		return cmp < 0
	}
	return aPort < bPort
}

func ipString(addr [16]byte, isIPv6 bool) string {
	if isIPv6 {
		return net.IP(addr[:]).String()
	}
	return net.IP(addr[:4]).String()
}
