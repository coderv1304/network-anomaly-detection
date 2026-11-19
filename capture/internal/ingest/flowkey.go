// Package ingest turns captured frames into normalized packets and provides
// packet sources for live interfaces and offline PCAP replay.
package ingest

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
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

// FNV-1a 64-bit parameters, inlined so hashing a key never allocates.
const (
	fnvOffset64 uint64 = 14695981039346656037
	fnvPrime64  uint64 = 1099511628211
)

// Endpoint is one side of a conversation. IPv4 addresses live in the first
// four bytes with the remaining bytes zero; IPv6 addresses use all sixteen.
type Endpoint struct {
	IP   [16]byte
	Port uint16
}

// FlowKey is a fixed-size directional five-tuple. It is a comparable value type
// with no pointers, so it is usable directly as a map key and copies without
// allocating on the packet hot path.
//
// IsIPv6 keeps the two address families distinct even when an IPv4 address is
// stored in its IPv4-mapped form.
type FlowKey struct {
	Src    Endpoint
	Dst    Endpoint
	Proto  uint8
	IsIPv6 bool
}

// Canonical returns the flow key with endpoints in stable lexicographic order
// (IP bytes, then port). Both directions of a conversation map to the same
// canonical key, so every packet of a flow reaches one worker.
func (k FlowKey) Canonical() FlowKey {
	if endpointLess(k.Dst, k.Src) {
		return FlowKey{Src: k.Dst, Dst: k.Src, Proto: k.Proto, IsIPv6: k.IsIPv6}
	}
	return k
}

// Reverse returns the flow key with source and destination swapped.
func (k FlowKey) Reverse() FlowKey {
	return FlowKey{Src: k.Dst, Dst: k.Src, Proto: k.Proto, IsIPv6: k.IsIPv6}
}

// CanonicalShard maps the conversation to a worker index in [0, numWorkers).
// The canonical endpoint order is hashed with FNV-1a 64, so A->B and B->A
// always select the same shard.
func (k FlowKey) CanonicalShard(numWorkers uint64) uint64 {
	if numWorkers == 0 {
		return 0
	}
	return k.hashCanonical() % numWorkers
}

// ShardIndex is the signed convenience form of CanonicalShard.
func (k FlowKey) ShardIndex(workers int) int {
	if workers <= 1 {
		return 0
	}
	return int(k.CanonicalShard(uint64(workers)))
}

// Hash returns the FNV-1a 64-bit hash of the canonical key. Tests use it to
// assert that both directions hash identically.
func (k FlowKey) Hash() uint64 { return k.hashCanonical() }

// hashCanonical hashes a fixed 38-byte canonical tuple without allocating.
func (k FlowKey) hashCanonical() uint64 {
	canonical := k.Canonical()
	var buf [38]byte
	copy(buf[0:16], canonical.Src.IP[:])
	copy(buf[16:32], canonical.Dst.IP[:])
	binary.BigEndian.PutUint16(buf[32:34], canonical.Src.Port)
	binary.BigEndian.PutUint16(buf[34:36], canonical.Dst.Port)
	buf[36] = canonical.Proto
	if canonical.IsIPv6 {
		buf[37] = 1
	}
	hash := fnvOffset64
	for _, b := range buf[:] {
		hash ^= uint64(b)
		hash *= fnvPrime64
	}
	return hash
}

// SrcString renders the source address in canonical human-readable form.
func (k FlowKey) SrcString() string { return ipString(k.Src.IP, k.IsIPv6) }

// DstString renders the destination address in canonical human-readable form.
func (k FlowKey) DstString() string { return ipString(k.Dst.IP, k.IsIPv6) }

// String is a stable, log-friendly representation of the directional key.
func (k FlowKey) String() string {
	return fmt.Sprintf("%s:%d->%s:%d/%d", k.SrcString(), k.Src.Port, k.DstString(), k.Dst.Port, k.Proto)
}

// SortKey is a byte representation suitable for deterministic ordering of
// flows in extract output. It is intentionally independent of map iteration.
func (k FlowKey) SortKey() []byte {
	canonical := k.Canonical()
	buf := make([]byte, 0, 40)
	buf = append(buf, canonical.Src.IP[:]...)
	buf = append(buf, canonical.Dst.IP[:]...)
	buf = binary.BigEndian.AppendUint16(buf, canonical.Src.Port)
	buf = binary.BigEndian.AppendUint16(buf, canonical.Dst.Port)
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

func endpointLess(a, b Endpoint) bool {
	if cmp := bytes.Compare(a.IP[:], b.IP[:]); cmp != 0 {
		return cmp < 0
	}
	return a.Port < b.Port
}

func ipString(addr [16]byte, isIPv6 bool) string {
	if isIPv6 {
		return net.IP(addr[:]).String()
	}
	return net.IP(addr[:4]).String()
}
