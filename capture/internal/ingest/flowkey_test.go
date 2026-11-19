package ingest

import (
	"net"
	"testing"
)

func TestCanonicalKeyIsSymmetric(t *testing.T) {
	a := FlowKey{
		Src:   Endpoint{IP: ip16("10.0.0.1"), Port: 1234},
		Dst:   Endpoint{IP: ip16("10.0.0.2"), Port: 80},
		Proto: ProtoTCP,
	}
	b := a.Reverse()

	if a.Canonical() != b.Canonical() {
		t.Fatalf("reverse keys produced different canonical forms: %v vs %v", a.Canonical(), b.Canonical())
	}
	if a.Hash() != b.Hash() {
		t.Fatalf("reverse keys hashed differently: %d vs %d", a.Hash(), b.Hash())
	}
	for workers := 1; workers <= 16; workers++ {
		if a.ShardIndex(workers) != b.ShardIndex(workers) {
			t.Fatalf("reverse keys routed to different shards for %d workers", workers)
		}
	}
}

func TestCanonicalShardIsSymmetricAndBounded(t *testing.T) {
	a := FlowKey{
		Src:   Endpoint{IP: ip16("192.0.2.10"), Port: 51515},
		Dst:   Endpoint{IP: ip16("198.51.100.20"), Port: 443},
		Proto: ProtoTCP,
	}
	b := a.Reverse()
	for _, workers := range []uint64{1, 2, 3, 7, 16, 64, 257} {
		if a.CanonicalShard(workers) != b.CanonicalShard(workers) {
			t.Fatalf("reverse keys routed to different shards for %d workers", workers)
		}
		if got := a.CanonicalShard(workers); got >= workers {
			t.Fatalf("shard %d is outside [0,%d)", got, workers)
		}
	}
	if a.CanonicalShard(0) != 0 {
		t.Fatalf("zero workers must map to shard 0, got %d", a.CanonicalShard(0))
	}
}

func TestCanonicalKeyPreservesDirectionalValues(t *testing.T) {
	a := FlowKey{
		Src:   Endpoint{IP: ip16("10.0.0.9"), Port: 5555},
		Dst:   Endpoint{IP: ip16("10.0.0.1"), Port: 443},
		Proto: ProtoTCP,
	}
	canonical := a.Canonical()
	if canonical.Src.IP != ip16("10.0.0.1") || canonical.Src.Port != 443 {
		t.Fatalf("canonical form did not order endpoints: %v", canonical)
	}
	if a.Src.IP != ip16("10.0.0.9") || a.Src.Port != 5555 {
		t.Fatalf("canonicalization mutated the directional key")
	}
}

func TestIPv4AndIPv6KeysAreDistinct(t *testing.T) {
	v4 := FlowKey{
		Src:    Endpoint{IP: ip16("10.0.0.1"), Port: 1},
		Dst:    Endpoint{IP: ip16("10.0.0.2"), Port: 2},
		Proto:  ProtoTCP,
		IsIPv6: false,
	}
	v6 := v4
	v6.IsIPv6 = true
	if v4.Canonical() == v6.Canonical() {
		t.Fatal("IPv4 and IPv6 keys must not collide")
	}
	if v4.Hash() == v6.Hash() {
		t.Fatal("IPv4 and IPv6 keys must not hash identically")
	}
}

func TestIPv6CanonicalKey(t *testing.T) {
	a := FlowKey{
		Src:    Endpoint{IP: ip16("2001:db8::2"), Port: 9000},
		Dst:    Endpoint{IP: ip16("2001:db8::1"), Port: 443},
		Proto:  ProtoTCP,
		IsIPv6: true,
	}
	if a.Canonical() != a.Reverse().Canonical() {
		t.Fatal("IPv6 reverse keys produced different canonical forms")
	}
	if a.SrcString() != "2001:db8::2" {
		t.Fatalf("unexpected IPv6 string %q", a.SrcString())
	}
}

func TestProtocolConstants(t *testing.T) {
	// Guard against accidental renumbering of the wire protocol values.
	if ProtoICMP != 1 || ProtoTCP != 6 || ProtoUDP != 17 || ProtoICMPv6 != 58 {
		t.Fatalf("unexpected protocol numbers: %d %d %d %d", ProtoICMP, ProtoTCP, ProtoUDP, ProtoICMPv6)
	}
}

func ip16(value string) [16]byte {
	var out [16]byte
	ip := net.ParseIP(value)
	if ip == nil {
		panic("bad test IP " + value)
	}
	if v4 := ip.To4(); v4 != nil {
		copy(out[:4], v4)
		return out
	}
	copy(out[:], ip.To16())
	return out
}
