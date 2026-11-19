package ingest

import (
	"io"
	"testing"
)

func TestPcapFileSourceReadsSyntheticFixture(t *testing.T) {
	source, err := OpenPcapFile("../../../tests/fixtures/sample_synthetic.pcap")
	if err != nil {
		t.Fatalf("OpenPcapFile: %v", err)
	}
	defer source.Close()

	count := 0
	for {
		packet, err := source.NextPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPacket: %v", err)
		}
		if packet.Length <= 0 {
			t.Fatalf("packet %d has non-positive length %d", count, packet.Length)
		}
		count++
	}
	if count != 25 {
		t.Fatalf("expected 25 IP packets, got %d", count)
	}
	if got := source.Stats().Received; got != 25 {
		t.Fatalf("expected 25 received, got %d", got)
	}
}
