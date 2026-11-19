package main

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"capture/internal/flow"
)

func TestExtractIsByteIdenticalCSV(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join("..", "..", "..", "tests", "fixtures", "sample_synthetic.pcap")
	first := filepath.Join(dir, "first.csv")
	second := filepath.Join(dir, "second.csv")

	if err := runExtract(config{pcapPath: fixture, outPath: first, workers: 4}); err != nil {
		t.Fatalf("first extract: %v", err)
	}
	if err := runExtract(config{pcapPath: fixture, outPath: second, workers: 4}); err != nil {
		t.Fatalf("second extract: %v", err)
	}
	firstBytes, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("extract output is not byte-identical across runs")
	}

	reader := csv.NewReader(bytes.NewReader(firstBytes))
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("parse extract csv: %v", err)
	}
	if len(rows) != 22 {
		t.Fatalf("expected a header plus 21 flows, got %d rows", len(rows))
	}
	header := rows[0]
	expected := flow.CSVHeader()
	if len(header) != len(expected) {
		t.Fatalf("expected %d columns, got %d", len(expected), len(header))
	}
	for i := range expected {
		if header[i] != expected[i] {
			t.Fatalf("column %d: got %q, want %q", i, header[i], expected[i])
		}
	}
	if len(header) != len(flow.MetadataColumns)+flow.FeatureCount {
		t.Fatalf("header does not follow the canonical schema: %v", header)
	}

	synIndex := columnIndex(t, header, "syn_cnt")
	protocolIndex := columnIndex(t, header, "protocol")
	sawHandshake := false
	for _, row := range rows[1:] {
		syn, err := strconv.Atoi(row[synIndex])
		if err != nil {
			t.Fatalf("syn_cnt is not an integer: %q", row[synIndex])
		}
		if syn == 2 {
			sawHandshake = true
		}
		if protocol, err := strconv.Atoi(row[protocolIndex]); err != nil || protocol <= 0 {
			t.Fatalf("protocol column is invalid: %q", row[protocolIndex])
		}
	}
	if !sawHandshake {
		t.Fatal("expected the TCP handshake flow to report syn_cnt=2")
	}
}

func TestExtractWorkersDoNotChangeOutput(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join("..", "..", "..", "tests", "fixtures", "sample_synthetic.pcap")
	single := filepath.Join(dir, "single.csv")
	many := filepath.Join(dir, "many.csv")
	if err := runExtract(config{pcapPath: fixture, outPath: single, workers: 1}); err != nil {
		t.Fatal(err)
	}
	if err := runExtract(config{pcapPath: fixture, outPath: many, workers: 8}); err != nil {
		t.Fatal(err)
	}
	singleBytes, _ := os.ReadFile(single)
	manyBytes, _ := os.ReadFile(many)
	if !bytes.Equal(singleBytes, manyBytes) {
		t.Fatal("worker count changed extract output")
	}
}

func TestNormalizeIngestURL(t *testing.T) {
	cases := map[string]string{
		"http://localhost:5000":               "http://localhost:5000/api/ingest",
		"http://localhost:5000/":              "http://localhost:5000/api/ingest",
		"http://localhost:5000/api/ingest":    "http://localhost:5000/api/ingest",
		"http://localhost:5000/api/flows?x=1": "http://localhost:5000/api/flows?x=1",
	}
	for input, expected := range cases {
		if got := normalizeIngestURL(input); got != expected {
			t.Errorf("normalizeIngestURL(%q) = %q, want %q", input, got, expected)
		}
	}
}

func columnIndex(t *testing.T, header []string, name string) int {
	t.Helper()
	for i, column := range header {
		if column == name {
			return i
		}
	}
	t.Fatalf("missing column %q in %v", name, header)
	return -1
}
