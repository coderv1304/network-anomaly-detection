package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractIsByteIdentical(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join("..", "..", "..", "tests", "fixtures", "sample_synthetic.pcap")
	first := filepath.Join(dir, "first.jsonl")
	second := filepath.Join(dir, "second.jsonl")

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
	lines := strings.Count(strings.TrimSpace(string(firstBytes)), "\n") + 1
	if lines != 21 {
		t.Fatalf("expected 21 flows from the synthetic fixture, got %d", lines)
	}
	if !strings.Contains(string(firstBytes), `"syn_cnt":2`) {
		t.Fatal("expected the handshake SYN count in extract output")
	}
}

func TestExtractWorkersDoNotChangeOutput(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join("..", "..", "..", "tests", "fixtures", "sample_synthetic.pcap")
	single := filepath.Join(dir, "single.jsonl")
	many := filepath.Join(dir, "many.jsonl")
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
		"http://localhost:5000":                  "http://localhost:5000/api/ingest",
		"http://localhost:5000/":                 "http://localhost:5000/api/ingest",
		"http://localhost:5000/api/ingest":       "http://localhost:5000/api/ingest",
		"http://localhost:5000/api/flows?x=1":    "http://localhost:5000/api/flows?x=1",
	}
	for input, expected := range cases {
		if got := normalizeIngestURL(input); got != expected {
			t.Errorf("normalizeIngestURL(%q) = %q, want %q", input, got, expected)
		}
	}
}
