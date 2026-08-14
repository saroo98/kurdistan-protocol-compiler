// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package scannera

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const privacyCorpusSchema = "kurdistan-phase17-privacy-corpus-v1"

type privacyCorpus struct {
	Schema string              `json:"schema"`
	Cases  []privacyCorpusCase `json:"cases"`
}

type privacyCorpusCase struct {
	Name        string  `json:"name"`
	Source      string  `json:"source"`
	PayloadUTF8 string  `json:"payloadUtf8,omitempty"`
	PayloadHex  string  `json:"payloadHex,omitempty"`
	WantPass    bool    `json:"wantPass"`
	WantPrivacy Privacy `json:"wantPrivacy"`
}

func TestIndependentScannersPassExactAdversarialCorpus(t *testing.T) {
	repositoryRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	corpusPath := filepath.Join(repositoryRoot, "testdata", "fixtures", "phase17", "privacy-scanner", "corpus-v1.json")
	corpus := loadPrivacyCorpus(t, corpusPath)
	python := findPythonForTest(t)
	script := filepath.Join(repositoryRoot, "scripts", "phase17", "privacy_scanner_b.py")
	for _, test := range corpus.Cases {
		t.Run(test.Name, func(t *testing.T) {
			payload := test.payload(t)
			otherSource := "REMOTE_JOURNAL"
			if test.Source == otherSource {
				otherSource = "ANDROID_LOGCAT"
			}
			raw := scannerByteStream([2]any{test.Source, payload}, [2]any{otherSource, []byte("safe categorical record")})
			goReceipt := Scan(bytes.NewReader(raw), int64(len(raw)))
			pythonReceipt := runPythonScannerForCorpus(t, python, script, raw)
			for name, receipt := range map[string]Receipt{"Go A": goReceipt, "Python B": pythonReceipt} {
				if (receipt.Result == "PASS") != test.WantPass || receipt.Privacy != test.WantPrivacy ||
					receipt.Truncated || receipt.ParseFailure || receipt.BackpressureFailure || receipt.CoverageGap {
					t.Fatalf("%s receipt=%+v wantPass=%t wantPrivacy=%+v", name, receipt, test.WantPass, test.WantPrivacy)
				}
			}
			if goReceipt.InputSHA256 != pythonReceipt.InputSHA256 || goReceipt.BytesConsumed != pythonReceipt.BytesConsumed ||
				goReceipt.RecordsConsumed != pythonReceipt.RecordsConsumed {
				t.Fatalf("receipt parity mismatch: go=%+v python=%+v", goReceipt, pythonReceipt)
			}
		})
	}
}

func loadPrivacyCorpus(t *testing.T, path string) privacyCorpus {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value privacyCorpus
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || value.Schema != privacyCorpusSchema || len(value.Cases) < 25 {
		t.Fatalf("corpus envelope rejected: schema=%q cases=%d trailing=%v", value.Schema, len(value.Cases), err)
	}
	seen := make(map[string]bool, len(value.Cases))
	for _, test := range value.Cases {
		if test.Name == "" || seen[test.Name] || (test.Source != "ANDROID_LOGCAT" && test.Source != "REMOTE_JOURNAL") ||
			(test.PayloadUTF8 == "") == (test.PayloadHex == "") || (test.WantPass && test.WantPrivacy != (Privacy{})) {
			t.Fatalf("corpus case rejected: %+v", test)
		}
		seen[test.Name] = true
	}
	return value
}

func (value privacyCorpusCase) payload(t *testing.T) []byte {
	t.Helper()
	if value.PayloadHex == "" {
		return []byte(value.PayloadUTF8)
	}
	decoded, err := hex.DecodeString(value.PayloadHex)
	if err != nil || len(decoded) == 0 {
		t.Fatalf("payloadHex rejected for %s: %v", value.Name, err)
	}
	return decoded
}

func runPythonScannerForCorpus(t *testing.T, python, script string, raw []byte) Receipt {
	t.Helper()
	input := filepath.Join(t.TempDir(), "stream.jsonl")
	if err := os.WriteFile(input, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(python, "-B", "-I", script, "--input", input).CombinedOutput()
	if err != nil {
		t.Fatalf("python scanner: %v: %s", err, output)
	}
	var receipt Receipt
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || receipt.Name != "PYTHON_B" {
		t.Fatalf("Python scanner receipt rejected: receipt=%+v trailing=%v", receipt, err)
	}
	return receipt
}
