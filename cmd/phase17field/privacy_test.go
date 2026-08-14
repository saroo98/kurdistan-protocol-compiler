// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"kurdistan/internal/phase17privacy/scannera"
)

func TestMarshalPrivacyObservationStreamIsDeterministicAndComplete(t *testing.T) {
	raw, records, err := marshalPrivacyObservationStream([]privacyObservation{
		{source: "ANDROID_LOGCAT", data: []byte("android category")},
		{source: "REMOTE_JOURNAL", data: []byte("relay category")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if records != 2 || bytes.Count(raw, []byte("\n")) != 2 || bytes.Contains(raw, []byte("android category")) {
		t.Fatalf("records=%d raw=%q", records, raw)
	}
	if _, _, err := marshalPrivacyObservationStream([]privacyObservation{{source: "UNKNOWN", data: []byte("x")}}); err == nil {
		t.Fatal("unknown observation source accepted")
	}
}

func TestRunPrivacyScannersRequiresExactIndependentParityAndDeletesRawInput(t *testing.T) {
	root := t.TempDir()
	value := config{
		evidenceRoot: root, scannerAPath: "scanner-a", scannerBPath: "scanner-b.py", pythonPath: "python",
	}
	qualified := qualifiedRun{scannerADigest: strings.Repeat("1", 64), scannerBDigest: strings.Repeat("2", 64)}
	raw, records, err := marshalPrivacyObservationStream([]privacyObservation{
		{source: "ANDROID_LOGCAT", data: []byte("android category")},
		{source: "REMOTE_JOURNAL", data: []byte("relay category")},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Hex(raw)
	commands := []string{}
	var pythonArguments []string
	var mutex sync.Mutex
	runner := commandRunner{runFunc: func(_ context.Context, stdin []byte, _ string, name string, arguments ...string) ([]byte, error) {
		if !bytes.Equal(stdin, raw) || !containsArguments(arguments, "-", len(raw)) {
			return nil, errors.New("scanner tee input mismatch")
		}
		mutex.Lock()
		commands = append(commands, name)
		if name == "python" {
			pythonArguments = append([]string(nil), arguments...)
		}
		mutex.Unlock()
		receipt := scannerWireReceipt{
			Schema: scannera.ReceiptSchema, Name: "GO_A", InputSHA256: digest,
			BytesConsumed: uint64(len(raw)), RecordsConsumed: records, Result: "PASS",
		}
		if name == "python" {
			receipt.Name = "PYTHON_B"
		}
		return json.Marshal(receipt)
	}}
	receipts, err := runPrivacyScanners(context.Background(), runner, value, qualified, root, raw, records)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(commands)
	if !reflect.DeepEqual(commands, []string{"python", "scanner-a"}) || len(receipts) != 2 || receipts[0].Name != "GO_A" || receipts[1].Name != "PYTHON_B" {
		t.Fatalf("commands=%v receipts=%+v", commands, receipts)
	}
	wantPythonArguments := []string{"-B", "-I", "scanner-b.py", "--input", "-", "--expected-bytes", fmt.Sprintf("%d", len(raw))}
	if !reflect.DeepEqual(pythonArguments, wantPythonArguments) {
		t.Fatalf("Python scanner arguments=%v want=%v", pythonArguments, wantPythonArguments)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("private scanner input retained: %v", entries)
	}
}

func TestRunPrivacyScannersFailsClosedForEveryScannerHealthDefect(t *testing.T) {
	qualified := qualifiedRun{scannerADigest: strings.Repeat("1", 64), scannerBDigest: strings.Repeat("2", 64)}
	raw, records, _ := marshalPrivacyObservationStream([]privacyObservation{
		{source: "ANDROID_LOGCAT", data: []byte("safe")}, {source: "REMOTE_JOURNAL", data: []byte("safe")},
	})
	digest := sha256Hex(raw)
	validReceipt := func(name string) scannerWireReceipt {
		return scannerWireReceipt{Schema: scannera.ReceiptSchema, Name: name, InputSHA256: digest,
			BytesConsumed: uint64(len(raw)), RecordsConsumed: records, Result: "PASS"}
	}
	for name, mutate := range map[string]func(*scannerWireReceipt) []byte{
		"output corruption": func(*scannerWireReceipt) []byte { return []byte("not-json") },
		"partial read": func(value *scannerWireReceipt) []byte {
			value.BytesConsumed--
			encoded, _ := json.Marshal(value)
			return encoded
		},
		"false PASS": func(value *scannerWireReceipt) []byte {
			value.Privacy.CredentialRetained = true
			encoded, _ := json.Marshal(value)
			return encoded
		},
		"false FAIL": func(value *scannerWireReceipt) []byte {
			value.Result = "FAIL"
			encoded, _ := json.Marshal(value)
			return encoded
		},
		"backpressure receipt": func(value *scannerWireReceipt) []byte {
			value.BackpressureFailure = true
			encoded, _ := json.Marshal(value)
			return encoded
		},
		"truncated receipt": func(value *scannerWireReceipt) []byte {
			value.Truncated = true
			encoded, _ := json.Marshal(value)
			return encoded
		},
		"coverage gap": func(value *scannerWireReceipt) []byte {
			value.CoverageGap = true
			encoded, _ := json.Marshal(value)
			return encoded
		},
	} {
		t.Run(name, func(t *testing.T) {
			runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, process string, _ ...string) ([]byte, error) {
				receiptName := "GO_A"
				if process == "python" {
					receiptName = "PYTHON_B"
				}
				receipt := validReceipt(receiptName)
				if process == "python" {
					return mutate(&receipt), nil
				}
				return json.Marshal(receipt)
			}}
			value := config{scannerAPath: "scanner-a", scannerBPath: "scanner-b.py", pythonPath: "python"}
			if _, err := runPrivacyScanners(context.Background(), runner, value, qualified, ".", raw, records); err == nil {
				t.Fatal("scanner health defect accepted")
			}
		})
	}
}

func TestRunPrivacyScannersTimesOutAStalledScanner(t *testing.T) {
	qualified := qualifiedRun{scannerADigest: strings.Repeat("1", 64), scannerBDigest: strings.Repeat("2", 64)}
	raw, records, _ := marshalPrivacyObservationStream([]privacyObservation{
		{source: "ANDROID_LOGCAT", data: []byte("safe")}, {source: "REMOTE_JOURNAL", data: []byte("safe")},
	})
	runner := commandRunner{runFunc: func(ctx context.Context, _ []byte, _ string, _ string, _ ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	value := config{scannerAPath: "scanner-a", scannerBPath: "scanner-b.py", pythonPath: "python"}
	if _, err := runPrivacyScanners(ctx, runner, value, qualified, ".", raw, records); err == nil {
		t.Fatalf("stalled scanner was not rejected: %v", err)
	}
}

func containsArguments(arguments []string, stdinMarker string, expectedBytes int) bool {
	wantBytes := fmt.Sprint(expectedBytes)
	hasStdin, hasLength := false, false
	for index, argument := range arguments {
		if argument == stdinMarker {
			hasStdin = true
		}
		if index > 0 && (arguments[index-1] == "-expected-bytes" || arguments[index-1] == "--expected-bytes") && argument == wantBytes {
			hasLength = true
		}
	}
	return hasStdin && hasLength
}

func TestRunPrivacyScannersFailsClosedOnDisagreement(t *testing.T) {
	root := t.TempDir()
	value := config{evidenceRoot: root, scannerAPath: "scanner-a", scannerBPath: "scanner-b.py", pythonPath: "python"}
	qualified := qualifiedRun{scannerADigest: strings.Repeat("1", 64), scannerBDigest: strings.Repeat("2", 64)}
	raw, records, err := marshalPrivacyObservationStream([]privacyObservation{
		{source: "ANDROID_LOGCAT", data: []byte("safe")}, {source: "REMOTE_JOURNAL", data: []byte("safe")},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Hex(raw)
	runner := commandRunner{runFunc: func(_ context.Context, _ []byte, _ string, name string, _ ...string) ([]byte, error) {
		receipt := scannerWireReceipt{Schema: scannera.ReceiptSchema, Name: "GO_A", InputSHA256: digest, BytesConsumed: uint64(len(raw)), RecordsConsumed: records, Result: "PASS"}
		if name == "python" {
			receipt.Name = "PYTHON_B"
			receipt.Result = "FAIL"
			receipt.Privacy.ProfileRetained = true
		}
		return json.Marshal(receipt)
	}}
	if _, err := runPrivacyScanners(context.Background(), runner, value, qualified, root, raw, records); err == nil {
		t.Fatal("scanner disagreement accepted")
	}
}

func TestRunPrivacyScannersTreatsChildFailureAsHarnessFailureWithoutRetainingInput(t *testing.T) {
	root := t.TempDir()
	value := config{evidenceRoot: root, scannerAPath: "scanner-a", scannerBPath: "scanner-b.py", pythonPath: "python"}
	qualified := qualifiedRun{scannerADigest: strings.Repeat("1", 64), scannerBDigest: strings.Repeat("2", 64)}
	raw, records, _ := marshalPrivacyObservationStream([]privacyObservation{
		{source: "ANDROID_LOGCAT", data: []byte("safe")}, {source: "REMOTE_JOURNAL", data: []byte("safe")},
	})
	runner := commandRunner{runFunc: func(context.Context, []byte, string, string, ...string) ([]byte, error) {
		return nil, errors.New("synthetic child failure")
	}}
	if _, err := runPrivacyScanners(context.Background(), runner, value, qualified, root, raw, records); err == nil {
		t.Fatal("scanner child failure accepted")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("private scanner input retained after failure: %v", entries)
	}
}
