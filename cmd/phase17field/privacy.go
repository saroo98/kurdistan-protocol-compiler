// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"

	"kurdistan/internal/assurance"
	"kurdistan/internal/phase17evidence"
	"kurdistan/internal/phase17privacy/scannera"
)

type privacyObservation struct {
	source string
	data   []byte
}

type privacyObservationWire struct {
	Source string `json:"source"`
	Data   string `json:"data"`
}

type scannerWireReceipt struct {
	Schema              string                         `json:"schema"`
	Name                string                         `json:"name"`
	InputSHA256         string                         `json:"inputSha256"`
	BytesConsumed       uint64                         `json:"bytesConsumed"`
	RecordsConsumed     uint64                         `json:"recordsConsumed"`
	Result              string                         `json:"result"`
	Truncated           bool                           `json:"truncated"`
	ParseFailure        bool                           `json:"parseFailure"`
	BackpressureFailure bool                           `json:"backpressureFailure"`
	CoverageGap         bool                           `json:"coverageGap"`
	Privacy             phase17evidence.FieldPrivacyV3 `json:"privacy"`
}

func marshalPrivacyObservationStream(values []privacyObservation) ([]byte, uint64, error) {
	if len(values) == 0 || len(values) > scannera.MaximumRecords {
		return nil, 0, errors.New("privacy observation inventory rejected")
	}
	var output bytes.Buffer
	seen := map[string]bool{"ANDROID_LOGCAT": false, "REMOTE_JOURNAL": false}
	for _, value := range values {
		if _, found := seen[value.source]; !found || len(value.data) > 8<<20 {
			return nil, 0, errors.New("privacy observation rejected")
		}
		wire := privacyObservationWire{Source: value.source, Data: base64.StdEncoding.EncodeToString(value.data)}
		raw, err := json.Marshal(wire)
		if err != nil {
			return nil, 0, err
		}
		if output.Len()+len(raw)+1 > scannera.MaximumBytes {
			return nil, 0, errors.New("privacy observation stream exceeds limit")
		}
		output.Write(raw)
		output.WriteByte('\n')
		seen[value.source] = true
	}
	if !seen["ANDROID_LOGCAT"] || !seen["REMOTE_JOURNAL"] {
		return nil, 0, errors.New("privacy observation coverage incomplete")
	}
	return output.Bytes(), uint64(len(values)), nil
}

func runPrivacyScanners(
	ctx context.Context,
	runner commandRunner,
	value config,
	qualified qualifiedRun,
	root string,
	raw []byte,
	records uint64,
) (receipts []phase17evidence.FieldScannerV3, resultErr error) {
	if len(raw) == 0 || len(raw) > scannera.MaximumBytes || records == 0 || qualified.scannerADigest == qualified.scannerBDigest {
		return nil, errors.New("privacy scanner inputs rejected")
	}
	inputDigest := sha256Hex(raw)
	commands := []struct {
		name     string
		identity string
		command  string
		args     []string
	}{
		{name: "GO_A", identity: qualified.scannerADigest, command: value.scannerAPath, args: []string{"-input", "-", "-expected-bytes", strconv.Itoa(len(raw))}},
		{name: "PYTHON_B", identity: qualified.scannerBDigest, command: value.pythonPath, args: []string{"-B", "-I", value.scannerBPath, "--input", "-", "--expected-bytes", strconv.Itoa(len(raw))}},
	}
	type execution struct {
		index  int
		output []byte
		err    error
	}
	executions := make(chan execution, len(commands))
	childContext, cancel := context.WithCancel(ctx)
	defer cancel()
	var group sync.WaitGroup
	for index, command := range commands {
		group.Add(1)
		go func(index int, command struct {
			name     string
			identity string
			command  string
			args     []string
		}) {
			defer group.Done()
			input := bytes.Clone(raw)
			defer clear(input)
			output, err := runBytesWithLimit(childContext, runner, input, root, 2*time.Minute, 1<<20, command.command, command.args...)
			if err != nil {
				cancel()
			}
			executions <- execution{index: index, output: output, err: err}
		}(index, command)
	}
	group.Wait()
	close(executions)
	ordered := make([]execution, len(commands))
	for execution := range executions {
		ordered[execution.index] = execution
	}
	result := make([]phase17evidence.FieldScannerV3, 0, len(commands))
	for index, command := range commands {
		execution := ordered[index]
		if execution.err != nil {
			return nil, errors.New("privacy scanner process failed")
		}
		var receipt scannerWireReceipt
		if err := assurance.DecodeStrict(bytes.NewReader(execution.output), &receipt); err != nil {
			return nil, errors.New("privacy scanner receipt rejected")
		}
		if receipt.Schema != scannera.ReceiptSchema || receipt.Name != command.name || receipt.InputSHA256 != inputDigest ||
			receipt.BytesConsumed != uint64(len(raw)) || receipt.RecordsConsumed != records {
			return nil, errors.New("privacy scanner parity rejected")
		}
		result = append(result, phase17evidence.FieldScannerV3{
			Name: receipt.Name, IdentitySHA256: command.identity, InputSHA256: receipt.InputSHA256,
			BytesConsumed: receipt.BytesConsumed, RecordsConsumed: receipt.RecordsConsumed, Result: receipt.Result,
			Truncated: receipt.Truncated, ParseFailure: receipt.ParseFailure,
			BackpressureFailure: receipt.BackpressureFailure, CoverageGap: receipt.CoverageGap, Privacy: receipt.Privacy,
		})
	}
	if len(result) != 2 || result[0].Result != "PASS" || result[1].Result != "PASS" ||
		result[0].InputSHA256 != result[1].InputSHA256 || result[0].BytesConsumed != result[1].BytesConsumed ||
		result[0].RecordsConsumed != result[1].RecordsConsumed || result[0].Privacy != (phase17evidence.FieldPrivacyV3{}) ||
		result[1].Privacy != (phase17evidence.FieldPrivacyV3{}) || !scannerReceiptHealthy(result[0]) || !scannerReceiptHealthy(result[1]) {
		return result, errors.New("privacy scanners did not independently pass")
	}
	return result, nil
}

func scannerReceiptHealthy(value phase17evidence.FieldScannerV3) bool {
	return !value.Truncated && !value.ParseFailure && !value.BackpressureFailure && !value.CoverageGap
}

func sha256Hex(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
