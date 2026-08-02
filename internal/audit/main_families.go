// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"kurdistan/internal/lab/fixtures"
	"kurdistan/internal/observe/byteparity"
	"kurdistan/internal/observe/classifierdata"
	"kurdistan/internal/observe/hostdetect"
	"kurdistan/internal/observe/protocorpus"
	"kurdistan/internal/observe/wireeval"
	"kurdistan/internal/operator/relayfleet"
	"kurdistan/internal/protocol/ir"
)

const (
	familyHardening      = "hardening"
	familyBytePathParity = "bytepath-parity"
	familyWireEvaluation = "wire-evaluation"
	familyHostDetection  = "host-detection"
	familyRelayFleet     = "relay-fleet"
)

type bytePathParityFamilyValue struct {
	Report byteparity.ByteParityReport
	Err    error
}

type wireEvaluationFamilyValue struct {
	Dataset wireeval.Dataset
	CSV     []byte
	JSONL   []byte
	Err     error
}

type hostDetectionFamilyValue struct {
	Summary hostdetect.HostDetectSummary
	Err     error
}

type relayFleetFamilyValue struct {
	Summary    relayfleet.RelayFleetSummary
	Comparison relayfleet.RelayFleetComparisonReport
	Err        error
}

type mainAuditFamilyValues struct {
	Hardening      []GateResult
	BytePathParity bytePathParityFamilyValue
	WireEvaluation wireEvaluationFamilyValue
	HostDetection  hostDetectionFamilyValue
	RelayFleet     relayFleetFamilyValue
}

func runMainAuditFamilies(ctx context.Context, options ExecutorOptions, profiles []*ir.Profile, cfg AuditConfig, corpus protocorpus.CorpusManifest, relayFleetBaselinePath string) (mainAuditFamilyValues, error) {
	if err := validateExecutorOptions(options); err != nil {
		return mainAuditFamilyValues{}, err
	}
	if options.Mode == ExecutorSerial {
		return executeMainAuditFamilies(ctx, options, profiles, cfg, corpus, relayFleetBaselinePath)
	}
	serial, err := executeMainAuditFamilies(ctx, ExecutorOptions{Mode: ExecutorSerial, Workers: 1}, profiles, cfg, corpus, relayFleetBaselinePath)
	if err != nil {
		return mainAuditFamilyValues{}, err
	}
	parallel, err := executeMainAuditFamilies(ctx, options, profiles, cfg, corpus, relayFleetBaselinePath)
	if err != nil {
		return mainAuditFamilyValues{}, err
	}
	if err := canonicalMainAuditFamilyValuesEqual(serial, parallel); err != nil {
		return mainAuditFamilyValues{}, fmt.Errorf("parallel audit shadow mismatch: %w", err)
	}
	return serial, nil
}

func executeMainAuditFamilies(ctx context.Context, options ExecutorOptions, profiles []*ir.Profile, cfg AuditConfig, corpus protocorpus.CorpusManifest, relayFleetBaselinePath string) (mainAuditFamilyValues, error) {
	families := []auditFamily{
		{ID: familyHardening, Run: func(ctx context.Context, _ familyValues) (any, error) {
			gates := HardeningGates(ctx, profiles, cfg)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return gates, nil
		}},
		{ID: familyBytePathParity, Run: func(ctx context.Context, _ familyValues) (any, error) {
			report, err := byteparity.Run(ctx, fixtures.DefaultSeeds(), fixtures.DefaultScenarios())
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			if err != nil {
				report = byteparity.ByteParityReport{Conclusion: "failed", UnexpectedDifferences: []string{err.Error()}}
			}
			return bytePathParityFamilyValue{Report: report, Err: err}, nil
		}},
		{ID: familyWireEvaluation, Run: func(ctx context.Context, _ familyValues) (any, error) {
			dataset, err := wireeval.BuildDataset(ctx, corpus, wireeval.BuildOptions{Seeds: wireeval.DefaultSeeds(), Scenarios: wireeval.DefaultScenarios(), SplitMode: wireeval.DefaultSplitMode(), Controls: true})
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			value := wireEvaluationFamilyValue{Dataset: dataset, Err: err}
			if err == nil {
				value.CSV, _ = classifierdata.ExportCSV(dataset.Records)
				value.JSONL, _ = classifierdata.ExportJSONL(dataset.Records)
			}
			return value, nil
		}},
		{ID: familyHostDetection, Dependencies: []string{familyWireEvaluation}, Run: func(_ context.Context, values familyValues) (any, error) {
			wire, err := familyValue[wireEvaluationFamilyValue](values, familyWireEvaluation)
			if err != nil {
				return nil, err
			}
			value := hostDetectionFamilyValue{Err: wire.Err}
			if wire.Err == nil {
				value.Summary, value.Err = hostdetect.Run(wire.Dataset, hostdetect.DefaultBuildOptions())
			}
			return value, nil
		}},
		{ID: familyRelayFleet, Dependencies: []string{familyWireEvaluation, familyHostDetection}, Run: func(ctx context.Context, values familyValues) (any, error) {
			wire, err := familyValue[wireEvaluationFamilyValue](values, familyWireEvaluation)
			if err != nil {
				return nil, err
			}
			host, err := familyValue[hostDetectionFamilyValue](values, familyHostDetection)
			if err != nil {
				return nil, err
			}
			value := relayFleetFamilyValue{
				Comparison: relayfleet.RelayFleetComparisonReport{Version: string(relayfleet.Version), Conclusion: "failed"},
				Err:        host.Err,
			}
			if host.Err == nil {
				value.Summary, value.Err = relayfleet.Run(wire.Dataset, host.Summary, relayfleet.DefaultOptions())
				value.Comparison, _ = relayfleet.VerifyFleet(ctx, relayFleetBaselinePath)
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return value, nil
		}},
	}
	results, err := executeAuditFamilies(ctx, options, families)
	if err != nil {
		return mainAuditFamilyValues{}, err
	}
	values := make(familyValues, len(results))
	for _, result := range results {
		values[result.ID] = result.Value
	}
	hardening, err := familyValue[[]GateResult](values, familyHardening)
	if err != nil {
		return mainAuditFamilyValues{}, err
	}
	bytePathParity, err := familyValue[bytePathParityFamilyValue](values, familyBytePathParity)
	if err != nil {
		return mainAuditFamilyValues{}, err
	}
	wireEvaluation, err := familyValue[wireEvaluationFamilyValue](values, familyWireEvaluation)
	if err != nil {
		return mainAuditFamilyValues{}, err
	}
	hostDetection, err := familyValue[hostDetectionFamilyValue](values, familyHostDetection)
	if err != nil {
		return mainAuditFamilyValues{}, err
	}
	relayFleetValue, err := familyValue[relayFleetFamilyValue](values, familyRelayFleet)
	if err != nil {
		return mainAuditFamilyValues{}, err
	}
	return mainAuditFamilyValues{
		Hardening:      hardening,
		BytePathParity: bytePathParity,
		WireEvaluation: wireEvaluation,
		HostDetection:  hostDetection,
		RelayFleet:     relayFleetValue,
	}, nil
}

func canonicalMainAuditFamilyValuesEqual(left, right mainAuditFamilyValues) error {
	leftRaw, err := canonicalMainAuditFamilyValuesJSON(left)
	if err != nil {
		return err
	}
	rightRaw, err := canonicalMainAuditFamilyValuesJSON(right)
	if err != nil {
		return err
	}
	if !bytes.Equal(leftRaw, rightRaw) {
		return fmt.Errorf("canonical audit family results differ")
	}
	return nil
}

func canonicalMainAuditFamilyValuesJSON(values mainAuditFamilyValues) ([]byte, error) {
	errors := map[string]string{}
	if values.BytePathParity.Err != nil {
		errors[familyBytePathParity] = values.BytePathParity.Err.Error()
	}
	if values.WireEvaluation.Err != nil {
		errors[familyWireEvaluation] = values.WireEvaluation.Err.Error()
	}
	if values.HostDetection.Err != nil {
		errors[familyHostDetection] = values.HostDetection.Err.Error()
	}
	if values.RelayFleet.Err != nil {
		errors[familyRelayFleet] = values.RelayFleet.Err.Error()
	}
	values.BytePathParity.Err = nil
	values.WireEvaluation.Err = nil
	values.HostDetection.Err = nil
	values.RelayFleet.Err = nil
	return json.Marshal(struct {
		Values mainAuditFamilyValues `json:"values"`
		Errors map[string]string     `json:"errors,omitempty"`
	}{Values: values, Errors: errors})
}

func familyValue[T any](values familyValues, id string) (T, error) {
	var zero T
	raw, ok := values[id]
	if !ok {
		return zero, fmt.Errorf("missing audit family value %q", id)
	}
	value, ok := raw.(T)
	if !ok {
		return zero, fmt.Errorf("audit family %q returned an unexpected value type", id)
	}
	return value, nil
}
