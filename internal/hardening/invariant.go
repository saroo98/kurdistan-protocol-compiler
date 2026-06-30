// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hardening

import (
	"context"
	"fmt"

	"kurdistan/internal/adapter"
	"kurdistan/internal/bytetransport"
	"kurdistan/internal/compiler"
	"kurdistan/internal/fixtures"
	"kurdistan/internal/framing"
	"kurdistan/internal/hostdetect"
	"kurdistan/internal/ir"
	"kurdistan/internal/localadapter"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/proxysem"
	kstream "kurdistan/internal/stream"
	"kurdistan/internal/wireeval"
	"kurdistan/internal/wirefeatures"
	"kurdistan/internal/wiregen"
	"kurdistan/internal/wiregencompare"
)

func RunInvariantRegistry(profiles []*ir.Profile) []CheckResult {
	p := firstProfile(profiles)
	results := []CheckResult{}
	results = append(results, check("generated_profiles_validate", CategoryInvariants, func() error {
		for _, p := range profiles {
			if err := ir.Validate(p); err != nil {
				return err
			}
		}
		return nil
	}))
	results = append(results, check("profile_id_stable_for_seed", CategoryInvariants, func() error {
		a, err := compiler.Generate(44)
		if err != nil {
			return err
		}
		b, err := compiler.Generate(44)
		if err != nil {
			return err
		}
		if a.ID != b.ID || a.GenerationHash != b.GenerationHash {
			return fmt.Errorf("seed not stable")
		}
		return nil
	}))
	results = append(results, check("profile_hash_changes_on_policy_change", CategoryInvariants, func() error {
		cp := *p
		cp.GenerationHash = ""
		cp.Scheduler.Mode = "mutated_mode"
		hash, err := ir.CanonicalHash(&cp)
		if err != nil {
			return err
		}
		if hash == p.GenerationHash {
			return fmt.Errorf("hash did not change")
		}
		return nil
	}))
	results = append(results, check("semantic_mappings_unique_and_present", CategoryInvariants, func() error {
		seen := map[string]bool{}
		for _, msg := range p.Messages {
			if msg.Semantic == "" || msg.WireSymbol == "" {
				return fmt.Errorf("empty semantic mapping")
			}
			if seen[msg.WireSymbol] {
				return fmt.Errorf("duplicate wire symbol")
			}
			seen[msg.WireSymbol] = true
		}
		return nil
	}))
	results = append(results, check("unsupported_policy_rejected", CategoryInvariants, func() error {
		cp := *p
		cp.GenerationHash = ""
		cp.FrameGrammar.LengthMode = "unsupported"
		if err := ir.Validate(&cp); err == nil {
			return fmt.Errorf("unsupported policy accepted")
		}
		return nil
	}))
	results = append(results, check("frame_round_trip_and_cross_profile_reject", CategoryInvariants, func() error {
		frames, err := framing.EncodeOperation(p, framing.Operation{Semantic: ir.SemanticData, StreamID: 1, Payload: []byte("hardening")}, p.Seed)
		if err != nil {
			return err
		}
		op, _, err := framing.DecodeFrames(p, frames)
		if err != nil {
			return err
		}
		if string(op.Payload) != "hardening" {
			return fmt.Errorf("frame round trip mismatch")
		}
		if len(profiles) > 1 {
			if other := profiles[1]; other != nil && other.ID != p.ID {
				if op2, _, err := framing.DecodeFrames(other, frames); err == nil && op2.Semantic == op.Semantic && string(op2.Payload) == string(op.Payload) {
					return fmt.Errorf("cross-profile frame silently equivalent")
				}
			}
		}
		return nil
	}))
	results = append(results, check("stream_limits_and_terminal_writes_rejected", CategoryInvariants, func() error {
		s, err := kstream.NewSession(kstream.Config{MaxConcurrentStreams: 1, InitialStreamWindowBytes: 8, InitialSessionWindowBytes: 8})
		if err != nil {
			return err
		}
		id, err := s.OpenStream("interactive")
		if err != nil {
			return err
		}
		if _, err := s.OpenStream("bulk"); err == nil {
			return fmt.Errorf("max stream limit ignored")
		}
		if _, err := s.WriteData(id, make([]byte, 9)); err == nil {
			return fmt.Errorf("backpressure not surfaced")
		}
		if err := s.Reset(id, "test"); err != nil {
			return err
		}
		if _, err := s.WriteData(id, []byte("x")); err == nil {
			return fmt.Errorf("reset stream accepted write")
		}
		return nil
	}))
	results = append(results, check("proxy_unknown_target_rejected", CategoryInvariants, func() error {
		if err := proxysem.DefaultRegistry().Validate(proxysem.TargetDescriptor{Class: "unknown"}); err == nil {
			return fmt.Errorf("unknown target accepted")
		}
		return nil
	}))
	results = append(results, check("adapter_config_lifecycle_and_hygiene", CategoryInvariants, func() error {
		cfg := adapter.DefaultConfig("adapter-hardening", adapter.AdapterKindIngress)
		cfg.MaxFlows = min(3, p.Stream.MaxConcurrentStreams)
		if err := adapter.ValidateConfig(cfg); err != nil {
			return err
		}
		if err := adapter.RequireCapabilities(p.AdapterPolicy.RequiredCapabilities, cfg.Capabilities); err != nil {
			return err
		}
		desc := adapter.FlowDescriptor{ID: "hardening-flow", Class: "synthetic", Direction: "bidirectional", RequestClass: "interactive", PriorityClass: "interactive", MaxReadBytes: 1024, MaxWriteBytes: 1024, MetadataPolicy: "bucketed"}
		flow, err := adapter.NewFlow(desc)
		if err != nil {
			return err
		}
		if err := flow.Open(adapter.DefaultCapabilities()); err != nil {
			return err
		}
		if err := flow.Reset(adapter.DefaultCapabilities(), "hardening"); err != nil {
			return err
		}
		if err := flow.RecordWrite(1); err == nil {
			return fmt.Errorf("adapter write after reset accepted")
		}
		return nil
	}))
	results = append(results, check("local_adapter_runtime_scenario_hygiene", CategoryInvariants, func() error {
		cfg := localadapter.DefaultConfig("local-hardening")
		cfg.MaxFlows = min(3, p.AdapterPolicy.MaxFlows)
		result, err := localadapter.RunScenario(context.Background(), p, localadapter.DefaultScenario(localadapter.ScenarioSingleFlowEcho), cfg)
		if err != nil {
			return err
		}
		if !result.Summary.Completed {
			return fmt.Errorf("local adapter scenario did not complete")
		}
		if result.Summary.PayloadLogged || result.Summary.SecretLogged {
			return fmt.Errorf("local adapter summary reported payload/secret logging")
		}
		return nil
	}))
	results = append(results, check("byte_transport_encode_decode_and_hygiene", CategoryInvariants, func() error {
		cfg := bytetransport.DefaultConfig("byte-hardening")
		frame := bytetransport.ByteFrame{SessionID: cfg.RuntimeID, StreamID: 1, Sequence: 1, Kind: bytetransport.FrameData, ByteCount: 64, FragmentCount: 1, MetadataClass: "hardening"}
		encoded, err := bytetransport.EncodeFrame(cfg, frame)
		if err != nil {
			return err
		}
		decoded, err := bytetransport.DecodeFrameBytes(cfg, encoded.Bytes)
		if err != nil {
			return err
		}
		if decoded.Frame.Kind != frame.Kind || decoded.Frame.ByteCount != frame.ByteCount {
			return fmt.Errorf("byte frame round trip mismatch")
		}
		result, err := bytetransport.RunScenario(context.Background(), p, bytetransport.DefaultScenario(bytetransport.ScenarioSingleFlow), cfg)
		if err != nil {
			return err
		}
		if result.Summary.PayloadLogged || result.Summary.SecretLogged {
			return fmt.Errorf("byte transport summary reported payload/secret logging")
		}
		return nil
	}))
	results = append(results, check("bytepath_fixture_manifest_validates", CategoryInvariants, func() error {
		manifest, err := fixtures.GenerateBytePathManifest(context.Background(), fixtures.ManifestOptions{
			ProfileSeeds:   []int{int(p.Seed)},
			ScenarioNames:  []string{bytetransport.ScenarioSingleFlow},
			BackendVersion: Version,
		})
		if err != nil {
			return err
		}
		if len(manifest.Entries) != 1 {
			return fmt.Errorf("unexpected fixture entries")
		}
		if err := fixtures.ValidateManifest(manifest); err != nil {
			return err
		}
		return nil
	}))
	results = append(results, check("protocol_corpus_and_wirefeatures_validate", CategoryInvariants, func() error {
		corpus := protocorpus.DefaultCorpus()
		if err := protocorpus.ValidateManifest(corpus); err != nil {
			return err
		}
		manifest, err := fixtures.GenerateBytePathManifest(context.Background(), fixtures.ManifestOptions{
			ProfileSeeds:   []int{int(p.Seed)},
			ScenarioNames:  []string{bytetransport.ScenarioSingleFlow},
			BackendVersion: Version,
		})
		if err != nil {
			return err
		}
		vectors, report := wirefeatures.ExtractFromFixtureManifest(manifest)
		if report.Conclusion != "passed" || len(vectors) == 0 {
			return fmt.Errorf("wire feature extraction failed")
		}
		comparison := wirefeatures.CompareToCorpus(vectors, corpus)
		if comparison.CorpusEntries != len(corpus.Entries) || len(comparison.MatchedFamilies) == 0 || comparison.PayloadLogged || comparison.SecretLogged {
			return fmt.Errorf("wire feature corpus comparison failed")
		}
		return nil
	}))
	results = append(results, check("wiregen_policy_and_feature_expectations_validate", CategoryInvariants, func() error {
		corpus := protocorpus.DefaultCorpus()
		policy, err := wiregen.SamplePolicy(p.Seed, corpus)
		if err != nil {
			return err
		}
		if err := wiregen.ValidatePolicy(policy, corpus); err != nil {
			return err
		}
		vector := wiregencompare.ExpectedVector(policy, bytetransport.ScenarioSingleFlow, "interpreted", p.ID)
		comparison := wiregencompare.ComparePoliciesToFeatures([]wiregen.WireShapePolicy{policy}, []wirefeatures.WireFeatureVector{vector})
		if comparison.Conclusion != "passed" || comparison.PayloadLogged || comparison.SecretLogged {
			return fmt.Errorf("wiregen expectation comparison failed")
		}
		return nil
	}))
	results = append(results, check("wireeval_dataset_and_split_validate", CategoryInvariants, func() error {
		dataset, err := wireeval.BuildDataset(context.Background(), protocorpus.DefaultCorpus(), wireeval.BuildOptions{
			Seeds:    wireeval.DefaultSeeds(),
			Controls: true,
		})
		if err != nil {
			return err
		}
		if err := wireeval.ValidateDataset(dataset); err != nil {
			return err
		}
		splits := wireeval.BuildSplitManifest(dataset.Records, wireeval.DefaultSplitMode())
		if !splits.Passed || splits.SplitCounts["train"] == 0 || splits.SplitCounts["test"] == 0 || splits.SplitCounts["ood"] == 0 {
			return fmt.Errorf("wireeval split manifest failed")
		}
		return nil
	}))
	results = append(results, check("hostdetect_observation_controls_validate", CategoryInvariants, func() error {
		summary, err := hostdetect.GenerateGoldenSummary(context.Background())
		if err != nil {
			return err
		}
		if err := hostdetect.ValidateSummary(summary); err != nil {
			return err
		}
		if summary.Detection.ControlHostsFlagged == 0 || !summary.Resistance.ControlCollapseDetected || !summary.Resistance.PaddingOnlyDetected {
			return fmt.Errorf("hostdetect controls not detected")
		}
		return nil
	}))
	return results
}

func check(name, category string, fn func() error) CheckResult {
	if err := fn(); err != nil {
		return fail(name, category, err.Error(), nil)
	}
	return pass(name, category, "checked", nil)
}
