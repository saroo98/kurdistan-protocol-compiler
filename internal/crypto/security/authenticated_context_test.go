// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"sort"
	"testing"

	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

func TestContextHashV1IndependentCanonicalSchemaAndCapabilityVector(t *testing.T) {
	p, err := compiler.Generate(6230)
	if err != nil {
		t.Fatal(err)
	}
	p.Security.TranscriptMode = TranscriptFullBindingV1
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	selected := []string{"multi_stream", "replay_window"}
	policy, err := ir.BuildEffectiveSecurityPolicy(p, selected[:1], selected[:1], selected)
	if err != nil {
		t.Fatal(err)
	}
	profileRaw, err := hex.DecodeString(policy.ProfileHash)
	if err != nil {
		t.Fatal(err)
	}
	var profileHash [32]byte
	copy(profileHash[:], profileRaw)
	capabilityHash, err := SelectedCapabilityHashV1(selected)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(capabilityHash[:]); got != "276585e9ee21fb1842ef6a21622f762f178b9dbf9f362bb882c9b7376950e711" {
		t.Fatalf("selected compact-JSON capability hash = %s", got)
	}
	policyHash, err := EffectivePolicyHashV1(policy)
	if err != nil {
		t.Fatal(err)
	}
	policyRaw := independentPolicyV1(policy)
	productionPolicyRaw, err := EncodePolicyV1(policy)
	if err != nil || !bytes.Equal(productionPolicyRaw, policyRaw) {
		t.Fatalf("PolicyV1 independent encoding mismatch: %v", err)
	}
	if want := independentContextHash("kurdistan/policy/v1/effective", policyRaw); policyHash != want {
		t.Fatalf("effective policy hash = %x, want %x", policyHash, want)
	}

	compatibility := CompatibilityBlockV1{
		SchemaVersion: p.Compatibility.SchemaVersion, CompilerSecurityVersion: p.Compatibility.CompilerSecurityVersion,
		MinimumRuntimeVersion:   p.Compatibility.MinimumRuntimeVersion,
		SupportedSecuritySuites: []string{ir.SecuritySuiteString()}, RequiredCapabilities: []string{"multi_stream"},
		SupportedCarrierFamilies: []string{p.CarrierPolicy.CarrierFamily},
		SupportedProxyFeatures:   []string{"proxy-a"}, SupportedStreamFeatures: []string{"stream-a"},
		MaxEnvelopeBytes: uint32(p.Compatibility.MaxEnvelopeBytes), MaxStreamCount: uint32(p.Compatibility.MaxStreamCount),
		MaxReplayWindow: uint32(p.Compatibility.MaxReplayWindow),
	}
	compatibilityRaw := independentCompatibilityBlock(compatibility)
	gotCompatibilityRaw, err := CanonicalCompatibilityBlockV1(compatibility)
	if err != nil || !bytes.Equal(gotCompatibilityRaw, compatibilityRaw) {
		t.Fatalf("compatibility canonical mismatch: %v", err)
	}
	compatibilityHash, _ := CompatibilityBlockHashV1(compatibility)
	if want := independentContextHash("kurdistan/context/v1/compatibility-block", compatibilityRaw); compatibilityHash != want {
		t.Fatalf("compatibility hash mismatch")
	}

	limits := LimitBlockV1{
		MaxFrameBytes: uint32(p.Limits.MaxFrameBytes), MaxPayloadBytes: uint32(p.Limits.MaxPayloadBytes),
		MaxStates: uint32(p.Limits.MaxStates), MaxTransitions: uint32(p.Limits.MaxTransitions),
		MaxSessionMillis: uint64(p.Limits.MaxSessionMillis), CarrierMaxEnvelopeBytes: uint32(p.CarrierPolicy.MaxEnvelopeBytes),
		CarrierMaxQueueDepth: uint32(p.CarrierPolicy.MaxCarrierQueueDepth), SessionMaxConcurrentStreams: uint32(p.Stream.MaxConcurrentStreams),
	}
	limitRaw := independentLimitBlock(limits)
	gotLimitRaw, err := CanonicalLimitBlockV1(limits)
	if err != nil || !bytes.Equal(gotLimitRaw, limitRaw) {
		t.Fatalf("limit canonical mismatch: %v", err)
	}
	limitHash, _ := LimitBlockHashV1(limits)
	if want := independentContextHash("kurdistan/context/v1/limit-block", limitRaw); limitHash != want {
		t.Fatalf("limit hash mismatch")
	}

	suite := SelectedSuiteV1{KDFSuite: policy.KDFSuite, AEADSuite: policy.AEADSuite, MACSuite: policy.MACSuite}
	suiteRaw := independentSelectedSuite(suite)
	gotSuiteRaw, err := CanonicalSelectedSuiteV1(suite)
	if err != nil || !bytes.Equal(gotSuiteRaw, suiteRaw) {
		t.Fatalf("selected suite canonical mismatch: %v", err)
	}
	config := ConfigSourceBlockV1{
		ProfileID: policy.ProfileID, ProfileHash: profileHash, SecurityVersion: policy.SecurityVersion,
		SelectedSuite: suite, EffectivePolicyHash: policyHash, SelectedCapabilityHash: capabilityHash,
		AdapterClass: p.AdapterPolicy.RuntimeMappingPolicy, CompatibilityBlockHash: compatibilityHash, LimitBlockHash: limitHash,
	}
	configRaw := independentConfigSourceBlock(config)
	gotConfigRaw, err := CanonicalConfigSourceBlockV1(config)
	if err != nil || !bytes.Equal(gotConfigRaw, configRaw) {
		t.Fatalf("config canonical mismatch: %v", err)
	}
	configHash, _ := ConfigSourceBlockHashV1(config)
	if want := independentContextHash("kurdistan/context/v1/config-source-block", configRaw); configHash != want {
		t.Fatalf("config hash mismatch")
	}

	binding := HandshakeModeBinding{
		ClientOptional: []string{"client-a"}, ServerOptional: []string{"server-a"},
		FeatureVectors: []string{"carrier:a", "proxy:a", "stream:a"}, CarrierFamily: p.CarrierPolicy.CarrierFamily,
		CarrierPolicyHash: testHash32(1), EnvelopeLimit: limits.CarrierMaxEnvelopeBytes, MaxFrameBytes: limits.MaxFrameBytes,
		LocalAdapterClass: p.AdapterPolicy.RuntimeMappingPolicy, FramingPolicyHash: testHash32(2),
		StateMachinePolicyHash: testHash32(3), SchedulerPolicyHash: testHash32(4), PaddingPolicyHash: testHash32(5),
		StreamPolicyHash: testHash32(6), ProxyPolicyHash: testHash32(7), CarrierContextHash: testHash32(8),
		CompatibilityBlock: compatibility, CompatibilityBlockHash: compatibilityHash,
		LimitBlock: limits, LimitBlockHash: limitHash, ConfigSourceBlock: config, ConfigSourceBlockHash: configHash,
	}
	modeRaw := independentAuthenticatedModeBinding(TranscriptFullBindingV1, binding)
	gotModeRaw, err := CanonicalAuthenticatedModeBindingV1(TranscriptFullBindingV1, binding)
	if err != nil || !bytes.Equal(gotModeRaw, modeRaw) {
		t.Fatalf("authenticated mode canonical mismatch: %v", err)
	}
	transcript := testHash32(20)
	input := AuthenticatedContextHashInputV1{
		EffectivePolicy: policy, EffectivePolicyHash: policyHash, TranscriptHash: transcript, SelectedSuite: suite,
		SelectedCapabilityHash: capabilityHash, ClientProfileHash: profileHash, ServerProfileHash: profileHash,
		ClientModeBinding: binding, ServerModeBinding: binding.Clone(),
	}
	gotContext, err := ContextHashV1(input)
	if err != nil {
		t.Fatal(err)
	}
	var version [2]byte
	binary.BigEndian.PutUint16(version[:], 1)
	wantContext := independentContextHash("kurdistan/context/v1/authenticated",
		version[:], policyRaw, policyHash[:], transcript[:], suiteRaw, capabilityHash[:], profileHash[:], profileHash[:],
		compatibilityRaw, compatibilityHash[:], compatibilityRaw, compatibilityHash[:],
		limitRaw, limitHash[:], limitRaw, limitHash[:], configRaw, configHash[:], configRaw, configHash[:], modeRaw, modeRaw)
	if gotContext != wantContext {
		t.Fatalf("context hash = %x, want %x", gotContext, wantContext)
	}
}

func TestContextRangeAndNoncanonicalListsReject(t *testing.T) {
	base := CompatibilityBlockV1{
		SchemaVersion: "schema", CompilerSecurityVersion: "compiler", MinimumRuntimeVersion: "runtime",
		SupportedSecuritySuites: []string{"suite-a", "suite-b"}, RequiredCapabilities: []string{"cap-a"},
		SupportedCarrierFamilies: []string{"carrier-a"}, MaxEnvelopeBytes: 1, MaxStreamCount: 1, MaxReplayWindow: 1,
	}
	for name, values := range map[string][]string{
		"unsorted":  {"suite-b", "suite-a"},
		"duplicate": {"suite-a", "suite-a"},
	} {
		t.Run(name, func(t *testing.T) {
			value := base.Clone()
			value.SupportedSecuritySuites = values
			if _, err := CanonicalCompatibilityBlockV1(value); err == nil {
				t.Fatal("noncanonical list accepted")
			}
		})
	}
	if _, err := CanonicalLimitBlockV1(LimitBlockV1{MaxFrameBytes: 1}); err == nil {
		t.Fatal("zero retained ranges accepted")
	}
	if _, err := SelectedCapabilityHashV1([]string{"replay_window", "multi_stream"}); err == nil {
		t.Fatal("unsorted selected capabilities accepted")
	}
	if _, err := SelectedCapabilityHashV1([]string{"multi_stream", "multi_stream"}); err == nil {
		t.Fatal("duplicate selected capabilities accepted")
	}
	if _, err := SelectedCapabilityHashV1([]string{"not-known"}); err == nil {
		t.Fatal("unknown selected capability accepted")
	}
}

func TestContextSourceContradictoryDuplicatesRejectIndependently(t *testing.T) {
	fixture := newContextTestFixture(t)
	for _, role := range []string{"client", "server"} {
		role := role
		t.Run(role+" profile hash versus PolicyV1", func(t *testing.T) {
			input := cloneContextHashInput(fixture.input)
			if role == "client" {
				input.ClientProfileHash[0] ^= 1
			} else {
				input.ServerProfileHash[0] ^= 1
			}
			assertContextRejects(t, input)
		})
		for _, tt := range []struct {
			name   string
			mutate func(*HandshakeModeBinding)
		}{
			{"config profile hash", func(v *HandshakeModeBinding) {
				v.ConfigSourceBlock.ProfileHash[0] ^= 1
				recomputeConfigSourceHash(t, v)
			}},
			{"envelope versus retained limit", func(v *HandshakeModeBinding) { v.EnvelopeLimit-- }},
			{"retained envelope versus envelope", func(v *HandshakeModeBinding) {
				v.LimitBlock.CarrierMaxEnvelopeBytes--
				recomputeBindingHashes(t, v)
			}},
			{"frame versus retained limit", func(v *HandshakeModeBinding) { v.MaxFrameBytes++ }},
			{"retained frame versus frame", func(v *HandshakeModeBinding) {
				v.LimitBlock.MaxFrameBytes++
				recomputeBindingHashes(t, v)
			}},
			{"adapter versus config adapter", func(v *HandshakeModeBinding) { v.LocalAdapterClass = alternateAdapter(v.LocalAdapterClass) }},
			{"config adapter versus adapter", func(v *HandshakeModeBinding) {
				v.ConfigSourceBlock.AdapterClass = alternateAdapter(v.LocalAdapterClass)
				recomputeConfigSourceHash(t, v)
			}},
			{"schema versus PolicyV1", func(v *HandshakeModeBinding) {
				v.CompatibilityBlock.SchemaVersion += "-other"
				recomputeBindingHashes(t, v)
			}},
			{"compiler version versus PolicyV1", func(v *HandshakeModeBinding) {
				v.CompatibilityBlock.CompilerSecurityVersion += "-other"
				recomputeBindingHashes(t, v)
			}},
			{"runtime version versus PolicyV1", func(v *HandshakeModeBinding) {
				v.CompatibilityBlock.MinimumRuntimeVersion += "-other"
				recomputeBindingHashes(t, v)
			}},
			{"config profile ID", func(v *HandshakeModeBinding) {
				v.ConfigSourceBlock.ProfileID += "-other"
				recomputeConfigSourceHash(t, v)
			}},
			{"config security version", func(v *HandshakeModeBinding) {
				v.ConfigSourceBlock.SecurityVersion += "-other"
				recomputeConfigSourceHash(t, v)
			}},
			{"config KDF suite", func(v *HandshakeModeBinding) {
				v.ConfigSourceBlock.SelectedSuite.KDFSuite += "-other"
				recomputeConfigSourceHash(t, v)
			}},
			{"config AEAD suite", func(v *HandshakeModeBinding) {
				v.ConfigSourceBlock.SelectedSuite.AEADSuite += "-other"
				recomputeConfigSourceHash(t, v)
			}},
			{"config MAC suite", func(v *HandshakeModeBinding) {
				v.ConfigSourceBlock.SelectedSuite.MACSuite += "-other"
				recomputeConfigSourceHash(t, v)
			}},
			{"config effective policy hash", func(v *HandshakeModeBinding) {
				v.ConfigSourceBlock.EffectivePolicyHash[0] ^= 1
				recomputeConfigSourceHash(t, v)
			}},
			{"config capability hash", func(v *HandshakeModeBinding) {
				v.ConfigSourceBlock.SelectedCapabilityHash[0] ^= 1
				recomputeConfigSourceHash(t, v)
			}},
			{"config compatibility hash", func(v *HandshakeModeBinding) {
				v.ConfigSourceBlock.CompatibilityBlockHash[0] ^= 1
				recomputeConfigSourceHash(t, v)
			}},
			{"config limit hash", func(v *HandshakeModeBinding) {
				v.ConfigSourceBlock.LimitBlockHash[0] ^= 1
				recomputeConfigSourceHash(t, v)
			}},
			{"compatibility block hash", func(v *HandshakeModeBinding) { v.CompatibilityBlockHash[0] ^= 1 }},
			{"limit block hash", func(v *HandshakeModeBinding) { v.LimitBlockHash[0] ^= 1 }},
			{"config source block hash", func(v *HandshakeModeBinding) { v.ConfigSourceBlockHash[0] ^= 1 }},
		} {
			t.Run(role+" "+tt.name, func(t *testing.T) {
				input := cloneContextHashInput(fixture.input)
				binding := &input.ClientModeBinding
				if role == "server" {
					binding = &input.ServerModeBinding
				}
				tt.mutate(binding)
				assertContextRejects(t, input)
			})
		}
	}
	for _, tt := range []struct {
		name   string
		mutate func(*AuthenticatedContextHashInputV1)
	}{
		{"effective policy hash", func(v *AuthenticatedContextHashInputV1) { v.EffectivePolicyHash[0] ^= 1 }},
		{"selected suite KDF", func(v *AuthenticatedContextHashInputV1) { v.SelectedSuite.KDFSuite += "-other" }},
		{"selected suite AEAD", func(v *AuthenticatedContextHashInputV1) { v.SelectedSuite.AEADSuite += "-other" }},
		{"selected suite MAC", func(v *AuthenticatedContextHashInputV1) { v.SelectedSuite.MACSuite += "-other" }},
		{"selected capability hash", func(v *AuthenticatedContextHashInputV1) { v.SelectedCapabilityHash[0] ^= 1 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := cloneContextHashInput(fixture.input)
			tt.mutate(&input)
			assertContextRejects(t, input)
		})
	}
}

func TestContextSourceEveryFieldSensitivityAndListRejection(t *testing.T) {
	fixture := newContextTestFixture(t)
	baseCompatibility, _ := CanonicalCompatibilityBlockV1(fixture.compatibility)
	compatibilityMutations := []struct {
		name   string
		mutate func(*CompatibilityBlockV1)
	}{
		{"schema", func(v *CompatibilityBlockV1) { v.SchemaVersion += "-x" }},
		{"compiler", func(v *CompatibilityBlockV1) { v.CompilerSecurityVersion += "-x" }},
		{"runtime", func(v *CompatibilityBlockV1) { v.MinimumRuntimeVersion += "-x" }},
		{"suite content", func(v *CompatibilityBlockV1) { v.SupportedSecuritySuites[0] += "-x" }},
		{"capability content", func(v *CompatibilityBlockV1) { v.RequiredCapabilities[0] += "-x" }},
		{"carrier content", func(v *CompatibilityBlockV1) { v.SupportedCarrierFamilies[0] += "-x" }},
		{"proxy content", func(v *CompatibilityBlockV1) { v.SupportedProxyFeatures[0] += "-x" }},
		{"stream content", func(v *CompatibilityBlockV1) { v.SupportedStreamFeatures[0] += "-x" }},
		{"envelope", func(v *CompatibilityBlockV1) { v.MaxEnvelopeBytes++ }},
		{"stream count", func(v *CompatibilityBlockV1) { v.MaxStreamCount++ }},
		{"replay", func(v *CompatibilityBlockV1) { v.MaxReplayWindow++ }},
	}
	for _, tt := range compatibilityMutations {
		t.Run("compatibility "+tt.name, func(t *testing.T) {
			value := fixture.compatibility.Clone()
			tt.mutate(&value)
			got, err := CanonicalCompatibilityBlockV1(value)
			if err != nil || bytes.Equal(got, baseCompatibility) {
				t.Fatalf("field was not independently sensitive: %v", err)
			}
		})
	}
	for _, list := range []struct {
		name string
		get  func(*CompatibilityBlockV1) *[]string
	}{
		{"suites", func(v *CompatibilityBlockV1) *[]string { return &v.SupportedSecuritySuites }},
		{"capabilities", func(v *CompatibilityBlockV1) *[]string { return &v.RequiredCapabilities }},
		{"carriers", func(v *CompatibilityBlockV1) *[]string { return &v.SupportedCarrierFamilies }},
		{"proxy", func(v *CompatibilityBlockV1) *[]string { return &v.SupportedProxyFeatures }},
		{"stream", func(v *CompatibilityBlockV1) *[]string { return &v.SupportedStreamFeatures }},
	} {
		t.Run("compatibility "+list.name+" cardinality and order", func(t *testing.T) {
			value := fixture.compatibility.Clone()
			values := list.get(&value)
			*values = append(*values, "zz-added")
			sort.Strings(*values)
			more, err := CanonicalCompatibilityBlockV1(value)
			if err != nil || bytes.Equal(more, baseCompatibility) {
				t.Fatalf("cardinality was not sensitive: %v", err)
			}
			(*values)[0], (*values)[1] = (*values)[1], (*values)[0]
			if _, err := CanonicalCompatibilityBlockV1(value); err == nil {
				t.Fatal("noncanonical order accepted")
			}
		})
	}

	baseLimit, _ := CanonicalLimitBlockV1(fixture.limits)
	for _, tt := range []struct {
		name   string
		mutate func(*LimitBlockV1)
	}{
		{"frame", func(v *LimitBlockV1) { v.MaxFrameBytes++ }},
		{"payload", func(v *LimitBlockV1) { v.MaxPayloadBytes++ }},
		{"states", func(v *LimitBlockV1) { v.MaxStates++ }},
		{"transitions", func(v *LimitBlockV1) { v.MaxTransitions++ }},
		{"session millis", func(v *LimitBlockV1) { v.MaxSessionMillis++ }},
		{"carrier envelope", func(v *LimitBlockV1) { v.CarrierMaxEnvelopeBytes-- }},
		{"carrier queue", func(v *LimitBlockV1) { v.CarrierMaxQueueDepth++ }},
		{"session streams", func(v *LimitBlockV1) { v.SessionMaxConcurrentStreams++ }},
	} {
		t.Run("limit "+tt.name, func(t *testing.T) {
			value := fixture.limits
			tt.mutate(&value)
			got, err := CanonicalLimitBlockV1(value)
			if err != nil || bytes.Equal(got, baseLimit) {
				t.Fatalf("field was not independently sensitive: %v", err)
			}
		})
	}

	baseSuite, _ := CanonicalSelectedSuiteV1(fixture.suite)
	for _, tt := range []struct {
		name   string
		mutate func(*SelectedSuiteV1)
	}{
		{"KDF", func(v *SelectedSuiteV1) { v.KDFSuite += "-x" }},
		{"AEAD", func(v *SelectedSuiteV1) { v.AEADSuite += "-x" }},
		{"MAC", func(v *SelectedSuiteV1) { v.MACSuite += "-x" }},
	} {
		t.Run("suite "+tt.name, func(t *testing.T) {
			value := fixture.suite
			tt.mutate(&value)
			got, err := CanonicalSelectedSuiteV1(value)
			if err != nil || bytes.Equal(got, baseSuite) {
				t.Fatalf("field was not independently sensitive: %v", err)
			}
		})
	}

	baseConfig, _ := CanonicalConfigSourceBlockV1(fixture.config)
	for _, tt := range []struct {
		name   string
		mutate func(*ConfigSourceBlockV1)
	}{
		{"profile ID", func(v *ConfigSourceBlockV1) { v.ProfileID += "-x" }},
		{"profile hash", func(v *ConfigSourceBlockV1) { v.ProfileHash[0] ^= 1 }},
		{"security version", func(v *ConfigSourceBlockV1) { v.SecurityVersion += "-x" }},
		{"KDF", func(v *ConfigSourceBlockV1) { v.SelectedSuite.KDFSuite += "-x" }},
		{"AEAD", func(v *ConfigSourceBlockV1) { v.SelectedSuite.AEADSuite += "-x" }},
		{"MAC", func(v *ConfigSourceBlockV1) { v.SelectedSuite.MACSuite += "-x" }},
		{"policy hash", func(v *ConfigSourceBlockV1) { v.EffectivePolicyHash[0] ^= 1 }},
		{"capability hash", func(v *ConfigSourceBlockV1) { v.SelectedCapabilityHash[0] ^= 1 }},
		{"adapter", func(v *ConfigSourceBlockV1) { v.AdapterClass += "-x" }},
		{"compatibility hash", func(v *ConfigSourceBlockV1) { v.CompatibilityBlockHash[0] ^= 1 }},
		{"limit hash", func(v *ConfigSourceBlockV1) { v.LimitBlockHash[0] ^= 1 }},
	} {
		t.Run("config "+tt.name, func(t *testing.T) {
			value := fixture.config
			tt.mutate(&value)
			got, err := CanonicalConfigSourceBlockV1(value)
			if err != nil || bytes.Equal(got, baseConfig) {
				t.Fatalf("field was not independently sensitive: %v", err)
			}
		})
	}
}

func TestContextHashEveryDisplayedRolePartAndCompleteModeBindingSensitivity(t *testing.T) {
	fixture := newContextTestFixture(t)
	baseHash, err := ContextHashV1(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	baseMode, err := CanonicalAuthenticatedModeBindingV1(fixture.input.EffectivePolicy.TranscriptMode, fixture.binding)
	if err != nil {
		t.Fatal(err)
	}
	otherMode, err := CanonicalAuthenticatedModeBindingV1(TranscriptCanonicalV1, fixture.binding)
	if err != nil || bytes.Equal(otherMode, baseMode) {
		t.Fatalf("transcript mode was not independently sensitive: %v", err)
	}
	for _, tt := range []struct {
		name   string
		mutate func(*HandshakeModeBinding)
	}{
		{"client optional content", func(v *HandshakeModeBinding) { v.ClientOptional[0] += "-x" }},
		{"server optional content", func(v *HandshakeModeBinding) { v.ServerOptional[0] += "-x" }},
		{"feature content", func(v *HandshakeModeBinding) { v.FeatureVectors[0] += "-x" }},
		{"carrier family", func(v *HandshakeModeBinding) { v.CarrierFamily = alternateCarrier(v.CarrierFamily) }},
		{"carrier hash", func(v *HandshakeModeBinding) { v.CarrierPolicyHash[0] ^= 1 }},
		{"envelope limit", func(v *HandshakeModeBinding) {
			v.EnvelopeLimit--
			v.LimitBlock.CarrierMaxEnvelopeBytes = v.EnvelopeLimit
			recomputeBindingHashes(t, v)
		}},
		{"frame limit", func(v *HandshakeModeBinding) {
			v.MaxFrameBytes++
			v.LimitBlock.MaxFrameBytes = v.MaxFrameBytes
			recomputeBindingHashes(t, v)
		}},
		{"adapter", func(v *HandshakeModeBinding) {
			v.LocalAdapterClass = alternateAdapter(v.LocalAdapterClass)
			v.ConfigSourceBlock.AdapterClass = v.LocalAdapterClass
			recomputeConfigSourceHash(t, v)
		}},
		{"framing hash", func(v *HandshakeModeBinding) { v.FramingPolicyHash[0] ^= 1 }},
		{"state hash", func(v *HandshakeModeBinding) { v.StateMachinePolicyHash[0] ^= 1 }},
		{"scheduler hash", func(v *HandshakeModeBinding) { v.SchedulerPolicyHash[0] ^= 1 }},
		{"padding hash", func(v *HandshakeModeBinding) { v.PaddingPolicyHash[0] ^= 1 }},
		{"stream hash", func(v *HandshakeModeBinding) { v.StreamPolicyHash[0] ^= 1 }},
		{"proxy hash", func(v *HandshakeModeBinding) { v.ProxyPolicyHash[0] ^= 1 }},
		{"carrier context hash", func(v *HandshakeModeBinding) { v.CarrierContextHash[0] ^= 1 }},
		{"compatibility block and hash", func(v *HandshakeModeBinding) {
			v.CompatibilityBlock.MaxEnvelopeBytes++
			recomputeBindingHashes(t, v)
		}},
		{"limit block and hash", func(v *HandshakeModeBinding) {
			v.LimitBlock.MaxPayloadBytes++
			recomputeBindingHashes(t, v)
		}},
		{"config block and hash", func(v *HandshakeModeBinding) {
			v.ConfigSourceBlock.ProfileID += "-x"
			recomputeConfigSourceHash(t, v)
		}},
	} {
		t.Run("mode "+tt.name, func(t *testing.T) {
			value := fixture.binding.Clone()
			tt.mutate(&value)
			got, err := CanonicalAuthenticatedModeBindingV1(fixture.input.EffectivePolicy.TranscriptMode, value)
			if err != nil || bytes.Equal(got, baseMode) {
				t.Fatalf("mode field was not independently sensitive: %v", err)
			}
		})
	}
	for _, list := range []struct {
		name string
		get  func(*HandshakeModeBinding) *[]string
	}{
		{"client optional", func(v *HandshakeModeBinding) *[]string { return &v.ClientOptional }},
		{"server optional", func(v *HandshakeModeBinding) *[]string { return &v.ServerOptional }},
		{"features", func(v *HandshakeModeBinding) *[]string { return &v.FeatureVectors }},
	} {
		t.Run("mode "+list.name+" cardinality and order", func(t *testing.T) {
			value := fixture.binding.Clone()
			values := list.get(&value)
			*values = append(*values, "zz-added")
			sort.Strings(*values)
			got, err := CanonicalAuthenticatedModeBindingV1(fixture.input.EffectivePolicy.TranscriptMode, value)
			if err != nil || bytes.Equal(got, baseMode) {
				t.Fatalf("cardinality was not sensitive: %v", err)
			}
			(*values)[0], (*values)[1] = (*values)[1], (*values)[0]
			if _, err := CanonicalAuthenticatedModeBindingV1(fixture.input.EffectivePolicy.TranscriptMode, value); err == nil {
				t.Fatal("noncanonical order accepted")
			}
		})
	}

	for _, role := range []string{"client", "server"} {
		for _, kind := range []string{"mode", "compatibility", "limit"} {
			t.Run(role+" "+kind+" displayed part", func(t *testing.T) {
				input := cloneContextHashInput(fixture.input)
				binding := &input.ClientModeBinding
				if role == "server" {
					binding = &input.ServerModeBinding
				}
				switch kind {
				case "mode":
					binding.FramingPolicyHash[0] ^= 1
				case "compatibility":
					binding.CompatibilityBlock.MaxEnvelopeBytes++
					recomputeBindingHashes(t, binding)
				case "limit":
					binding.LimitBlock.MaxPayloadBytes++
					recomputeBindingHashes(t, binding)
				}
				got, err := ContextHashV1(input)
				if err != nil || got == baseHash {
					t.Fatalf("displayed role part was not sensitive: %v", err)
				}
			})
		}
	}
	for _, tt := range []struct {
		name   string
		mutate func(*AuthenticatedContextHashInputV1)
	}{
		{"TH4", func(v *AuthenticatedContextHashInputV1) { v.TranscriptHash[0] ^= 1 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := cloneContextHashInput(fixture.input)
			tt.mutate(&input)
			got, err := ContextHashV1(input)
			if err != nil || got == baseHash {
				t.Fatalf("displayed context part was not sensitive: %v", err)
			}
		})
	}
}

func TestContextHashEveryDisplayedPartRejectsIndependentContradiction(t *testing.T) {
	fixture := newContextTestFixture(t)
	for _, tt := range []struct {
		name   string
		mutate func(*AuthenticatedContextHashInputV1)
	}{
		{"PolicyV1", func(v *AuthenticatedContextHashInputV1) { v.EffectivePolicy.ReplayWindowSize++ }},
		{"effective policy hash", func(v *AuthenticatedContextHashInputV1) { v.EffectivePolicyHash[0] ^= 1 }},
		{"SelectedSuiteV1", func(v *AuthenticatedContextHashInputV1) { v.SelectedSuite.KDFSuite += "-x" }},
		{"selected capability hash", func(v *AuthenticatedContextHashInputV1) { v.SelectedCapabilityHash[0] ^= 1 }},
		{"client profile hash", func(v *AuthenticatedContextHashInputV1) { v.ClientProfileHash[0] ^= 1 }},
		{"server profile hash", func(v *AuthenticatedContextHashInputV1) { v.ServerProfileHash[0] ^= 1 }},
		{"client compatibility block", func(v *AuthenticatedContextHashInputV1) { v.ClientModeBinding.CompatibilityBlock.MaxEnvelopeBytes++ }},
		{"client compatibility hash", func(v *AuthenticatedContextHashInputV1) { v.ClientModeBinding.CompatibilityBlockHash[0] ^= 1 }},
		{"server compatibility block", func(v *AuthenticatedContextHashInputV1) { v.ServerModeBinding.CompatibilityBlock.MaxEnvelopeBytes++ }},
		{"server compatibility hash", func(v *AuthenticatedContextHashInputV1) { v.ServerModeBinding.CompatibilityBlockHash[0] ^= 1 }},
		{"client limit block", func(v *AuthenticatedContextHashInputV1) { v.ClientModeBinding.LimitBlock.MaxPayloadBytes++ }},
		{"client limit hash", func(v *AuthenticatedContextHashInputV1) { v.ClientModeBinding.LimitBlockHash[0] ^= 1 }},
		{"server limit block", func(v *AuthenticatedContextHashInputV1) { v.ServerModeBinding.LimitBlock.MaxPayloadBytes++ }},
		{"server limit hash", func(v *AuthenticatedContextHashInputV1) { v.ServerModeBinding.LimitBlockHash[0] ^= 1 }},
		{"client config block", func(v *AuthenticatedContextHashInputV1) { v.ClientModeBinding.ConfigSourceBlock.ProfileID += "-x" }},
		{"client config hash", func(v *AuthenticatedContextHashInputV1) { v.ClientModeBinding.ConfigSourceBlockHash[0] ^= 1 }},
		{"server config block", func(v *AuthenticatedContextHashInputV1) { v.ServerModeBinding.ConfigSourceBlock.ProfileID += "-x" }},
		{"server config hash", func(v *AuthenticatedContextHashInputV1) { v.ServerModeBinding.ConfigSourceBlockHash[0] ^= 1 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := cloneContextHashInput(fixture.input)
			tt.mutate(&input)
			assertContextRejects(t, input)
		})
	}
	// U16(1) has no caller-controlled operand; the independent full-context
	// vector above pins it as its own first H part. TH4 and each complete
	// client/server mode part are valid sensitivity cases in the preceding test.
}

func independentCompatibilityBlock(v CompatibilityBlockV1) []byte {
	var out bytes.Buffer
	for _, value := range []string{v.SchemaVersion, v.CompilerSecurityVersion, v.MinimumRuntimeVersion} {
		independentLP(&out, []byte(value))
	}
	for _, values := range [][]string{v.SupportedSecuritySuites, v.RequiredCapabilities, v.SupportedCarrierFamilies, v.SupportedProxyFeatures, v.SupportedStreamFeatures} {
		independentLP(&out, independentStringList(values))
	}
	for _, value := range []uint32{v.MaxEnvelopeBytes, v.MaxStreamCount, v.MaxReplayWindow} {
		_ = binary.Write(&out, binary.BigEndian, value)
	}
	return out.Bytes()
}

func independentPolicyV1(policy ir.EffectiveSecurityPolicy) []byte {
	var out bytes.Buffer
	for _, value := range []string{
		policy.SecurityVersion,
		policy.TranscriptMode,
		policy.KDFSuite,
		policy.AEADSuite,
		policy.MACSuite,
		policy.NonceMode,
		policy.ReplayPolicy,
	} {
		independentLP(&out, []byte(value))
	}
	_ = binary.Write(&out, binary.BigEndian, uint32(policy.ReplayWindowSize))
	for _, value := range []string{
		policy.DowngradePolicy,
		policy.CapabilityNegotiationPolicy,
		policy.ProfileCompatibilityPolicy,
		policy.KeyRotationPolicy,
		policy.ConfigValidationPolicy,
		policy.SecureEnvelopeMode,
	} {
		independentLP(&out, []byte(value))
	}
	_ = binary.Write(&out, binary.BigEndian, uint64(policy.MaxSessionMessages))
	_ = binary.Write(&out, binary.BigEndian, uint64(policy.MaxKeyLifetimeMessages))
	return out.Bytes()
}

func independentLimitBlock(v LimitBlockV1) []byte {
	var out bytes.Buffer
	for _, value := range []uint32{v.MaxFrameBytes, v.MaxPayloadBytes, v.MaxStates, v.MaxTransitions} {
		_ = binary.Write(&out, binary.BigEndian, value)
	}
	_ = binary.Write(&out, binary.BigEndian, v.MaxSessionMillis)
	for _, value := range []uint32{v.CarrierMaxEnvelopeBytes, v.CarrierMaxQueueDepth, v.SessionMaxConcurrentStreams} {
		_ = binary.Write(&out, binary.BigEndian, value)
	}
	return out.Bytes()
}

func independentSelectedSuite(v SelectedSuiteV1) []byte {
	var out bytes.Buffer
	for _, value := range []string{v.KDFSuite, v.AEADSuite, v.MACSuite} {
		independentLP(&out, []byte(value))
	}
	return out.Bytes()
}

func independentConfigSourceBlock(v ConfigSourceBlockV1) []byte {
	var out bytes.Buffer
	independentLP(&out, []byte(v.ProfileID))
	out.Write(v.ProfileHash[:])
	independentLP(&out, []byte(v.SecurityVersion))
	independentLP(&out, independentSelectedSuite(v.SelectedSuite))
	out.Write(v.EffectivePolicyHash[:])
	out.Write(v.SelectedCapabilityHash[:])
	independentLP(&out, []byte(v.AdapterClass))
	out.Write(v.CompatibilityBlockHash[:])
	out.Write(v.LimitBlockHash[:])
	return out.Bytes()
}

func independentAuthenticatedModeBinding(mode string, v HandshakeModeBinding) []byte {
	var out bytes.Buffer
	independentLP(&out, []byte(mode))
	for _, values := range [][]string{v.ClientOptional, v.ServerOptional, v.FeatureVectors} {
		independentLP(&out, independentStringList(values))
	}
	independentLP(&out, []byte(v.CarrierFamily))
	out.Write(v.CarrierPolicyHash[:])
	_ = binary.Write(&out, binary.BigEndian, v.EnvelopeLimit)
	_ = binary.Write(&out, binary.BigEndian, v.MaxFrameBytes)
	independentLP(&out, []byte(v.LocalAdapterClass))
	for _, value := range [][32]byte{v.FramingPolicyHash, v.StateMachinePolicyHash, v.SchedulerPolicyHash, v.PaddingPolicyHash, v.StreamPolicyHash, v.ProxyPolicyHash, v.CarrierContextHash} {
		out.Write(value[:])
	}
	independentLP(&out, independentCompatibilityBlock(v.CompatibilityBlock))
	out.Write(v.CompatibilityBlockHash[:])
	independentLP(&out, independentLimitBlock(v.LimitBlock))
	out.Write(v.LimitBlockHash[:])
	independentLP(&out, independentConfigSourceBlock(v.ConfigSourceBlock))
	out.Write(v.ConfigSourceBlockHash[:])
	return out.Bytes()
}

func independentStringList(values []string) []byte {
	if !slices.IsSorted(values) {
		panic("test vector list must be sorted")
	}
	var out bytes.Buffer
	_ = binary.Write(&out, binary.BigEndian, uint32(len(values)))
	for _, value := range values {
		independentLP(&out, []byte(value))
	}
	return out.Bytes()
}

func independentContextHash(label string, parts ...[]byte) [32]byte {
	var out bytes.Buffer
	independentLP(&out, []byte(label))
	for _, part := range parts {
		independentLP(&out, part)
	}
	return sha256.Sum256(out.Bytes())
}

func independentLP(out *bytes.Buffer, value []byte) {
	_ = binary.Write(out, binary.BigEndian, uint32(len(value)))
	out.Write(value)
}

func testHash32(start byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

type contextTestFixture struct {
	input         AuthenticatedContextHashInputV1
	compatibility CompatibilityBlockV1
	limits        LimitBlockV1
	suite         SelectedSuiteV1
	config        ConfigSourceBlockV1
	binding       HandshakeModeBinding
}

func newContextTestFixture(t *testing.T) contextTestFixture {
	t.Helper()
	p, err := compiler.Generate(6231)
	if err != nil {
		t.Fatal(err)
	}
	p.Security.TranscriptMode = TranscriptFullBindingV1
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	selected := []string{"multi_stream", "replay_window"}
	policy, err := ir.BuildEffectiveSecurityPolicy(p, selected[:1], selected[:1], selected)
	if err != nil {
		t.Fatal(err)
	}
	profileRaw, err := hex.DecodeString(policy.ProfileHash)
	if err != nil {
		t.Fatal(err)
	}
	var profileHash [32]byte
	copy(profileHash[:], profileRaw)
	capabilityHash, err := SelectedCapabilityHashV1(selected)
	if err != nil {
		t.Fatal(err)
	}
	policyHash, err := EffectivePolicyHashV1(policy)
	if err != nil {
		t.Fatal(err)
	}
	compatibility := CompatibilityBlockV1{
		SchemaVersion: p.Compatibility.SchemaVersion, CompilerSecurityVersion: p.Compatibility.CompilerSecurityVersion,
		MinimumRuntimeVersion:   p.Compatibility.MinimumRuntimeVersion,
		SupportedSecuritySuites: []string{ir.SecuritySuiteString()}, RequiredCapabilities: []string{"multi_stream"},
		SupportedCarrierFamilies: []string{p.CarrierPolicy.CarrierFamily},
		SupportedProxyFeatures:   []string{"proxy-a"}, SupportedStreamFeatures: []string{"stream-a"},
		MaxEnvelopeBytes: uint32(p.Compatibility.MaxEnvelopeBytes), MaxStreamCount: uint32(p.Compatibility.MaxStreamCount),
		MaxReplayWindow: uint32(p.Compatibility.MaxReplayWindow),
	}
	limits := LimitBlockV1{
		MaxFrameBytes: uint32(p.Limits.MaxFrameBytes), MaxPayloadBytes: uint32(p.Limits.MaxPayloadBytes),
		MaxStates: uint32(p.Limits.MaxStates), MaxTransitions: uint32(p.Limits.MaxTransitions),
		MaxSessionMillis: uint64(p.Limits.MaxSessionMillis), CarrierMaxEnvelopeBytes: uint32(p.CarrierPolicy.MaxEnvelopeBytes),
		CarrierMaxQueueDepth: uint32(p.CarrierPolicy.MaxCarrierQueueDepth), SessionMaxConcurrentStreams: uint32(p.Stream.MaxConcurrentStreams),
	}
	if compatibility.MaxEnvelopeBytes < limits.CarrierMaxEnvelopeBytes {
		compatibility.MaxEnvelopeBytes = limits.CarrierMaxEnvelopeBytes
	}
	if compatibility.MaxStreamCount < limits.SessionMaxConcurrentStreams {
		compatibility.MaxStreamCount = limits.SessionMaxConcurrentStreams
	}
	if compatibility.MaxReplayWindow < uint32(policy.ReplayWindowSize) {
		compatibility.MaxReplayWindow = uint32(policy.ReplayWindowSize)
	}
	compatibilityHash, err := CompatibilityBlockHashV1(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	limitHash, err := LimitBlockHashV1(limits)
	if err != nil {
		t.Fatal(err)
	}
	suite := SelectedSuiteV1{KDFSuite: policy.KDFSuite, AEADSuite: policy.AEADSuite, MACSuite: policy.MACSuite}
	config := ConfigSourceBlockV1{
		ProfileID: policy.ProfileID, ProfileHash: profileHash, SecurityVersion: policy.SecurityVersion,
		SelectedSuite: suite, EffectivePolicyHash: policyHash, SelectedCapabilityHash: capabilityHash,
		AdapterClass: p.AdapterPolicy.RuntimeMappingPolicy, CompatibilityBlockHash: compatibilityHash, LimitBlockHash: limitHash,
	}
	configHash, err := ConfigSourceBlockHashV1(config)
	if err != nil {
		t.Fatal(err)
	}
	binding := HandshakeModeBinding{
		ClientOptional: []string{"client-a", "client-b"}, ServerOptional: []string{"server-a", "server-b"},
		FeatureVectors: []string{"carrier:a", "proxy:a", "stream:a"}, CarrierFamily: p.CarrierPolicy.CarrierFamily,
		CarrierPolicyHash: testHash32(1), EnvelopeLimit: limits.CarrierMaxEnvelopeBytes, MaxFrameBytes: limits.MaxFrameBytes,
		LocalAdapterClass: p.AdapterPolicy.RuntimeMappingPolicy, FramingPolicyHash: testHash32(2),
		StateMachinePolicyHash: testHash32(3), SchedulerPolicyHash: testHash32(4), PaddingPolicyHash: testHash32(5),
		StreamPolicyHash: testHash32(6), ProxyPolicyHash: testHash32(7), CarrierContextHash: testHash32(8),
		CompatibilityBlock: compatibility, CompatibilityBlockHash: compatibilityHash,
		LimitBlock: limits, LimitBlockHash: limitHash, ConfigSourceBlock: config, ConfigSourceBlockHash: configHash,
	}
	transcript := testHash32(20)
	input := AuthenticatedContextHashInputV1{
		EffectivePolicy: policy, EffectivePolicyHash: policyHash, TranscriptHash: transcript, SelectedSuite: suite,
		SelectedCapabilityHash: capabilityHash, ClientProfileHash: profileHash, ServerProfileHash: profileHash,
		ClientModeBinding: binding.Clone(), ServerModeBinding: binding.Clone(),
	}
	if _, err := ContextHashV1(input); err != nil {
		t.Fatalf("invalid context test fixture: %v", err)
	}
	return contextTestFixture{input: input, compatibility: compatibility, limits: limits, suite: suite, config: config, binding: binding}
}

func cloneContextHashInput(input AuthenticatedContextHashInputV1) AuthenticatedContextHashInputV1 {
	input.EffectivePolicy = input.EffectivePolicy.Clone()
	input.ClientModeBinding = input.ClientModeBinding.Clone()
	input.ServerModeBinding = input.ServerModeBinding.Clone()
	return input
}

func recomputeBindingHashes(t *testing.T, binding *HandshakeModeBinding) {
	t.Helper()
	var err error
	binding.CompatibilityBlockHash, err = CompatibilityBlockHashV1(binding.CompatibilityBlock)
	if err != nil {
		t.Fatal(err)
	}
	binding.LimitBlockHash, err = LimitBlockHashV1(binding.LimitBlock)
	if err != nil {
		t.Fatal(err)
	}
	binding.ConfigSourceBlock.CompatibilityBlockHash = binding.CompatibilityBlockHash
	binding.ConfigSourceBlock.LimitBlockHash = binding.LimitBlockHash
	recomputeConfigSourceHash(t, binding)
}

func recomputeConfigSourceHash(t *testing.T, binding *HandshakeModeBinding) {
	t.Helper()
	var err error
	binding.ConfigSourceBlockHash, err = ConfigSourceBlockHashV1(binding.ConfigSourceBlock)
	if err != nil {
		t.Fatal(err)
	}
}

func assertContextRejects(t *testing.T, input AuthenticatedContextHashInputV1) {
	t.Helper()
	if _, err := ContextHashV1(input); err == nil {
		t.Fatal("contradictory context input accepted")
	}
}

func alternateAdapter(current string) string {
	if current != "one_flow_one_stream" {
		return "one_flow_one_stream"
	}
	return "priority_mapped_stream"
}

func alternateCarrier(current string) string {
	for _, candidate := range ir.CarrierFamilies() {
		if candidate != current {
			return candidate
		}
	}
	return current
}
