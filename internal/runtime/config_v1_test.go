// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
)

func TestStrictSessionConfigCanonicalHashV1(t *testing.T) {
	value := strictSessionConfigTestValueV1()
	want := independentConfigPolicyHashV1(value)
	got, err := ConfigPolicyHashV1(value)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("config hash mismatch: got %x want %x", got, want)
	}
	literal := [32]byte{0xc9, 0x0d, 0xf6, 0x74, 0xf6, 0x9b, 0x71, 0xd4, 0x84, 0x05, 0xab, 0xb2, 0x8d, 0xde, 0xbd, 0x88, 0x21, 0x5e, 0x81, 0xa7, 0x88, 0x7b, 0x02, 0x2d, 0x61, 0x7e, 0xe3, 0x8a, 0x5f, 0xa2, 0x50, 0x42}
	if got != literal {
		t.Fatalf("literal config vector mismatch: got %x want %x", got, literal)
	}
	value.ConfigPolicyHash = got
	client, err := NewClientStrictSessionConfigV1(value)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := NewRelayStrictSessionConfigV1(value)
	if err != nil {
		t.Fatal(err)
	}
	if client.value != relay.value || client.value != value {
		t.Fatal("role wrappers did not retain the exact role-neutral value")
	}
	source := value
	source.ProfileID = "mutated-source"
	clientCopy := client
	clientCopy.value.ProfileID = "mutated-wrapper-copy"
	if client.value.ProfileID != value.ProfileID || relay.value.ProfileID != value.ProfileID {
		t.Fatal("source or wrapper-copy mutation aliased an admitted wrapper")
	}
}

func TestStrictSessionConfigRejectsEveryCanonicalMutationV1(t *testing.T) {
	base := strictSessionConfigTestValueV1()
	base.ConfigPolicyHash = independentConfigPolicyHashV1(base)
	mutations := map[string]func(*StrictSessionConfigV1){
		"profile id":       func(v *StrictSessionConfigV1) { v.ProfileID = "other" },
		"profile hash":     func(v *StrictSessionConfigV1) { v.ProfileHash[0] ^= 1 },
		"suite":            func(v *StrictSessionConfigV1) { v.SelectedSuite.MACSuite = "other" },
		"policy hash":      func(v *StrictSessionConfigV1) { v.EffectivePolicyHash[0] ^= 1 },
		"capability hash":  func(v *StrictSessionConfigV1) { v.SelectedCapabilityHash[0] ^= 1 },
		"replay":           func(v *StrictSessionConfigV1) { v.ReplayWindowSize++ },
		"session messages": func(v *StrictSessionConfigV1) { v.MaxSessionMessages++ },
		"key messages":     func(v *StrictSessionConfigV1) { v.MaxKeyLifetimeMessages++ },
		"streams":          func(v *StrictSessionConfigV1) { v.MaxConcurrentStreams++ },
		"frame":            func(v *StrictSessionConfigV1) { v.MaxFrameBytes++ },
		"envelope":         func(v *StrictSessionConfigV1) { v.MaxEnvelopeBytes++ },
		"hash":             func(v *StrictSessionConfigV1) { v.ConfigPolicyHash[0] ^= 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if _, err := NewClientStrictSessionConfigV1(value); !errors.Is(err, ErrConfigInvalid) {
				t.Fatalf("got %v, want config_invalid", err)
			}
		})
	}
}

func TestStrictSessionConfigRangeChecksV1(t *testing.T) {
	base := strictSessionConfigTestValueV1()
	mutations := map[string]func(*StrictSessionConfigV1){
		"empty id":             func(v *StrictSessionConfigV1) { v.ProfileID = "" },
		"control id":           func(v *StrictSessionConfigV1) { v.ProfileID = "bad\x1f" },
		"profile hash":         func(v *StrictSessionConfigV1) { v.ProfileHash = [32]byte{} },
		"policy hash":          func(v *StrictSessionConfigV1) { v.EffectivePolicyHash = [32]byte{} },
		"capability hash":      func(v *StrictSessionConfigV1) { v.SelectedCapabilityHash = [32]byte{} },
		"empty suite":          func(v *StrictSessionConfigV1) { v.SelectedSuite.KDFSuite = "" },
		"malformed suite":      func(v *StrictSessionConfigV1) { v.SelectedSuite.KDFSuite = "bad\x1f" },
		"replay zero":          func(v *StrictSessionConfigV1) { v.ReplayWindowSize = 0 },
		"replay one":           func(v *StrictSessionConfigV1) { v.ReplayWindowSize = 1 },
		"replay above":         func(v *StrictSessionConfigV1) { v.ReplayWindowSize = 4097 },
		"session zero":         func(v *StrictSessionConfigV1) { v.MaxSessionMessages = 0 },
		"session above":        func(v *StrictSessionConfigV1) { v.MaxSessionMessages = 1<<24 + 1 },
		"key zero":             func(v *StrictSessionConfigV1) { v.MaxKeyLifetimeMessages = 0 },
		"key above session":    func(v *StrictSessionConfigV1) { v.MaxKeyLifetimeMessages = v.MaxSessionMessages + 1 },
		"streams zero":         func(v *StrictSessionConfigV1) { v.MaxConcurrentStreams = 0 },
		"streams above":        func(v *StrictSessionConfigV1) { v.MaxConcurrentStreams = 65536 },
		"frame zero":           func(v *StrictSessionConfigV1) { v.MaxFrameBytes = 0 },
		"frame above":          func(v *StrictSessionConfigV1) { v.MaxFrameBytes = 1<<20 + 1 },
		"envelope zero":        func(v *StrictSessionConfigV1) { v.MaxEnvelopeBytes = 0 },
		"envelope above frame": func(v *StrictSessionConfigV1) { v.MaxEnvelopeBytes = v.MaxFrameBytes + 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if _, err := ConfigPolicyHashV1(value); !errors.Is(err, ErrConfigInvalid) {
				t.Fatalf("got %v, want config_invalid", err)
			}
		})
	}
	boundaries := map[string]func(*StrictSessionConfigV1){
		"replay min":            func(v *StrictSessionConfigV1) { v.ReplayWindowSize = 2 },
		"replay max":            func(v *StrictSessionConfigV1) { v.ReplayWindowSize = 4096 },
		"session min key min":   func(v *StrictSessionConfigV1) { v.MaxSessionMessages, v.MaxKeyLifetimeMessages = 1, 1 },
		"session max":           func(v *StrictSessionConfigV1) { v.MaxSessionMessages = 1 << 24 },
		"key equals session":    func(v *StrictSessionConfigV1) { v.MaxKeyLifetimeMessages = v.MaxSessionMessages },
		"streams min":           func(v *StrictSessionConfigV1) { v.MaxConcurrentStreams = 1 },
		"streams max":           func(v *StrictSessionConfigV1) { v.MaxConcurrentStreams = 65535 },
		"frame envelope min":    func(v *StrictSessionConfigV1) { v.MaxFrameBytes, v.MaxEnvelopeBytes = 1, 1 },
		"frame max":             func(v *StrictSessionConfigV1) { v.MaxFrameBytes = 1 << 20 },
		"envelope equals frame": func(v *StrictSessionConfigV1) { v.MaxEnvelopeBytes = v.MaxFrameBytes },
	}
	for name, mutate := range boundaries {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			hash, err := ConfigPolicyHashV1(value)
			if err != nil {
				t.Fatal(err)
			}
			value.ConfigPolicyHash = hash
			if _, err := NewClientStrictSessionConfigV1(value); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStrictSessionConfigExactFieldOrderV1(t *testing.T) {
	typeOf := reflect.TypeOf(StrictSessionConfigV1{})
	want := []string{"ProfileID", "ProfileHash", "SelectedSuite", "EffectivePolicyHash", "SelectedCapabilityHash", "ReplayWindowSize", "MaxSessionMessages", "MaxKeyLifetimeMessages", "MaxConcurrentStreams", "MaxFrameBytes", "MaxEnvelopeBytes", "ConfigPolicyHash"}
	if typeOf.NumField() != len(want) {
		t.Fatalf("got %d fields", typeOf.NumField())
	}
	for i, name := range want {
		if typeOf.Field(i).Name != name {
			t.Fatalf("field %d=%s want %s", i, typeOf.Field(i).Name, name)
		}
	}
}

func TestConfigValidationV1RedactionCertificate(t *testing.T) {
	client := ClientLocalRuntimeControlsV1{RuntimeID: "client-local", EventCapacity: 7, QueueCeiling: 8}
	relay := RelayLocalRuntimeControlsV1{RuntimeID: "relay-local", EventCapacity: 9, QueueCeiling: 8}
	clientCertificate := reviewedClientImplementationSupportV1.redaction
	relayCertificate := reviewedRelayImplementationSupportV1.redaction
	if err := validateAdvancedLocalControlsV1("strict_with_redaction", 8, 8, client, relay, clientCertificate, relayCertificate); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"client", "relay"} {
		t.Run(role+"-missing", func(t *testing.T) {
			clientCopy, relayCopy := clientCertificate, relayCertificate
			if role == "client" {
				clientCopy = redactionCertificateV1{}
			} else {
				relayCopy = redactionCertificateV1{}
			}
			if err := validateAdvancedLocalControlsV1("strict_with_redaction", 8, 8, client, relay, clientCopy, relayCopy); !errors.Is(err, ErrConfigInvalid) {
				t.Fatalf("missing %s certificate err=%v", role, err)
			}
		})
	}
	wrongVersion := clientCertificate
	wrongVersion.version++
	if err := validateAdvancedLocalControlsV1("strict_with_redaction", 8, 8, client, relay, wrongVersion, relayCertificate); !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("wrong version err=%v", err)
	}
	if err := validateAdvancedLocalControlsV1("strict_with_redaction", 8, 8, client, relay, clientCertificate, clientCertificate); !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("cross-role reuse err=%v", err)
	}
	for _, value := range []any{client, relay, PairInputV1{ClientControls: client, RelayControls: relay}} {
		typeOf := reflect.TypeOf(value)
		if typeOf == reflect.TypeOf(PairInputV1{}) {
			for _, name := range []string{"ClientControls", "RelayControls"} {
				field, _ := typeOf.FieldByName(name)
				if field.Type.NumField() != 3 {
					t.Fatalf("%s transitively exposes %d local-control fields", name, field.Type.NumField())
				}
			}
		} else if typeOf.NumField() != 3 {
			t.Fatalf("local controls expose %d fields", typeOf.NumField())
		}
	}
	for _, value := range []any{client, relay, PairInputV1{ClientControls: client, RelayControls: relay}} {
		if _, ok := value.(encoding.TextMarshaler); ok {
			t.Fatalf("%T unexpectedly exposes text marshaling", value)
		}
		if _, ok := value.(fmt.Stringer); ok {
			t.Fatalf("%T unexpectedly exposes String", value)
		}
	}
	raw, err := json.Marshal(client)
	if err != nil {
		t.Fatal(err)
	}
	formatted := []byte(fmt.Sprintf("%v|%+v|%#v", client, relay, PairInputV1{ClientControls: client, RelayControls: relay}))
	if bytes.Contains(raw, []byte("redaction")) || bytes.Contains(raw, clientRedactionMarkerV1[:]) || bytes.Contains(formatted, clientRedactionMarkerV1[:]) || bytes.Contains(formatted, []byte("redaction")) {
		t.Fatalf("private redaction certificate serialized: %s", raw)
	}
}

func TestConfigValidationV1StrictProfileBound(t *testing.T) {
	client := ClientLocalRuntimeControlsV1{RuntimeID: "client-local", EventCapacity: 1, QueueCeiling: 8}
	relay := RelayLocalRuntimeControlsV1{RuntimeID: "relay-local", EventCapacity: 65535, QueueCeiling: 8}
	clientCertificate, relayCertificate := reviewedClientImplementationSupportV1.redaction, reviewedRelayImplementationSupportV1.redaction
	if err := validateAdvancedLocalControlsV1("strict_profile_bound", 8, 8, client, relay, clientCertificate, relayCertificate); err != nil {
		t.Fatal(err)
	}
	client.QueueCeiling = 7
	if err := validateAdvancedLocalControlsV1("strict_profile_bound", 8, 8, client, relay, clientCertificate, relayCertificate); !errors.Is(err, errConfigProfileMismatchV1) || err.Error() != "config_profile_mismatch" {
		t.Fatalf("client role-cap mismatch err=%v", err)
	}
	client.QueueCeiling = 8
	relay.QueueCeiling = 7
	if err := validateAdvancedLocalControlsV1("strict_profile_bound", 8, 8, client, relay, clientCertificate, relayCertificate); !errors.Is(err, errConfigProfileMismatchV1) {
		t.Fatalf("relay role-cap mismatch err=%v", err)
	}
	plainClient := ClientLocalRuntimeControlsV1{RuntimeID: "plain", EventCapacity: 1, QueueCeiling: 1}
	plainRelay := RelayLocalRuntimeControlsV1{RuntimeID: "plain", EventCapacity: 1, QueueCeiling: 1}
	if err := validateAdvancedLocalControlsV1("strict_required", 8, 8, plainClient, plainRelay, redactionCertificateV1{}, redactionCertificateV1{}); err != nil {
		t.Fatalf("strict_required changed: %v", err)
	}
}

func strictSessionConfigTestValueV1() StrictSessionConfigV1 {
	var profileHash, policyHash, capabilityHash [32]byte
	for i := range profileHash {
		profileHash[i] = byte(i + 1)
		policyHash[i] = byte(i + 33)
		capabilityHash[i] = byte(i + 65)
	}
	return StrictSessionConfigV1{
		ProfileID: "profile-test", ProfileHash: profileHash,
		SelectedSuite: security.SelectedSuiteV1{
			KDFSuite: security.SuiteKDFHKDFSHA256, AEADSuite: security.SuiteAEADAES256GCM, MACSuite: security.SuiteMACHMACSHA256,
		},
		EffectivePolicyHash: policyHash, SelectedCapabilityHash: capabilityHash,
		ReplayWindowSize: 64, MaxSessionMessages: 1024, MaxKeyLifetimeMessages: 256,
		MaxConcurrentStreams: 16, MaxFrameBytes: 65536, MaxEnvelopeBytes: 32768,
	}
}

func TestPairAdmissionFaultCapabilityMismatchCausalRedGreenV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 9251, "message_lifetime_bound", 8, 8)
	runtime := lifecycleRuntimeV1(t, fixture)
	input := lifecyclePairInputV1(t, fixture)
	input.FirstContactInput.SelectedCapabilities = append(input.FirstContactInput.SelectedCapabilities, "transcript_binding")
	if client, relay, err := runtime.NewAuthenticatedChannelPair(input); !errors.Is(err, ErrCapabilityRejected) || client != nil || relay != nil || runtime.pendingPairMaterialCountV1() != 0 {
		t.Fatalf("normal capability admission pair=%v/%v err=%v", client, relay, err)
	}
	token, _ := auth.NewAuthLabFaultTokenV1("runtime_accepts_capability_downgrade")
	client, relay, err := runtime.NewAuthenticatedChannelPairWithAuthLabFaultV1(input, token)
	if err != nil || client == nil || relay == nil {
		t.Fatalf("lab capability admission pair=%v/%v err=%v", client, relay, err)
	}
	client.Close()
}

func TestPairAdmissionFaultProfileMismatchCausalRedGreenV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 9252, "message_lifetime_bound", 8, 8)
	runtime := lifecycleRuntimeV1(t, fixture)
	input := lifecyclePairInputV1(t, fixture)
	input.FirstContactInput.Server.ProfileHash[0] ^= 1
	if client, relay, err := runtime.NewAuthenticatedChannelPair(input); !errors.Is(err, ErrProfileMismatch) || client != nil || relay != nil || runtime.pendingPairMaterialCountV1() != 0 {
		t.Fatalf("normal profile admission pair=%v/%v err=%v", client, relay, err)
	}
	token, _ := auth.NewAuthLabFaultTokenV1("runtime_accepts_profile_mismatch")
	client, relay, err := runtime.NewAuthenticatedChannelPairWithAuthLabFaultV1(input, token)
	if err != nil || client == nil || relay == nil {
		t.Fatalf("lab profile admission pair=%v/%v err=%v", client, relay, err)
	}
	client.Close()
}

func TestUnsafeConfigFaultCausalRedGreenV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 9253, "message_lifetime_bound", 8, 8)
	runtime := lifecycleRuntimeV1(t, fixture)
	input := lifecyclePairInputV1(t, fixture)
	input.ClientControls.QueueCeiling--
	if client, relay, err := runtime.NewAuthenticatedChannelPair(input); !errors.Is(err, ErrConfigInvalid) || client != nil || relay != nil || runtime.pendingPairMaterialCountV1() != 0 {
		t.Fatalf("normal unsafe config pair=%v/%v err=%v", client, relay, err)
	}
	token, _ := auth.NewAuthLabFaultTokenV1("unsafe_config_allowed")
	client, relay, err := runtime.NewAuthenticatedChannelPairWithAuthLabFaultV1(input, token)
	if err != nil || client == nil || relay == nil {
		t.Fatalf("lab unsafe config pair=%v/%v err=%v", client, relay, err)
	}
	client.Close()
}

func TestNormalAPINoFaultConfiguredPairV1(t *testing.T) {
	method := reflect.ValueOf((*HandshakeRuntime).NewAuthenticatedChannelPair).Type()
	if method.NumIn() != 2 || method.In(1) != reflect.TypeOf(PairInputV1{}) {
		t.Fatal("normal configured-pair API accepts fault authority")
	}
}

func independentConfigPolicyHashV1(value StrictSessionConfigV1) [32]byte {
	var canonical bytes.Buffer
	independentLPV1(&canonical, []byte(value.ProfileID))
	canonical.Write(value.ProfileHash[:])
	var suite bytes.Buffer
	independentLPV1(&suite, []byte(value.SelectedSuite.KDFSuite))
	independentLPV1(&suite, []byte(value.SelectedSuite.AEADSuite))
	independentLPV1(&suite, []byte(value.SelectedSuite.MACSuite))
	independentLPV1(&canonical, suite.Bytes())
	canonical.Write(value.EffectivePolicyHash[:])
	canonical.Write(value.SelectedCapabilityHash[:])
	independentU32V1(&canonical, value.ReplayWindowSize)
	independentU64V1(&canonical, value.MaxSessionMessages)
	independentU64V1(&canonical, value.MaxKeyLifetimeMessages)
	independentU32V1(&canonical, value.MaxConcurrentStreams)
	independentU32V1(&canonical, value.MaxFrameBytes)
	independentU32V1(&canonical, value.MaxEnvelopeBytes)
	var input bytes.Buffer
	independentLPV1(&input, []byte("kurdistan/runtime/v1/config-policy"))
	independentLPV1(&input, canonical.Bytes())
	return sha256.Sum256(input.Bytes())
}

func independentLPV1(out *bytes.Buffer, value []byte) {
	independentU32V1(out, uint32(len(value)))
	out.Write(value)
}

func independentU32V1(out *bytes.Buffer, value uint32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	out.Write(raw[:])
}

func independentU64V1(out *bytes.Buffer, value uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	out.Write(raw[:])
}
