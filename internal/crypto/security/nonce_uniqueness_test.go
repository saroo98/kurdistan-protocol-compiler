// SPDX-License-Identifier: AGPL-3.0-or-later
package security

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestNonceUniquenessInjectivityEnvelopeV1(t *testing.T) {
	modes := []string{NonceModeCounterXORBaseV1, NonceModeCounterAppendBaseV1, NonceModeDirectionalCounterV1, NonceModeStreamPartitionedCounterV1}
	for ordinal, mode := range modes {
		schedule := mustNonceScheduleV1(t)
		context := envelopeContextFixtureV1(mode, ReplayPolicyWindowedReplayV1, 64, "metadata_authenticated")
		client, _ := envelopePairV1(t, schedule, context)
		config, err := newNonceDirectionConfigV1(schedule.Epoch, DirectionClientToRelayV1, schedule.ClientNonceBase, mode)
		if err != nil {
			t.Fatal(err)
		}
		type privatePair struct {
			ordinal int
			nonce   [12]byte
		}
		seen := make(map[privatePair]struct{})
		slots := []uint16{1, 2, 65535}
		for i := 0; i < 256; i++ {
			slot := slots[i%len(slots)]
			var record EnvelopeRecordV1
			if i%4 == 0 {
				record, err = client.SealControlV1(2, nil, nil)
			} else {
				record, err = client.SealApplicationV1(slot, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			nonce, err := deriveNonceV1(config, record.Slot, record.Sequence)
			if err != nil {
				t.Fatal(err)
			}
			key := privatePair{ordinal: ordinal, nonce: nonce}
			if _, duplicate := seen[key]; duplicate {
				t.Fatal("reachable strict allocation collision")
			}
			seen[key] = struct{}{}
		}
		if mode == NonceModeStreamPartitionedCounterV1 {
			formulaSeen := make(map[[12]byte]struct{})
			for _, slot := range []uint16{0, 1, 2, 65535} {
				for sequence := uint64(0); sequence < 64; sequence++ {
					nonce, err := deriveNonceV1(config, slot, sequence)
					if err != nil {
						t.Fatal(err)
					}
					if _, duplicate := formulaSeen[nonce]; duplicate {
						t.Fatal("stream slot/sequence formula collision")
					}
					formulaSeen[nonce] = struct{}{}
				}
			}
		}
		schedule.Destroy()
	}
}

func TestNonceUniquenessCollisionObserverV1(t *testing.T) {
	type observed struct {
		keyOrdinal uint32
		nonce      [12]byte
	}
	seen := make(map[observed]struct{})
	keyOrdinals := make(map[[32]byte]uint32)
	collisions := 0
	nextOrdinal := uint32(0)
	for _, mode := range []string{NonceModeCounterXORBaseV1, NonceModeCounterAppendBaseV1, NonceModeDirectionalCounterV1, NonceModeStreamPartitionedCounterV1} {
		first := mustNonceScheduleV1(t)
		second, err := RatchetKeyScheduleV1(first)
		if err != nil {
			t.Fatal(err)
		}
		for _, schedule := range []KeySchedule{first, second} {
			client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(mode, ReplayPolicyWindowedReplayV1, 64, "metadata_authenticated"))
			for _, endpoint := range []*EnvelopeCodecV1{client, relay} {
				base := schedule.ClientNonceBase
				keyBytes := schedule.ClientWriteKey
				direction := DirectionClientToRelayV1
				if endpoint == relay {
					base = schedule.ServerNonceBase
					keyBytes = schedule.ServerWriteKey
					direction = DirectionRelayToClientV1
				}
				var keyIdentity [32]byte
				copy(keyIdentity[:], keyBytes)
				ordinal, ok := keyOrdinals[keyIdentity]
				if !ok {
					nextOrdinal++
					ordinal = nextOrdinal
					keyOrdinals[keyIdentity] = ordinal
				}
				config, _ := newNonceDirectionConfigV1(schedule.Epoch, direction, base, mode)
				endpoint.state.sealFail = func() error { return ErrAEADInvalid }
				if _, err := endpoint.SealApplicationV1(1, nil); !errors.Is(err, ErrAEADInvalid) {
					t.Fatal("observer injected failure was not exercised")
				}
				failedNonce, _ := deriveNonceV1(config, 1, 0)
				failed := observed{keyOrdinal: ordinal, nonce: failedNonce}
				if _, duplicate := seen[failed]; duplicate {
					collisions++
				}
				seen[failed] = struct{}{}
				endpoint.state.sealFail = nil
				for i := 0; i < 64; i++ {
					record, err := endpoint.SealApplicationV1(uint16(i%3+1), nil)
					if err != nil {
						t.Fatal(err)
					}
					nonce, _ := deriveNonceV1(config, record.Slot, record.Sequence)
					key := observed{keyOrdinal: ordinal, nonce: nonce}
					if _, duplicate := seen[key]; duplicate {
						collisions++
					}
					seen[key] = struct{}{}
				}
			}
		}
		first.Destroy()
		second.Destroy()
	}
	if collisions != 0 || len(seen) != 1040 {
		t.Fatalf("observer aggregate mismatch: samples=%d collisions=%d", len(seen), collisions)
	}
}

func TestEnvelopeV1ExactApplicationAADLayouts(t *testing.T) {
	ciphertexts := make(map[string][]byte)
	vectors := map[string]string{
		"metadata_authenticated":      "00010001010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020001000000000000000000010003000000000000000000000014",
		"synthetic_aead_test":         "00010001010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020002000000000000000000010003000000000000000000000014",
		"full_context_bound_envelope": "000100010101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020200010000000000000000000100030000000000000000000000140303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040405050505050505050505050505050505050505050505050505050505050505050606060606060606060606060606060606060606060606060606060606060606",
	}
	for _, mode := range []string{"metadata_authenticated", "synthetic_aead_test", "full_context_bound_envelope"} {
		schedule := mustNonceScheduleV1(t)
		context := envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 64, mode)
		client, _ := envelopePairV1(t, schedule, context)
		record, err := client.SealApplicationV1(3, []byte("body"))
		if err != nil {
			t.Fatal(err)
		}
		got := client.applicationAADV1(record)
		ciphertexts[mode] = append([]byte(nil), record.Ciphertext...)
		want := independentApplicationAADV1(client, record)
		literal, err := hex.DecodeString(vectors[mode])
		if err != nil {
			t.Fatal(err)
		}
		wantLen := 94
		if mode == "full_context_bound_envelope" {
			wantLen = 222
		}
		if len(got) != wantLen || !bytes.Equal(got, want) || !bytes.Equal(got, literal) {
			t.Fatalf("mode %s AAD mismatch len=%d", mode, len(got))
		}
		schedule.Destroy()
	}
	if bytes.Equal(ciphertexts["metadata_authenticated"], ciphertexts["synthetic_aead_test"]) {
		t.Fatal("policy-derived class did not separate ciphertext/tag")
	}
}

func TestEnvelopeV1StrictAPINoNonceOrAADBypass(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	filename = strings.Replace(filename, "nonce_uniqueness_test.go", "envelope.go", 1)
	file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || !strings.Contains(fn.Name.Name, "EnvelopeV1") && !strings.Contains(fn.Name.Name, "ApplicationV1") {
			continue
		}
		if fn.Type.Params != nil {
			for _, field := range fn.Type.Params.List {
				for _, name := range field.Names {
					lower := strings.ToLower(name.Name)
					if strings.Contains(lower, "nonce") || (strings.Contains(fn.Name.Name, "Application") && strings.Contains(lower, "aad")) {
						t.Fatalf("strict API exposes forbidden operand %s.%s", fn.Name.Name, name.Name)
					}
				}
			}
		}
	}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range general.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "EnvelopeRecordV1" {
				continue
			}
			structure := typeSpec.Type.(*ast.StructType)
			for _, field := range structure.Fields.List {
				for _, name := range field.Names {
					lower := strings.ToLower(name.Name)
					if strings.Contains(lower, "nonce") || strings.Contains(lower, "class") {
						t.Fatalf("strict record exposes caller/wire field %s", name.Name)
					}
				}
			}
		}
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	allocationIndex := strings.Index(source, "allocation, err =")
	sealIndex := strings.Index(source, "c.outbound.Seal(")
	if allocationIndex < 0 || sealIndex < 0 || allocationIndex > sealIndex || strings.Contains(source, "state.next--") || strings.Contains(source, "sequences = nil") {
		t.Fatal("strict send source does not preserve allocate-before-seal/no-reset shape")
	}
	if strings.Contains(source, "internal/runtime") || strings.Contains(source, "NewEnvelopeCodec(") && strings.Contains(source[:sealIndex], "NewEnvelopeCodec(") {
		t.Fatal("strict implementation crosses runtime or legacy constructor boundary")
	}
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 64, "metadata_authenticated"))
	if _, err := client.SealControlV1(1, nil, nil); err == nil {
		t.Fatal("control path admitted application record type")
	}
	app, err := client.SealApplicationV1(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, err := relay.OpenControlV1(app, nil); plaintext != nil || err == nil {
		t.Fatal("control open bypassed application AAD")
	}
}

func independentApplicationAADV1(codec *EnvelopeCodecV1, record EnvelopeRecordV1) []byte {
	var out bytes.Buffer
	_ = binary.Write(&out, binary.BigEndian, uint16(1))
	_ = binary.Write(&out, binary.BigEndian, uint16(1))
	out.Write(codec.context.EffectivePolicyHash[:])
	out.Write(codec.context.TranscriptHash[:])
	class, _ := codec.ExpectedClassV1()
	_ = binary.Write(&out, binary.BigEndian, class)
	_ = binary.Write(&out, binary.BigEndian, record.Epoch)
	_ = binary.Write(&out, binary.BigEndian, record.Direction)
	_ = binary.Write(&out, binary.BigEndian, record.Slot)
	_ = binary.Write(&out, binary.BigEndian, record.Sequence)
	_ = binary.Write(&out, binary.BigEndian, record.SealedLength)
	if codec.context.EffectivePolicy.SecureEnvelopeMode == "full_context_bound_envelope" {
		out.Write(codec.context.CapabilityHash[:])
		out.Write(codec.context.ProfileHash[:])
		out.Write(codec.context.FramingHash[:])
		out.Write(codec.context.CarrierContextHash[:])
	}
	return out.Bytes()
}
