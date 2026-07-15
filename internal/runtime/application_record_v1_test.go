// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"kurdistan/internal/crypto/security"
)

func testApplicationContextV1(mode string) security.EnvelopeContextV1 {
	var context security.EnvelopeContextV1
	context.EffectivePolicy.SecureEnvelopeMode = mode
	context.MaxEnvelopeBytes = 4096
	for i := range context.EffectivePolicyHash {
		context.EffectivePolicyHash[i] = byte(0x20 + i)
		context.TranscriptHash[i] = byte(i)
		context.CapabilityHash[i] = byte(0x60 + i)
		context.ProfileHash[i] = byte(0x80 + i)
		context.FramingHash[i] = byte(0xa0 + i)
		context.CarrierContextHash[i] = byte(0xc0 + i)
	}
	return context
}

func testApplicationFragmentV1() ApplicationFragmentV1 {
	var operationID [32]byte
	for i := range operationID {
		operationID[i] = byte(0x40 + i)
	}
	return ApplicationFragmentV1{OperationID: operationID, FragmentCount: 1, OperationLength: 4, Fragment: []byte("kurd")}
}

func independentApplicationAADV1(record security.EnvelopeRecordV1, context security.EnvelopeContextV1, class uint16) []byte {
	length := 94
	if context.EffectivePolicy.SecureEnvelopeMode == "full_context_bound_envelope" {
		length = 222
	}
	out := make([]byte, length)
	binary.BigEndian.PutUint16(out[0:2], 1)
	binary.BigEndian.PutUint16(out[2:4], 1)
	copy(out[4:36], context.EffectivePolicyHash[:])
	copy(out[36:68], context.TranscriptHash[:])
	binary.BigEndian.PutUint16(out[68:70], class)
	binary.BigEndian.PutUint64(out[70:78], record.Epoch)
	binary.BigEndian.PutUint16(out[78:80], record.Direction)
	binary.BigEndian.PutUint16(out[80:82], record.Slot)
	binary.BigEndian.PutUint64(out[82:90], record.Sequence)
	binary.BigEndian.PutUint32(out[90:94], record.SealedLength)
	if length == 222 {
		copy(out[94:126], context.CapabilityHash[:])
		copy(out[126:158], context.ProfileHash[:])
		copy(out[158:190], context.FramingHash[:])
		copy(out[190:222], context.CarrierContextHash[:])
	}
	return out
}

func vectorAEADV1(t *testing.T) cipher.AEAD {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

func vectorNonceV1() []byte { return mustHexV1("a0a10003a4a5a6a7a8a9aaab") }

func mustHexV1(value string) []byte {
	out, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return out
}

func vectorSealV1(t *testing.T, context security.EnvelopeContextV1, direction uint16) ApplicationSealV1 {
	t.Helper()
	return func(slot uint16, plaintext []byte) (security.EnvelopeRecordV1, error) {
		record := security.EnvelopeRecordV1{RecordType: 1, Epoch: 7, Direction: direction, Slot: slot, Sequence: 0, SealedLength: uint32(len(plaintext) + 16)}
		class := uint16(RecordClassApplicationV1)
		if context.EffectivePolicy.SecureEnvelopeMode == "synthetic_aead_test" {
			class = RecordClassSyntheticV1
		}
		record.Ciphertext = vectorAEADV1(t).Seal(nil, vectorNonceV1(), plaintext, independentApplicationAADV1(record, context, class))
		return record, nil
	}
}

func vectorOpenV1(t *testing.T, context security.EnvelopeContextV1) ApplicationOpenV1 {
	t.Helper()
	return func(record security.EnvelopeRecordV1) ([]byte, error) {
		class := uint16(RecordClassApplicationV1)
		if context.EffectivePolicy.SecureEnvelopeMode == "synthetic_aead_test" {
			class = RecordClassSyntheticV1
		}
		return vectorAEADV1(t).Open(nil, vectorNonceV1(), record.Ciphertext, independentApplicationAADV1(record, context, class))
	}
}

func TestApplicationRecordVectorV1(t *testing.T) {
	context := testApplicationContextV1("metadata_authenticated")
	var callbackBody []byte
	var observedBody []byte
	seal := vectorSealV1(t, context, applicationDirectionClientV1)
	record, err := (ClientApplicationCodecV1{}).SealApplicationFragmentV1(context, 3, testApplicationFragmentV1(), func(slot uint16, body []byte) (security.EnvelopeRecordV1, error) {
		callbackBody = body
		observedBody = append([]byte(nil), body...)
		return seal(slot, body)
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedBody := mustHexV1("000100010001404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000010000000400000000000000046b757264")
	if !bytes.Equal(observedBody, expectedBody) {
		t.Fatalf("body mismatch: %x", observedBody)
	}
	if !bytes.Equal(callbackBody, make([]byte, len(callbackBody))) {
		t.Fatal("callback plaintext was retained after Seal")
	}
	expectedHeader := mustHexV1("0001000100000000000000070001000300000000000000000000004a")
	if !bytes.Equal(record[:28], expectedHeader) {
		t.Fatalf("header mismatch: %x", record[:28])
	}
	expectedAAD := mustHexV1("00010001202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000100000000000000070001000300000000000000000000004a")
	envelope := security.EnvelopeRecordV1{RecordType: 1, Epoch: 7, Direction: 1, Slot: 3, Sequence: 0, SealedLength: 74}
	if got := independentApplicationAADV1(envelope, context, 1); !bytes.Equal(got, expectedAAD) || len(got) != applicationMinimalAADBytesV1 {
		t.Fatalf("AAD mismatch: %x", got)
	}
	sealed := record[28:]
	if !bytes.Equal(sealed[:58], mustHexV1("57dfb6f40b90d39fd0b6eb26a0017ff0de8f5c2f26f4bcaab94c1a986064279c79f2aaf0e6ee8bb8c2ceabfeb51ed6317428210f93dc76ca541f")) || !bytes.Equal(sealed[58:], mustHexV1("7ab1651bfc0b0d1d434d530854a22efa")) {
		t.Fatalf("sealed vector mismatch: %x", sealed)
	}
	if got := sha256.Sum256(sealed); hex.EncodeToString(got[:]) != "e276cad5d62c4a9475d3cc151426a0f93e73acf37b7eb9bd4c76fc32556b3ffc" {
		t.Fatalf("sealed hash: %x", got)
	}
	if got := sha256.Sum256(record); hex.EncodeToString(got[:]) != "e7d850e574a53ba5306e9c4163692ae72b0521278fb28beb55c4d055ac63c116" {
		t.Fatalf("record hash: %x", got)
	}
	opened, err := (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(context, record, vectorOpenV1(t, context))
	if err != nil || opened.OperationID != testApplicationFragmentV1().OperationID || !bytes.Equal(opened.Fragment, []byte("kurd")) {
		t.Fatalf("open mismatch: %#v, %v", opened, err)
	}
	if len(expectedBody) != applicationBodyFixedBytesV1+4 || len(sealed) != applicationMinimumSealedBytesV1+4 || len(record) != 98+4 {
		t.Fatal("vector length contract mismatch")
	}
}

func TestFullContextVectorV1(t *testing.T) {
	context := testApplicationContextV1("full_context_bound_envelope")
	record, err := (ClientApplicationCodecV1{}).SealApplicationFragmentV1(context, 3, testApplicationFragmentV1(), vectorSealV1(t, context, applicationDirectionClientV1))
	if err != nil {
		t.Fatal(err)
	}
	sealed := record[28:]
	fullAAD := independentApplicationAADV1(security.EnvelopeRecordV1{RecordType: 1, Epoch: 7, Direction: 1, Slot: 3, SealedLength: 74}, context, 1)
	if len(fullAAD) != applicationFullAADBytesV1 || !bytes.Equal(fullAAD[94:126], context.CapabilityHash[:]) || !bytes.Equal(fullAAD[126:158], context.ProfileHash[:]) || !bytes.Equal(fullAAD[158:190], context.FramingHash[:]) || !bytes.Equal(fullAAD[190:222], context.CarrierContextHash[:]) {
		t.Fatal("full AAD length mismatch")
	}
	if !bytes.Equal(sealed[:58], mustHexV1("57dfb6f40b90d39fd0b6eb26a0017ff0de8f5c2f26f4bcaab94c1a986064279c79f2aaf0e6ee8bb8c2ceabfeb51ed6317428210f93dc76ca541f")) || !bytes.Equal(sealed[58:], mustHexV1("3681d9e2fb8b3fbe2bae4dc3a0526c57")) {
		t.Fatalf("full sealed mismatch: %x", sealed)
	}
	if got := sha256.Sum256(sealed); hex.EncodeToString(got[:]) != "e3751c22e25b9e2702653cff852b2ea5dfe93bcb3b82c89b2c01776dcfb93f20" {
		t.Fatalf("sealed hash: %x", got)
	}
	if got := sha256.Sum256(record); hex.EncodeToString(got[:]) != "c056b27e4993e9d8a59909173b6cc2ea40c846f6c50181944396e943991a9208" {
		t.Fatalf("record hash: %x", got)
	}
}

func TestRecordClassRoleAndFragmentOffsetV1(t *testing.T) {
	for _, mode := range []string{"metadata_authenticated", "full_context_bound_envelope", "synthetic_aead_test"} {
		context := testApplicationContextV1(mode)
		for _, tc := range []struct {
			name      string
			seal      func() ([]byte, error)
			open      func([]byte) (ApplicationFragmentV1, error)
			direction uint16
		}{
			{"client", func() ([]byte, error) {
				return (ClientApplicationCodecV1{}).SealApplicationFragmentV1(context, 65535, testApplicationFragmentV1(), vectorSealV1(t, context, 1))
			}, func(record []byte) (ApplicationFragmentV1, error) {
				return (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(context, record, vectorOpenV1(t, context))
			}, 1},
			{"relay", func() ([]byte, error) {
				return (RelayApplicationCodecV1{}).SealApplicationFragmentV1(context, 1, testApplicationFragmentV1(), vectorSealV1(t, context, 2))
			}, func(record []byte) (ApplicationFragmentV1, error) {
				return (ClientApplicationCodecV1{}).OpenApplicationFragmentV1(context, record, vectorOpenV1(t, context))
			}, 2},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				record, err := tc.seal()
				if err != nil || binary.BigEndian.Uint16(record[12:14]) != tc.direction {
					t.Fatalf("seal: %v", err)
				}
				if _, err := tc.open(record); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	fragment := testApplicationFragmentV1()
	fragment.FragmentCount, fragment.FragmentIndex, fragment.OperationLength, fragment.FragmentOffset = 2, 1, 8, 4
	if !validApplicationFragmentV1(fragment) {
		t.Fatal("valid partial multi-fragment grammar rejected")
	}
}

func TestRecordParseAndRecordLengthPrecedenceV1(t *testing.T) {
	context := testApplicationContextV1("metadata_authenticated")
	valid, err := (ClientApplicationCodecV1{}).SealApplicationFragmentV1(context, 3, testApplicationFragmentV1(), vectorSealV1(t, context, 1))
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func([]byte) []byte{
		"short":                func(record []byte) []byte { return record[:27] },
		"trailing":             func(record []byte) []byte { return append(record, 0) },
		"version":              func(record []byte) []byte { binary.BigEndian.PutUint16(record[0:2], 2); return record },
		"type":                 func(record []byte) []byte { binary.BigEndian.PutUint16(record[2:4], 2); return record },
		"direction-zero":       func(record []byte) []byte { binary.BigEndian.PutUint16(record[12:14], 0); return record },
		"direction-unknown":    func(record []byte) []byte { binary.BigEndian.PutUint16(record[12:14], 3); return record },
		"direction-wrong-role": func(record []byte) []byte { binary.BigEndian.PutUint16(record[12:14], 2); return record },
		"slot-zero":            func(record []byte) []byte { binary.BigEndian.PutUint16(record[14:16], 0); return record },
		"sealed-small":         func(record []byte) []byte { binary.BigEndian.PutUint32(record[24:28], 69); return record },
		"sealed-huge":          func(record []byte) []byte { binary.BigEndian.PutUint32(record[24:28], ^uint32(0)); return record },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			record := mutate(append([]byte(nil), valid...))
			var calls atomic.Int32
			_, err := (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(context, record, func(security.EnvelopeRecordV1) ([]byte, error) { calls.Add(1); return nil, nil })
			if !errors.Is(err, ErrRecordInvalid) || calls.Load() != 0 {
				t.Fatalf("err=%v calls=%d", err, calls.Load())
			}
		})
	}
	for length := 0; length < applicationHeaderBytesV1; length++ {
		var calls atomic.Int32
		_, err := (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(context, valid[:length], func(security.EnvelopeRecordV1) ([]byte, error) { calls.Add(1); return nil, nil })
		if err != ErrRecordInvalid || calls.Load() != 0 {
			t.Fatalf("short header length=%d err=%v calls=%d", length, err, calls.Load())
		}
	}
	limited := context
	limited.MaxEnvelopeBytes = 73
	var calls atomic.Int32
	_, err = (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(limited, valid, func(security.EnvelopeRecordV1) ([]byte, error) { calls.Add(1); return nil, nil })
	if !errors.Is(err, ErrRecordInvalid) || calls.Load() != 0 {
		t.Fatalf("limit precedence: %v calls=%d", err, calls.Load())
	}
	boundary := context
	boundary.MaxEnvelopeBytes = 74
	if _, err := (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(boundary, valid, vectorOpenV1(t, context)); err != nil {
		t.Fatalf("exact envelope limit rejected: %v", err)
	}
}

func TestApplicationFragmentV1FailurePrecedenceAndHygiene(t *testing.T) {
	context := testApplicationContextV1("metadata_authenticated")
	valid, err := (ClientApplicationCodecV1{}).SealApplicationFragmentV1(context, 3, testApplicationFragmentV1(), vectorSealV1(t, context, 1))
	if err != nil {
		t.Fatal(err)
	}
	secretBody := []byte("secret plaintext")
	_, err = (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(context, valid, func(security.EnvelopeRecordV1) ([]byte, error) { return secretBody, errors.New("secret raw cause") })
	if err != security.ErrAuthenticationFailed || strings.Contains(err.Error(), "secret") || !bytes.Equal(secretBody, make([]byte, len(secretBody))) {
		t.Fatalf("open hygiene: err=%v body=%q", err, secretBody)
	}
	full := testApplicationContextV1("full_context_bound_envelope")
	full.CapabilityHash = [32]byte{}
	var calls atomic.Int32
	_, err = (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(full, valid, func(security.EnvelopeRecordV1) ([]byte, error) { calls.Add(1); return nil, nil })
	if err != security.ErrEnvelopeContextInvalid || calls.Load() != 0 {
		t.Fatalf("context precedence: %v calls=%d", err, calls.Load())
	}
	body := mustHexV1("000100010001404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000010000000400000000000000046b757264")
	malformed := append([]byte(nil), body...)
	binary.BigEndian.PutUint16(malformed[0:2], 2)
	_, err = (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(context, valid, func(security.EnvelopeRecordV1) ([]byte, error) { return malformed, nil })
	if err != ErrRecordInvalid {
		t.Fatalf("body grammar precedence: %v", err)
	}
	_, err = (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(context, valid, func(security.EnvelopeRecordV1) ([]byte, error) {
		return append(append([]byte(nil), body...), 0), nil
	})
	if err != ErrRecordInvalid {
		t.Fatalf("authenticated body/header length mismatch: %v", err)
	}
	wrongClass := append([]byte(nil), body...)
	binary.BigEndian.PutUint16(wrongClass[4:6], RecordClassSyntheticV1)
	_, err = (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(context, valid, func(security.EnvelopeRecordV1) ([]byte, error) { return wrongClass, nil })
	if err != security.ErrEnvelopeModeRejected {
		t.Fatalf("class precedence: %v", err)
	}
	unknownClass := append([]byte(nil), body...)
	binary.BigEndian.PutUint16(unknownClass[4:6], 3)
	_, err = (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(context, valid, func(security.EnvelopeRecordV1) ([]byte, error) { return unknownClass, nil })
	if err != security.ErrEnvelopeModeRejected {
		t.Fatalf("unknown class grammar: %v", err)
	}
	sealedAlias := []byte("secret sealed")
	_, err = (ClientApplicationCodecV1{}).SealApplicationFragmentV1(context, 3, testApplicationFragmentV1(), func(uint16, []byte) (security.EnvelopeRecordV1, error) {
		return security.EnvelopeRecordV1{Ciphertext: sealedAlias}, errors.New("secret raw cause")
	})
	if err != security.ErrAEADInvalid || strings.Contains(err.Error(), "secret") || !bytes.Equal(sealedAlias, make([]byte, len(sealedAlias))) {
		t.Fatalf("seal hygiene: err=%v sealed=%q", err, sealedAlias)
	}
	var successfulAlias []byte
	var aliasObserved bool
	aliasedRecord, err := (ClientApplicationCodecV1{}).SealApplicationFragmentV1(context, 3, testApplicationFragmentV1(), func(slot uint16, body []byte) (security.EnvelopeRecordV1, error) {
		successfulAlias = append(body, make([]byte, applicationAEADOverheadV1)...)
		aliasObserved = &successfulAlias[0] == &body[0]
		for i := len(body); i < len(successfulAlias); i++ {
			successfulAlias[i] = 0xa5
		}
		return security.EnvelopeRecordV1{RecordType: 1, Epoch: 7, Direction: 1, Slot: slot, SealedLength: uint32(len(successfulAlias)), Ciphertext: successfulAlias}, nil
	})
	if err != nil || !aliasObserved || len(aliasedRecord) != applicationHeaderBytesV1+len(successfulAlias) || !bytes.Equal(aliasedRecord[len(aliasedRecord)-applicationAEADOverheadV1:], bytes.Repeat([]byte{0xa5}, applicationAEADOverheadV1)) || !bytes.Equal(successfulAlias, make([]byte, len(successfulAlias))) {
		t.Fatalf("successful seal alias boundary: err=%v observed=%v record=%x alias=%x", err, aliasObserved, aliasedRecord, successfulAlias)
	}
	for _, sentinel := range []error{security.ErrNonceExhausted, security.ErrNonceMismatch, security.ErrAEADInvalid, security.ErrEnvelopeContextInvalid} {
		_, err := (ClientApplicationCodecV1{}).SealApplicationFragmentV1(context, 3, testApplicationFragmentV1(), func(uint16, []byte) (security.EnvelopeRecordV1, error) { return security.EnvelopeRecordV1{}, sentinel })
		if err != sentinel {
			t.Fatalf("seal taxonomy %v became %v", sentinel, err)
		}
	}
	for _, sentinel := range []error{security.ErrNonceExhausted, security.ErrNonceMismatch, security.ErrAEADInvalid, security.ErrAuthenticationFailed, security.ErrEnvelopeContextInvalid} {
		_, err := (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(context, valid, func(security.EnvelopeRecordV1) ([]byte, error) { return nil, sentinel })
		if err != sentinel {
			t.Fatalf("open taxonomy %v became %v", sentinel, err)
		}
	}
}

func TestFragmentOffsetAndBodyGrammarV1(t *testing.T) {
	base := mustHexV1("000100010001404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000010000000400000000000000046b757264")
	mutations := map[string]func([]byte){
		"version-zero":       func(body []byte) { binary.BigEndian.PutUint16(body[0:2], 0) },
		"version-unknown":    func(body []byte) { binary.BigEndian.PutUint16(body[0:2], 2) },
		"type-zero":          func(body []byte) { binary.BigEndian.PutUint16(body[2:4], 0) },
		"type-control":       func(body []byte) { binary.BigEndian.PutUint16(body[2:4], 2) },
		"type-unknown":       func(body []byte) { binary.BigEndian.PutUint16(body[2:4], 99) },
		"zero-operation-id":  func(body []byte) { clear(body[6:38]) },
		"index-equals-count": func(body []byte) { binary.BigEndian.PutUint16(body[38:40], 1) },
		"count-zero":         func(body []byte) { binary.BigEndian.PutUint16(body[40:42], 0) },
		"operation-zero":     func(body []byte) { binary.BigEndian.PutUint32(body[42:46], 0) },
		"offset-range":       func(body []byte) { binary.BigEndian.PutUint32(body[46:50], 1) },
		"single-short-body":  func(body []byte) { binary.BigEndian.PutUint32(body[42:46], 5) },
		"single-offset-body": func(body []byte) {
			binary.BigEndian.PutUint32(body[42:46], 5)
			binary.BigEndian.PutUint32(body[46:50], 1)
		},
		"fragment-zero":     func(body []byte) { binary.BigEndian.PutUint32(body[50:54], 0) },
		"fragment-mismatch": func(body []byte) { binary.BigEndian.PutUint32(body[50:54], 3) },
		"offset-overflow":   func(body []byte) { binary.BigEndian.PutUint32(body[46:50], ^uint32(0)) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			body := append([]byte(nil), base...)
			mutate(body)
			fragment, _, err := parseApplicationBodyV1(body)
			if err != ErrRecordInvalid || !reflect.DeepEqual(fragment, ApplicationFragmentV1{}) {
				t.Fatalf("err=%v fragment=%#v", err, fragment)
			}
		})
	}
	if _, _, err := parseApplicationBodyV1(append(base, 0)); err != ErrRecordInvalid {
		t.Fatalf("trailing body: %v", err)
	}
	for length := 0; length < applicationBodyFixedBytesV1; length++ {
		if _, _, err := parseApplicationBodyV1(base[:length]); err != ErrRecordInvalid {
			t.Fatalf("short body length %d: %v", length, err)
		}
	}
}

func TestOperationMetadataPrivacyV1(t *testing.T) {
	context := testApplicationContextV1("metadata_authenticated")
	fragment := testApplicationFragmentV1()
	record, err := (ClientApplicationCodecV1{}).SealApplicationFragmentV1(context, 3, fragment, vectorSealV1(t, context, 1))
	if err != nil {
		t.Fatal(err)
	}
	header := record[:applicationHeaderBytesV1]
	if bytes.Contains(header, fragment.OperationID[:]) || bytes.Contains(header, fragment.Fragment) || bytes.Contains(header, context.EffectivePolicyHash[:]) || bytes.Contains(header, context.TranscriptHash[:]) || bytes.Contains(record, vectorNonceV1()) {
		t.Fatal("private operation metadata, context, fragment, or nonce appeared in clear record")
	}
}

func TestApplicationFragmentV1ConcurrentStateless(t *testing.T) {
	context := testApplicationContextV1("metadata_authenticated")
	codec := ClientApplicationCodecV1{}
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(slot uint16) {
			defer wg.Done()
			if _, err := codec.SealApplicationFragmentV1(context, slot, testApplicationFragmentV1(), func(slot uint16, body []byte) (security.EnvelopeRecordV1, error) {
				return security.EnvelopeRecordV1{RecordType: 1, Epoch: 7, Direction: 1, Slot: slot, Sequence: uint64(slot), SealedLength: uint32(len(body) + 16), Ciphertext: make([]byte, len(body)+16)}, nil
			}); err != nil {
				errs <- err
			}
		}(uint16(i + 1))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestApplicationFragmentV1AuthOnlyAliasBoundary(t *testing.T) {
	context := testApplicationContextV1("metadata_authenticated")
	valid, err := (ClientApplicationCodecV1{}).SealApplicationFragmentV1(context, 3, testApplicationFragmentV1(), vectorSealV1(t, context, 1))
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), valid...)
	canonicalBody := mustHexV1("000100010001404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000010000000400000000000000046b757264")
	fragment, err := (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(context, valid, func(record security.EnvelopeRecordV1) ([]byte, error) {
		copy(record.Ciphertext, canonicalBody)
		return record.Ciphertext[:len(canonicalBody)], nil
	})
	if err != nil || !bytes.Equal(fragment.Fragment, []byte("kurd")) {
		t.Fatalf("in-place authentication result rejected: %#v %v", fragment, err)
	}
	if !bytes.Equal(valid, original) {
		t.Fatal("caller record was mutated")
	}
}

func TestApplicationFragmentV1APIBoundary(t *testing.T) {
	if reflect.TypeOf(ClientApplicationCodecV1{}).NumField() != 0 || reflect.TypeOf(RelayApplicationCodecV1{}).NumField() != 0 {
		t.Fatal("role codecs must remain stateless")
	}
	for _, codec := range []any{ClientApplicationCodecV1{}, RelayApplicationCodecV1{}} {
		typeOf := reflect.TypeOf(codec)
		for i := 0; i < typeOf.NumMethod(); i++ {
			signature := strings.ToLower(typeOf.Method(i).Type.String())
			for _, forbidden := range []string{"direction", "class uint16", "nonce", "aad", "applicationheaderv1"} {
				if strings.Contains(signature, forbidden) {
					t.Fatalf("caller-controlled authority in %s: %s", typeOf.Method(i).Name, signature)
				}
			}
		}
	}
}

func TestRecordLengthBoundedAllocationV1(t *testing.T) {
	context := testApplicationContextV1("metadata_authenticated")
	small := make([]byte, applicationHeaderBytesV1)
	huge := make([]byte, applicationHeaderBytesV1)
	binary.BigEndian.PutUint16(small[0:2], 1)
	binary.BigEndian.PutUint16(small[2:4], 1)
	binary.BigEndian.PutUint16(small[12:14], 1)
	binary.BigEndian.PutUint16(small[14:16], 1)
	binary.BigEndian.PutUint32(small[24:28], 69)
	copy(huge, small)
	binary.BigEndian.PutUint32(huge[24:28], ^uint32(0))
	measure := func(record []byte) float64 {
		return testing.AllocsPerRun(100, func() {
			_, _ = (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(context, record, func(security.EnvelopeRecordV1) ([]byte, error) {
				panic("invalid header reached callback")
			})
		})
	}
	if smallAllocs, hugeAllocs := measure(small), measure(huge); hugeAllocs > smallAllocs+1 {
		t.Fatalf("attacker length changed allocation scale: small=%v huge=%v", smallAllocs, hugeAllocs)
	}
	limited := context
	limited.MaxEnvelopeBytes = applicationMinimumSealedBytesV1
	var sealCalls atomic.Int32
	_, err := (ClientApplicationCodecV1{}).SealApplicationFragmentV1(limited, 1, testApplicationFragmentV1(), func(uint16, []byte) (security.EnvelopeRecordV1, error) {
		sealCalls.Add(1)
		return security.EnvelopeRecordV1{}, nil
	})
	if err != ErrRecordInvalid || sealCalls.Load() != 0 {
		t.Fatalf("oversized Seal allocated/called primitive: err=%v calls=%d", err, sealCalls.Load())
	}
}
