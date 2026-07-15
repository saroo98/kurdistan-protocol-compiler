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
	"testing"
)

const (
	operationAckBodyVectorV1 = "00010002cde482ac3912a60bdba0c2a0ecebc0335cf2850833d7f2e9d502e2fe798ffd340000000000000005"
	operationAckAADVectorV1  = "00010002202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000000070002000000000000000b0000003c"
	operationAckHeaderV1     = "0001000200000000000000070002000000000000000b0000003c"
	operationAckCiphertextV1 = "e8de59be63e5cffed77e6dd10286b57dc47c83ff6e7dafec088247653f2fcc44105a354c243ed2b636fc5159"
	operationAckTagV1        = "f8ce0e52c04e8a34694eb042c535e105"
	operationAckRecordV1     = "0001000200000000000000070002000000000000000b0000003ce8de59be63e5cffed77e6dd10286b57dc47c83ff6e7dafec088247653f2fcc44105a354c243ed2b636fc5159f8ce0e52c04e8a34694eb042c535e105"
	closeBodyVectorV1        = "000100030001"
	closeAADVectorV1         = "00010003202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000000070002000000000000000c00000016"
	closeHeaderVectorV1      = "0001000300000000000000070002000000000000000c00000016"
	closeCiphertextVectorV1  = "17b3e1818ec7"
	closeTagVectorV1         = "6c1ff72c25b291cb249742d5b93bc97d"
	closeRecordVectorV1      = "0001000300000000000000070002000000000000000c0000001617b3e1818ec76c1ff72c25b291cb249742d5b93bc97d"
)

func TestOperationAckVectorV1(t *testing.T) {
	context := controlVectorContextV1()
	ack := OperationAckV1{OperationID: controlVectorOperationIDV1(), CompletedCount: 5}
	wantBody := mustControlHexV1(t, operationAckBodyVectorV1)
	wantAAD := mustControlHexV1(t, operationAckAADVectorV1)
	wantHeader := mustControlHexV1(t, operationAckHeaderV1)
	wantCiphertext := mustControlHexV1(t, operationAckCiphertextV1)
	wantTag := mustControlHexV1(t, operationAckTagV1)
	wantRecord := mustControlHexV1(t, operationAckRecordV1)
	wantNonce := mustControlHexV1(t, "a0a1a2a3000000000000000b")

	body, err := encodeOperationAckBodyV1(ack)
	if err != nil {
		t.Fatal(err)
	}
	assertControlBytesV1(t, "body", body[:], wantBody)
	header := ControlHeaderV1{
		Version: ControlRecordVersionV1, Type: RecordTypeOperationAckV1,
		Epoch: 7, Direction: controlDirectionRelayV1, Sequence: 11,
		SealedLength: operationAckSealedBytesV1,
	}
	headerBytes := encodeControlHeaderV1(header)
	assertControlBytesV1(t, "header", headerBytes[:], wantHeader)
	parsedHeader, err := parseControlHeaderV1(headerBytes[:])
	if err != nil || parsedHeader != header {
		t.Fatalf("header parse mismatch: got %+v err %v want %+v", parsedHeader, err, header)
	}
	aad := encodeControlAADV1(header, context)
	assertControlBytesV1(t, "aad", aad[:], wantAAD)

	aead := controlVectorAEADV1(t)
	var observedBody, observedAAD, observedNonce, observedSealed []byte
	seal := func(epoch, sequence uint64, plaintext, aad []byte) ([]byte, error) {
		if epoch != 7 || sequence != 11 {
			t.Fatalf("seal metadata mismatch: epoch=%d sequence=%d", epoch, sequence)
		}
		nonce := controlVectorNonceV1(sequence)
		observedBody = append([]byte(nil), plaintext...)
		observedAAD = append([]byte(nil), aad...)
		observedNonce = append([]byte(nil), nonce[:]...)
		observedSealed = aead.Seal(nil, nonce[:], plaintext, aad)
		return append([]byte(nil), observedSealed...), nil
	}
	record, err := (RelayControlCodecV1{}).SealOperationAckV1(context, 7, 11, ack, seal)
	if err != nil {
		t.Fatal(err)
	}
	assertControlBytesV1(t, "callback body", observedBody, wantBody)
	assertControlBytesV1(t, "callback aad", observedAAD, wantAAD)
	assertControlBytesV1(t, "callback nonce", observedNonce, wantNonce)
	if len(observedSealed) != operationAckSealedBytesV1 {
		t.Fatalf("sealed length=%d want %d", len(observedSealed), operationAckSealedBytesV1)
	}
	assertControlBytesV1(t, "ciphertext", observedSealed[:operationAckBodyBytesV1], wantCiphertext)
	assertControlBytesV1(t, "tag", observedSealed[operationAckBodyBytesV1:], wantTag)
	assertControlDigestV1(t, "sealed", observedSealed, "325e9591b36c0b666b44de18e326db47e49074780c212ce985c27f1c18c32d27")
	assertControlBytesV1(t, "record", record, wantRecord)
	assertControlDigestV1(t, "record", record, "3a1ebb8246fc3d1c013017b11e28b29d4363001884496fc6e3c1a7f823acd194")
	if len(body) != 44 || len(observedSealed)-aead.Overhead() != 44 || aead.Overhead() != 16 || len(record) != 86 || len(aad) != 90 || len(headerBytes) != 26 {
		t.Fatal("operation acknowledgement vector length invariant changed")
	}

	open := func(epoch, sequence uint64, sealed, aad []byte) ([]byte, error) {
		if epoch != 7 || sequence != 11 {
			t.Fatalf("open metadata mismatch: epoch=%d sequence=%d", epoch, sequence)
		}
		nonce := controlVectorNonceV1(sequence)
		assertControlBytesV1(t, "open sealed", sealed, observedSealed)
		assertControlBytesV1(t, "open aad", aad, wantAAD)
		assertControlBytesV1(t, "open nonce", nonce[:], wantNonce)
		return aead.Open(nil, nonce[:], sealed, aad)
	}
	opened, err := (ClientControlCodecV1{}).OpenOperationAckV1(context, record, open)
	if err != nil {
		t.Fatal(err)
	}
	if opened != ack {
		t.Fatalf("opened ack mismatch: got %+v want %+v", opened, ack)
	}
	parsedBody, err := parseOperationAckBodyV1(wantBody)
	if err != nil || parsedBody != ack {
		t.Fatalf("independent body parse mismatch: got %+v err %v", parsedBody, err)
	}
}

func TestCloseVectorV1(t *testing.T) {
	context := controlVectorContextV1()
	closeValue := CloseV1{Code: CloseCodeTerminalV1}
	wantBody := mustControlHexV1(t, closeBodyVectorV1)
	wantAAD := mustControlHexV1(t, closeAADVectorV1)
	wantHeader := mustControlHexV1(t, closeHeaderVectorV1)
	wantCiphertext := mustControlHexV1(t, closeCiphertextVectorV1)
	wantTag := mustControlHexV1(t, closeTagVectorV1)
	wantRecord := mustControlHexV1(t, closeRecordVectorV1)
	wantNonce := mustControlHexV1(t, "a0a1a2a3000000000000000c")

	body, err := encodeCloseBodyV1(closeValue)
	if err != nil {
		t.Fatal(err)
	}
	assertControlBytesV1(t, "body", body[:], wantBody)
	header := ControlHeaderV1{
		Version: ControlRecordVersionV1, Type: RecordTypeCloseV1,
		Epoch: 7, Direction: controlDirectionRelayV1, Sequence: 12,
		SealedLength: closeSealedBytesV1,
	}
	headerBytes := encodeControlHeaderV1(header)
	assertControlBytesV1(t, "header", headerBytes[:], wantHeader)
	aad := encodeControlAADV1(header, context)
	assertControlBytesV1(t, "aad", aad[:], wantAAD)

	aead := controlVectorAEADV1(t)
	var observedBody, observedAAD, observedNonce, observedSealed []byte
	seal := func(epoch, sequence uint64, plaintext, aad []byte) ([]byte, error) {
		if epoch != 7 || sequence != 12 {
			t.Fatalf("seal metadata mismatch: epoch=%d sequence=%d", epoch, sequence)
		}
		nonce := controlVectorNonceV1(sequence)
		observedBody = append([]byte(nil), plaintext...)
		observedAAD = append([]byte(nil), aad...)
		observedNonce = append([]byte(nil), nonce[:]...)
		observedSealed = aead.Seal(nil, nonce[:], plaintext, aad)
		return append([]byte(nil), observedSealed...), nil
	}
	record, err := (RelayControlCodecV1{}).SealCloseV1(context, 7, 12, closeValue, seal)
	if err != nil {
		t.Fatal(err)
	}
	assertControlBytesV1(t, "callback body", observedBody, wantBody)
	assertControlBytesV1(t, "callback aad", observedAAD, wantAAD)
	assertControlBytesV1(t, "callback nonce", observedNonce, wantNonce)
	assertControlBytesV1(t, "ciphertext", observedSealed[:closeBodyBytesV1], wantCiphertext)
	assertControlBytesV1(t, "tag", observedSealed[closeBodyBytesV1:], wantTag)
	assertControlDigestV1(t, "sealed", observedSealed, "2cc1df11ab190657d8d401b8df11b6e893f2f6388e2a30adf72364546e1aea89")
	assertControlBytesV1(t, "record", record, wantRecord)
	assertControlDigestV1(t, "record", record, "7f1e2060fc73e29507339187ff6ba446a5e263cb0a2ebab3b98f0bf7cbbe2187")
	if len(body) != 6 || len(observedSealed)-aead.Overhead() != 6 || aead.Overhead() != 16 || len(record) != 48 || len(aad) != 90 || len(headerBytes) != 26 {
		t.Fatal("close vector length invariant changed")
	}

	open := func(epoch, sequence uint64, sealed, aad []byte) ([]byte, error) {
		if epoch != 7 || sequence != 12 {
			t.Fatalf("open metadata mismatch: epoch=%d sequence=%d", epoch, sequence)
		}
		nonce := controlVectorNonceV1(sequence)
		assertControlBytesV1(t, "open sealed", sealed, observedSealed)
		assertControlBytesV1(t, "open aad", aad, wantAAD)
		assertControlBytesV1(t, "open nonce", nonce[:], wantNonce)
		return aead.Open(nil, nonce[:], sealed, aad)
	}
	opened, err := (ClientControlCodecV1{}).OpenCloseV1(context, record, open)
	if err != nil {
		t.Fatal(err)
	}
	if opened != closeValue {
		t.Fatalf("opened close mismatch: got %+v want %+v", opened, closeValue)
	}
	parsedBody, err := parseCloseBodyV1(wantBody)
	if err != nil || parsedBody != closeValue {
		t.Fatalf("independent close parse mismatch: got %+v err %v", parsedBody, err)
	}
}

func TestControlHeaderV1MalformedPreParse(t *testing.T) {
	base := mustControlHexV1(t, operationAckRecordV1)
	baseClose := mustControlHexV1(t, closeRecordVectorV1)
	context := controlVectorContextV1()
	cases := map[string][]byte{
		"empty":                   nil,
		"short header":            append([]byte(nil), base[:controlHeaderBytesV1-1]...),
		"truncated sealed":        append([]byte(nil), base[:len(base)-1]...),
		"trailing":                append(append([]byte(nil), base...), 0),
		"version zero":            mutateControlU16V1(base, 0, 0),
		"version unknown":         mutateControlU16V1(base, 0, 2),
		"type zero":               mutateControlU16V1(base, 2, 0),
		"type application":        mutateControlU16V1(base, 2, 1),
		"type close substitution": mutateControlU16V1(base, 2, RecordTypeCloseV1),
		"type unknown":            mutateControlU16V1(base, 2, 4),
		"direction zero":          mutateControlU16V1(base, 12, 0),
		"direction wrong role":    mutateControlU16V1(base, 12, controlDirectionClientV1),
		"direction unknown":       mutateControlU16V1(base, 12, 3),
		"sealed zero":             mutateControlU32V1(base, 22, 0),
		"sealed off by one":       mutateControlU32V1(base, 22, operationAckSealedBytesV1-1),
		"sealed close length":     mutateControlU32V1(base, 22, closeSealedBytesV1),
		"sealed maximum":          mutateControlU32V1(base, 22, ^uint32(0)),
	}
	for name, record := range cases {
		t.Run(name, func(t *testing.T) {
			before := append([]byte(nil), record...)
			contextBefore := context
			calls := 0
			opened, err := (ClientControlCodecV1{}).OpenOperationAckV1(context, record, func(uint64, uint64, []byte, []byte) ([]byte, error) {
				calls++
				return mustControlHexV1(t, operationAckBodyVectorV1), nil
			})
			if !errors.Is(err, ErrRecordInvalid) || err == nil || err.Error() != "record_invalid" {
				t.Fatalf("got %v, want record_invalid", err)
			}
			if opened != (OperationAckV1{}) || calls != 0 {
				t.Fatalf("pre-parse failure leaked value or invoked callback: opened=%+v calls=%d", opened, calls)
			}
			if !bytes.Equal(record, before) || context != contextBefore {
				t.Fatal("pre-parse failure mutated caller-owned input")
			}
		})
	}

	closeCalls := 0
	if _, err := (ClientControlCodecV1{}).OpenOperationAckV1(context, baseClose, func(uint64, uint64, []byte, []byte) ([]byte, error) {
		closeCalls++
		return mustControlHexV1(t, operationAckBodyVectorV1), nil
	}); !errors.Is(err, ErrRecordInvalid) || closeCalls != 0 {
		t.Fatalf("close-to-ack substitution got %v calls=%d", err, closeCalls)
	}
	ackCalls := 0
	if _, err := (ClientControlCodecV1{}).OpenCloseV1(context, base, func(uint64, uint64, []byte, []byte) ([]byte, error) {
		ackCalls++
		return mustControlHexV1(t, closeBodyVectorV1), nil
	}); !errors.Is(err, ErrRecordInvalid) || ackCalls != 0 {
		t.Fatalf("ack-to-close substitution got %v calls=%d", err, ackCalls)
	}
	closeLengthCases := map[string][]byte{
		"close sealed zero":       mutateControlU32V1(baseClose, 22, 0),
		"close sealed ack length": mutateControlU32V1(baseClose, 22, operationAckSealedBytesV1),
		"close sealed maximum":    mutateControlU32V1(baseClose, 22, ^uint32(0)),
		"close truncated":         append([]byte(nil), baseClose[:len(baseClose)-1]...),
		"close trailing":          append(append([]byte(nil), baseClose...), 0),
	}
	for name, record := range closeLengthCases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			if _, err := (ClientControlCodecV1{}).OpenCloseV1(context, record, func(uint64, uint64, []byte, []byte) ([]byte, error) {
				calls++
				return mustControlHexV1(t, closeBodyVectorV1), nil
			}); !errors.Is(err, ErrRecordInvalid) || calls != 0 {
				t.Fatalf("got %v calls=%d, want pre-callback record_invalid", err, calls)
			}
		})
	}

	header := mustControlHexV1(t, operationAckHeaderV1)
	if _, err := parseControlHeaderV1(header[:len(header)-1]); !errors.Is(err, ErrRecordInvalid) {
		t.Fatalf("short standalone header got %v", err)
	}
	if _, err := parseControlHeaderV1(append(header, 0)); !errors.Is(err, ErrRecordInvalid) {
		t.Fatalf("trailing standalone header got %v", err)
	}
}

func TestControlMalformedOperationAckBodyV1(t *testing.T) {
	record := mustControlHexV1(t, operationAckRecordV1)
	context := controlVectorContextV1()
	valid := mustControlHexV1(t, operationAckBodyVectorV1)
	cases := map[string][]byte{
		"short":           append([]byte(nil), valid[:len(valid)-1]...),
		"trailing":        append(append([]byte(nil), valid...), 0),
		"version zero":    mutateControlU16V1(valid, 0, 0),
		"version unknown": mutateControlU16V1(valid, 0, 2),
		"type zero":       mutateControlU16V1(valid, 2, 0),
		"type close":      mutateControlU16V1(valid, 2, RecordTypeCloseV1),
		"operation zero": func() []byte {
			out := append([]byte(nil), valid...)
			clear(out[4:36])
			return out
		}(),
		"count zero": mutateControlU64V1(valid, 36, 0),
		"close body": mustControlHexV1(t, closeBodyVectorV1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			before := append([]byte(nil), record...)
			contextBefore := context
			calls := 0
			opened, err := (ClientControlCodecV1{}).OpenOperationAckV1(context, record, func(_ uint64, _ uint64, sealed, aad []byte) ([]byte, error) {
				calls++
				if len(sealed) != operationAckSealedBytesV1 || len(aad) != controlAADBytesV1 {
					t.Fatal("bounded callback input length changed")
				}
				sealed[0] ^= 1
				aad[0] ^= 1
				return append([]byte(nil), body...), nil
			})
			if !errors.Is(err, ErrOperationAckInvalid) || err == nil || err.Error() != "operation_ack_invalid" {
				t.Fatalf("got %v, want operation_ack_invalid", err)
			}
			if opened != (OperationAckV1{}) || calls != 1 {
				t.Fatalf("body failure result/callback mismatch: opened=%+v calls=%d", opened, calls)
			}
			if !bytes.Equal(record, before) || context != contextBefore {
				t.Fatal("body failure mutated caller-owned record/context")
			}
		})
	}
}

func TestControlMalformedCloseBodyV1(t *testing.T) {
	record := mustControlHexV1(t, closeRecordVectorV1)
	context := controlVectorContextV1()
	valid := mustControlHexV1(t, closeBodyVectorV1)
	cases := map[string][]byte{
		"short":           append([]byte(nil), valid[:len(valid)-1]...),
		"trailing":        append(append([]byte(nil), valid...), 0),
		"version zero":    mutateControlU16V1(valid, 0, 0),
		"version unknown": mutateControlU16V1(valid, 0, 2),
		"type zero":       mutateControlU16V1(valid, 2, 0),
		"type ack":        mutateControlU16V1(valid, 2, RecordTypeOperationAckV1),
		"code zero":       mutateControlU16V1(valid, 4, 0),
		"code unknown":    mutateControlU16V1(valid, 4, 2),
		"ack body":        mustControlHexV1(t, operationAckBodyVectorV1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			before := append([]byte(nil), record...)
			calls := 0
			opened, err := (ClientControlCodecV1{}).OpenCloseV1(context, record, func(_ uint64, _ uint64, sealed, aad []byte) ([]byte, error) {
				calls++
				sealed[0] ^= 1
				aad[0] ^= 1
				return append([]byte(nil), body...), nil
			})
			if !errors.Is(err, ErrRecordInvalid) || err == nil || err.Error() != "record_invalid" {
				t.Fatalf("got %v, want record_invalid", err)
			}
			if opened != (CloseV1{}) || calls != 1 || !bytes.Equal(record, before) {
				t.Fatalf("close failure leaked/mutated state: opened=%+v calls=%d", opened, calls)
			}
		})
	}
}

func TestControlDirectionRoleWrappersV1(t *testing.T) {
	if controlDirectionClientV1 != uint16(0x0001) || controlDirectionRelayV1 != uint16(0x0002) {
		t.Fatalf("control direction literals changed: client=%#04x relay=%#04x", controlDirectionClientV1, controlDirectionRelayV1)
	}
	context := controlVectorContextV1()
	context.EffectivePolicyHash[0], context.EffectivePolicyHash[31] = 0xd1, 0xd2
	context.TH4[0], context.TH4[31] = 0xe1, 0xe2
	ack := OperationAckV1{OperationID: controlVectorOperationIDV1(), CompletedCount: 1}
	closeValue := CloseV1{Code: CloseCodeTerminalV1}
	ackBody, err := encodeOperationAckBodyV1(ack)
	if err != nil {
		t.Fatal(err)
	}
	closeBody, err := encodeCloseBodyV1(closeValue)
	if err != nil {
		t.Fatal(err)
	}
	seal := func(_ uint64, _ uint64, plaintext, _ []byte) ([]byte, error) {
		return append(append([]byte(nil), plaintext...), make([]byte, 16)...), nil
	}
	open := func(_ uint64, _ uint64, sealed, _ []byte) ([]byte, error) {
		return append([]byte(nil), sealed[:len(sealed)-16]...), nil
	}

	const clientAckEpoch uint64 = 0x0102030405060708
	const clientAckSequence uint64 = 0x1112131415161718
	wantClientAckAAD := independentControlAADV1(
		context, RecordTypeOperationAckV1, clientAckEpoch,
		controlDirectionClientV1, clientAckSequence, operationAckSealedBytesV1,
	)
	clientAckSealCalls := 0
	clientAck, err := (ClientControlCodecV1{}).SealOperationAckV1(context, clientAckEpoch, clientAckSequence, ack, func(epoch, sequence uint64, plaintext, aad []byte) ([]byte, error) {
		clientAckSealCalls++
		if epoch != clientAckEpoch || sequence != clientAckSequence {
			t.Fatalf("client ack seal metadata mismatch: epoch=%x sequence=%x", epoch, sequence)
		}
		assertControlBytesV1(t, "client ack seal body", plaintext, ackBody[:])
		assertControlBytesV1(t, "client ack seal aad", aad, wantClientAckAAD)
		return append(append([]byte(nil), plaintext...), make([]byte, 16)...), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if clientAckSealCalls != 1 {
		t.Fatalf("client ack seal calls=%d want 1", clientAckSealCalls)
	}
	clientHeader, _, err := parseControlRecordV1(clientAck, controlDirectionClientV1, RecordTypeOperationAckV1)
	wantClientAckHeader := ControlHeaderV1{
		Version: ControlRecordVersionV1, Type: RecordTypeOperationAckV1,
		Epoch: clientAckEpoch, Direction: controlDirectionClientV1,
		Sequence: clientAckSequence, SealedLength: operationAckSealedBytesV1,
	}
	if err != nil || clientHeader != wantClientAckHeader {
		t.Fatalf("client direction mismatch: header=%+v err=%v", clientHeader, err)
	}
	clientAckOpenCalls := 0
	if opened, err := (RelayControlCodecV1{}).OpenOperationAckV1(context, clientAck, func(epoch, sequence uint64, sealed, aad []byte) ([]byte, error) {
		clientAckOpenCalls++
		if epoch != clientAckEpoch || sequence != clientAckSequence {
			t.Fatalf("relay ack open metadata mismatch: epoch=%x sequence=%x", epoch, sequence)
		}
		if len(sealed) != operationAckSealedBytesV1 {
			t.Fatalf("relay ack open sealed length=%d want %d", len(sealed), operationAckSealedBytesV1)
		}
		assertControlBytesV1(t, "relay ack open sealed body", sealed[:operationAckBodyBytesV1], ackBody[:])
		assertControlBytesV1(t, "relay ack open aad", aad, wantClientAckAAD)
		return append([]byte(nil), sealed[:operationAckBodyBytesV1]...), nil
	}); err != nil || opened != ack {
		t.Fatalf("relay open of client ack: opened=%+v err=%v", opened, err)
	}
	if clientAckOpenCalls != 1 {
		t.Fatalf("client ack open calls=%d want 1", clientAckOpenCalls)
	}
	wrongCalls := 0
	if _, err := (ClientControlCodecV1{}).OpenOperationAckV1(context, clientAck, func(uint64, uint64, []byte, []byte) ([]byte, error) {
		wrongCalls++
		return nil, nil
	}); !errors.Is(err, ErrRecordInvalid) || wrongCalls != 0 {
		t.Fatalf("same-role client ack got %v calls=%d", err, wrongCalls)
	}

	const relayCloseEpoch uint64 = 0x4142434445464748
	const relayCloseSequence uint64 = 0x5152535455565758
	relayClose, err := (RelayControlCodecV1{}).SealCloseV1(context, relayCloseEpoch, relayCloseSequence, closeValue, seal)
	if err != nil {
		t.Fatal(err)
	}
	relayHeader, _, err := parseControlRecordV1(relayClose, controlDirectionRelayV1, RecordTypeCloseV1)
	wantRelayCloseHeader := ControlHeaderV1{
		Version: ControlRecordVersionV1, Type: RecordTypeCloseV1,
		Epoch: relayCloseEpoch, Direction: controlDirectionRelayV1,
		Sequence: relayCloseSequence, SealedLength: closeSealedBytesV1,
	}
	if err != nil || relayHeader != wantRelayCloseHeader {
		t.Fatalf("relay direction mismatch: header=%+v err=%v", relayHeader, err)
	}
	if opened, err := (ClientControlCodecV1{}).OpenCloseV1(context, relayClose, open); err != nil || opened != closeValue {
		t.Fatalf("client open of relay close: opened=%+v err=%v", opened, err)
	}

	const clientCloseEpoch uint64 = 0x2122232425262728
	const clientCloseSequence uint64 = 0x3132333435363738
	wantClientCloseAAD := independentControlAADV1(
		context, RecordTypeCloseV1, clientCloseEpoch,
		controlDirectionClientV1, clientCloseSequence, closeSealedBytesV1,
	)
	clientCloseSealCalls := 0
	clientClose, err := (ClientControlCodecV1{}).SealCloseV1(context, clientCloseEpoch, clientCloseSequence, closeValue, func(epoch, sequence uint64, plaintext, aad []byte) ([]byte, error) {
		clientCloseSealCalls++
		if epoch != clientCloseEpoch || sequence != clientCloseSequence {
			t.Fatalf("client close seal metadata mismatch: epoch=%x sequence=%x", epoch, sequence)
		}
		assertControlBytesV1(t, "client close seal body", plaintext, closeBody[:])
		assertControlBytesV1(t, "client close seal aad", aad, wantClientCloseAAD)
		return append(append([]byte(nil), plaintext...), make([]byte, 16)...), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if clientCloseSealCalls != 1 {
		t.Fatalf("client close seal calls=%d want 1", clientCloseSealCalls)
	}
	clientCloseHeader, _, err := parseControlRecordV1(clientClose, controlDirectionClientV1, RecordTypeCloseV1)
	wantClientCloseHeader := ControlHeaderV1{
		Version: ControlRecordVersionV1, Type: RecordTypeCloseV1,
		Epoch: clientCloseEpoch, Direction: controlDirectionClientV1,
		Sequence: clientCloseSequence, SealedLength: closeSealedBytesV1,
	}
	if err != nil || clientCloseHeader != wantClientCloseHeader {
		t.Fatalf("client close header mismatch: header=%+v err=%v", clientCloseHeader, err)
	}
	clientCloseOpenCalls := 0
	if opened, err := (RelayControlCodecV1{}).OpenCloseV1(context, clientClose, func(epoch, sequence uint64, sealed, aad []byte) ([]byte, error) {
		clientCloseOpenCalls++
		if epoch != clientCloseEpoch || sequence != clientCloseSequence {
			t.Fatalf("relay close open metadata mismatch: epoch=%x sequence=%x", epoch, sequence)
		}
		if len(sealed) != closeSealedBytesV1 {
			t.Fatalf("relay close open sealed length=%d want %d", len(sealed), closeSealedBytesV1)
		}
		assertControlBytesV1(t, "relay close open sealed body", sealed[:closeBodyBytesV1], closeBody[:])
		assertControlBytesV1(t, "relay close open aad", aad, wantClientCloseAAD)
		return append([]byte(nil), sealed[:closeBodyBytesV1]...), nil
	}); err != nil || opened != closeValue {
		t.Fatalf("relay open of client close: opened=%+v err=%v", opened, err)
	}
	if clientCloseOpenCalls != 1 {
		t.Fatalf("client close open calls=%d want 1", clientCloseOpenCalls)
	}

	const relayAckEpoch uint64 = 0x6162636465666768
	const relayAckSequence uint64 = 0x7172737475767778
	relayAck, err := (RelayControlCodecV1{}).SealOperationAckV1(context, relayAckEpoch, relayAckSequence, ack, seal)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := (ClientControlCodecV1{}).OpenOperationAckV1(context, relayAck, open); err != nil || opened != ack {
		t.Fatalf("client open of relay ack: opened=%+v err=%v", opened, err)
	}
}

func TestControlRecordV1FailuresAreNormalized(t *testing.T) {
	context := controlVectorContextV1()
	validAck := OperationAckV1{OperationID: controlVectorOperationIDV1(), CompletedCount: 1}
	validClose := CloseV1{Code: CloseCodeTerminalV1}
	calls := 0
	seal := func(uint64, uint64, []byte, []byte) ([]byte, error) {
		calls++
		return make([]byte, operationAckSealedBytesV1), nil
	}
	if _, err := (ClientControlCodecV1{}).SealOperationAckV1(context, 1, 1, OperationAckV1{CompletedCount: 1}, seal); !errors.Is(err, ErrOperationAckInvalid) || calls != 0 {
		t.Fatalf("zero operation ID got %v calls=%d", err, calls)
	}
	if _, err := (ClientControlCodecV1{}).SealOperationAckV1(context, 1, 1, OperationAckV1{OperationID: validAck.OperationID}, seal); !errors.Is(err, ErrOperationAckInvalid) || calls != 0 {
		t.Fatalf("zero completed count got %v calls=%d", err, calls)
	}
	if _, err := (ClientControlCodecV1{}).SealCloseV1(context, 1, 1, CloseV1{}, seal); !errors.Is(err, ErrRecordInvalid) || calls != 0 {
		t.Fatalf("zero close code got %v calls=%d", err, calls)
	}
	if _, err := (ClientControlCodecV1{}).SealCloseV1(context, 1, 1, CloseV1{Code: 2}, seal); !errors.Is(err, ErrRecordInvalid) || calls != 0 {
		t.Fatalf("unknown close code got %v calls=%d", err, calls)
	}
	if _, err := (ClientControlCodecV1{}).SealOperationAckV1(context, 1, 1, validAck, nil); !errors.Is(err, ErrRecordInvalid) {
		t.Fatalf("nil seal got %v", err)
	}
	if _, err := (ClientControlCodecV1{}).SealCloseV1(context, 1, 1, validClose, func(uint64, uint64, []byte, []byte) ([]byte, error) {
		return nil, errors.New("secret raw seal cause")
	}); !errors.Is(err, ErrRecordInvalid) || strings.Contains(err.Error(), "secret") || err.Error() != "record_invalid" {
		t.Fatalf("seal error was not normalized: %v", err)
	}
	if record, err := (ClientControlCodecV1{}).SealCloseV1(context, 1, 1, validClose, func(uint64, uint64, []byte, []byte) ([]byte, error) {
		return make([]byte, closeSealedBytesV1), errors.New("secret correct-length seal cause")
	}); err != ErrRecordInvalid || record != nil || strings.Contains(err.Error(), "secret") || err.Error() != "record_invalid" {
		t.Fatalf("correct-length seal error was not honored: record=%x err=%v", record, err)
	}
	if record, err := (ClientControlCodecV1{}).SealCloseV1(context, 1, 1, validClose, func(uint64, uint64, []byte, []byte) ([]byte, error) {
		return make([]byte, closeSealedBytesV1-1), nil
	}); err != ErrRecordInvalid || record != nil {
		t.Fatalf("short close sealed length got record=%x err=%v", record, err)
	}
	if record, err := (ClientControlCodecV1{}).SealCloseV1(context, 1, 1, validClose, func(uint64, uint64, []byte, []byte) ([]byte, error) {
		return make([]byte, closeSealedBytesV1+1), nil
	}); err != ErrRecordInvalid || record != nil {
		t.Fatalf("oversized close sealed length got record=%x err=%v", record, err)
	}
	if record, err := (ClientControlCodecV1{}).SealOperationAckV1(context, 1, 1, validAck, func(uint64, uint64, []byte, []byte) ([]byte, error) {
		return make([]byte, operationAckSealedBytesV1-1), nil
	}); err != ErrRecordInvalid || record != nil {
		t.Fatalf("short ack sealed length got record=%x err=%v", record, err)
	}
	if record, err := (ClientControlCodecV1{}).SealOperationAckV1(context, 1, 1, validAck, func(uint64, uint64, []byte, []byte) ([]byte, error) {
		return make([]byte, operationAckSealedBytesV1+1), nil
	}); err != ErrRecordInvalid || record != nil {
		t.Fatalf("oversized ack sealed length got record=%x err=%v", record, err)
	}

	record := mustControlHexV1(t, operationAckRecordV1)
	if _, err := (ClientControlCodecV1{}).OpenOperationAckV1(context, record, nil); !errors.Is(err, ErrRecordInvalid) {
		t.Fatalf("nil open got %v", err)
	}
	if _, err := (ClientControlCodecV1{}).OpenOperationAckV1(context, record, func(uint64, uint64, []byte, []byte) ([]byte, error) {
		return nil, errors.New("secret raw open cause")
	}); !errors.Is(err, ErrRecordInvalid) || strings.Contains(err.Error(), "secret") || err.Error() != "record_invalid" {
		t.Fatalf("open error was not normalized: %v", err)
	}
	closeRecord := mustControlHexV1(t, closeRecordVectorV1)
	if opened, err := (ClientControlCodecV1{}).OpenCloseV1(context, closeRecord, nil); err != ErrRecordInvalid || opened != (CloseV1{}) {
		t.Fatalf("nil close open got opened=%+v err=%v", opened, err)
	}
	if opened, err := (ClientControlCodecV1{}).OpenCloseV1(context, closeRecord, func(uint64, uint64, []byte, []byte) ([]byte, error) {
		return mustControlHexV1(t, closeBodyVectorV1), errors.New("secret raw close open cause")
	}); err != ErrRecordInvalid || opened != (CloseV1{}) || strings.Contains(err.Error(), "secret") || err.Error() != "record_invalid" {
		t.Fatalf("close open error was not honored: opened=%+v err=%v", opened, err)
	}
	if !errors.Is(ErrRecordInvalid, ErrRecordInvalid) || !errors.Is(ErrOperationAckInvalid, ErrOperationAckInvalid) || errors.Is(ErrRecordInvalid, ErrOperationAckInvalid) || errors.Is(ErrOperationAckInvalid, ErrRecordInvalid) {
		t.Fatal("control sentinels have unsafe errors.Is behavior")
	}
}

func TestControlRecordV1APIStateScan(t *testing.T) {
	for _, codec := range []reflect.Type{reflect.TypeOf(ClientControlCodecV1{}), reflect.TypeOf(RelayControlCodecV1{})} {
		if codec.NumField() != 0 || codec.Size() != 0 {
			t.Fatalf("codec %s unexpectedly owns state", codec)
		}
		for i := 0; i < codec.NumMethod(); i++ {
			method := codec.Method(i)
			for param := 1; param < method.Type.NumIn(); param++ {
				typ := method.Type.In(param)
				if typ.Kind() == reflect.Uint16 || typ == reflect.TypeOf(ControlHeaderV1{}) || strings.Contains(typ.String(), "Nonce") {
					t.Fatalf("exported method %s exposes direction, header, nonce, or slot selection through %s", method.Name, typ)
				}
			}
		}
	}
	for _, callback := range []reflect.Type{reflect.TypeOf(ControlSealV1(nil)), reflect.TypeOf(ControlOpenV1(nil))} {
		if callback.NumIn() != 4 || callback.In(0).Kind() != reflect.Uint64 || callback.In(1).Kind() != reflect.Uint64 || callback.In(2) != reflect.TypeOf([]byte(nil)) || callback.In(3) != reflect.TypeOf([]byte(nil)) {
			t.Fatalf("callback API exposes unexpected control operands: %s", callback)
		}
	}
}

func controlVectorContextV1() ControlContextV1 {
	var context ControlContextV1
	for i := range context.EffectivePolicyHash {
		context.EffectivePolicyHash[i] = byte(0x20 + i)
		context.TH4[i] = byte(i)
	}
	return context
}

func controlVectorOperationIDV1() [32]byte {
	encoded, err := hex.DecodeString("cde482ac3912a60bdba0c2a0ecebc0335cf2850833d7f2e9d502e2fe798ffd34")
	if err != nil {
		panic(err)
	}
	var operationID [32]byte
	copy(operationID[:], encoded)
	return operationID
}

func controlVectorAEADV1(t *testing.T) cipher.AEAD {
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

func controlVectorNonceV1(sequence uint64) [12]byte {
	var nonce [12]byte
	copy(nonce[:4], []byte{0xa0, 0xa1, 0xa2, 0xa3})
	binary.BigEndian.PutUint64(nonce[4:], sequence)
	return nonce
}

func independentControlAADV1(context ControlContextV1, recordType uint16, epoch uint64, direction uint16, sequence uint64, sealedLength uint32) []byte {
	out := make([]byte, controlAADBytesV1)
	binary.BigEndian.PutUint16(out[0:2], ControlRecordVersionV1)
	binary.BigEndian.PutUint16(out[2:4], recordType)
	copy(out[4:36], context.EffectivePolicyHash[:])
	copy(out[36:68], context.TH4[:])
	binary.BigEndian.PutUint64(out[68:76], epoch)
	binary.BigEndian.PutUint16(out[76:78], direction)
	binary.BigEndian.PutUint64(out[78:86], sequence)
	binary.BigEndian.PutUint32(out[86:90], sealedLength)
	return out
}

func mustControlHexV1(t *testing.T, encoded string) []byte {
	t.Helper()
	out, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertControlBytesV1(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch:\n got %x\nwant %x", name, got, want)
	}
}

func assertControlDigestV1(t *testing.T, name string, value []byte, want string) {
	t.Helper()
	got := sha256.Sum256(value)
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("%s sha256=%x want %s", name, got, want)
	}
}

func mutateControlU16V1(source []byte, offset int, value uint16) []byte {
	out := append([]byte(nil), source...)
	binary.BigEndian.PutUint16(out[offset:offset+2], value)
	return out
}

func mutateControlU32V1(source []byte, offset int, value uint32) []byte {
	out := append([]byte(nil), source...)
	binary.BigEndian.PutUint32(out[offset:offset+4], value)
	return out
}

func mutateControlU64V1(source []byte, offset int, value uint64) []byte {
	out := append([]byte(nil), source...)
	binary.BigEndian.PutUint64(out[offset:offset+8], value)
	return out
}
