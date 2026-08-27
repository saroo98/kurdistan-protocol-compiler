// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"encoding/hex"
	"testing"

	"kurdistan/internal/product/backup"
)

func TestBackupPreviewRejectsInconsistentCountsAndUnknownKinds(t *testing.T) {
	for _, preview := range []backup.Preview{
		{Version: backup.Version, RecordCount: 1, KindCounts: map[backup.RecordKind]int{}},
		{Version: backup.Version, RecordCount: 0, KindCounts: map[backup.RecordKind]int{99: 0}},
	} {
		if _, err := encodeBackupPreview(preview); err == nil {
			t.Fatal("inconsistent preview accepted")
		}
	}
}

func TestBackupOpenWithoutHandleOwnerDoesNotReturnPreview(t *testing.T) {
	encoded, err := backup.CreateWithRandom(bytes.NewReader(bytes.Repeat([]byte{3}, 28)), "correct horse battery staple", backup.Payload{Version: 2})
	if err != nil {
		t.Fatal(err)
	}
	handle, preview, code := BackupOpenPreview(nil, encoded, []byte("correct horse battery staple"))
	if handle != 0 || code != CodeInvalidArgument || preview != nil {
		t.Fatal("failed ownership transfer returned output")
	}
}

func TestBackupBridgeRecipientV2SharedGoldenAndMalformedBounds(t *testing.T) {
	const golden = "4b42503200020100000000000000010161000000017803000000000000000011726563697069656e742d6b6579732d7633000000224b434b330301016b0400000000000000010000000000000002010161000101000102"
	wire, err := hex.DecodeString(golden)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := DecodeBackupPayload(wire)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyBackupPayload(&payload)
	canonical, err := EncodeBackupPayload(payload)
	if err != nil || !bytes.Equal(canonical, wire) {
		t.Fatal("shared Go/Kotlin key golden changed")
	}
	defer clear(canonical)
	for length := 0; length < len(wire); length++ {
		if _, err := DecodeBackupPayload(wire[:length]); err == nil {
			t.Fatalf("truncation %d accepted", length)
		}
	}
	for _, offset := range []int{4, 16, 17, 18, 19, 50, 51, 52, 53} {
		mutated := bytes.Clone(wire)
		mutated[offset] = 0xff
		if _, err := DecodeBackupPayload(mutated); err == nil {
			t.Fatalf("bound mutation %d accepted", offset)
		}
	}
}

func TestBackupBridgeV2CanonicalAndUnknownVersionRejection(t *testing.T) {
	payload := backup.Payload{Version: 2, Records: []backup.Record{{Kind: backup.RecordNativeProfile, LocalID: "a", Generation: 1, ExactBytes: []byte("x")}}}
	raw, err := EncodeBackupPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(raw) != "4b425032000101000000000000000101610000000178" {
		t.Fatalf("unexpected v2 wire %x", raw)
	}
	restored, err := DecodeBackupPayload(raw)
	if err != nil || restored.Version != 2 {
		t.Fatalf("version changed: %d %v", restored.Version, err)
	}
	raw[3] = '3'
	if _, err := DecodeBackupPayload(raw); err == nil {
		t.Fatal("unknown bridge version accepted")
	}
}

type acceptBackupRecords struct{}

func (acceptBackupRecords) VerifyBackupRecord(record backup.Record) error { return nil }

func TestBackupBridgePreviewBindingAndRestore(t *testing.T) {
	payload := backup.Payload{
		Version: 1,
		Records: []backup.Record{{
			Kind:       backup.RecordNativeProfile,
			LocalID:    "8e40d21c-8fd7-4a3f-b582-7feff8ef8c4d",
			Generation: 7,
			ExactBytes: []byte("bounded fixture"),
		}},
	}
	wire, err := EncodeBackupPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, code := BackupCreate(wire, []byte("correct horse battery staple"))
	if code != CodeOK {
		t.Fatalf("create code=%v", code)
	}
	var registry HandleRegistry
	handle, preview, code := BackupOpenPreview(
		&registry,
		encoded,
		[]byte("correct horse battery staple"),
	)
	if code != CodeOK {
		t.Fatalf("open code=%v", code)
	}
	mutated := append([]byte(nil), preview...)
	mutated[len(mutated)-1] ^= 1
	if _, code := BackupRestore(&registry, handle, mutated, acceptBackupRecords{}); code == CodeOK {
		t.Fatal("mutated preview accepted")
	}
	restored, code := BackupRestore(&registry, handle, preview, acceptBackupRecords{})
	if code != CodeOK {
		t.Fatalf("restore code=%v", code)
	}
	decoded, err := DecodeBackupPayload(restored)
	if err != nil || len(decoded.Records) != 1 ||
		string(decoded.Records[0].ExactBytes) != "bounded fixture" {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
}
