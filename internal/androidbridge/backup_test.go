// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"testing"

	"kurdistan/internal/product/backup"
)

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
