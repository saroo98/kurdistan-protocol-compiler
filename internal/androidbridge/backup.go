// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"encoding/binary"
	"errors"

	"kurdistan/internal/product/backup"
)

const (
	backupPayloadMagic = "KBP1"
	backupPreviewMagic = "KBV1"
)

type BackupEnvironment interface {
	backup.RestoreVerifier
}

type backupHandle struct {
	opened  backup.Opened
	preview backup.Preview
}

func (state *backupHandle) Destroy() {
	if state == nil {
		return
	}
	state.opened.Destroy()
	state.preview = backup.Preview{}
}

func EncodeBackupPayload(payload backup.Payload) ([]byte, error) {
	if err := backup.ValidatePayload(payload); err != nil {
		return nil, backup.ErrInvalidPayload
	}
	size := 4 + 2
	for _, record := range payload.Records {
		if len(record.LocalID) == 0 || len(record.LocalID) > 128 ||
			len(record.ExactBytes) == 0 || len(record.ExactBytes) > backup.MaxPayloadBytes {
			return nil, backup.ErrInvalidPayload
		}
		size += 1 + 8 + 1 + len(record.LocalID) + 4 + len(record.ExactBytes)
	}
	if size > backup.MaxPayloadBytes {
		return nil, backup.ErrInvalidPayload
	}
	out := make([]byte, size)
	copy(out[:4], backupPayloadMagic)
	if payload.Version == 2 {
		copy(out[:4], "KBP2")
	}
	binary.BigEndian.PutUint16(out[4:6], uint16(len(payload.Records)))
	offset := 6
	for _, record := range payload.Records {
		out[offset] = byte(record.Kind)
		offset++
		binary.BigEndian.PutUint64(out[offset:offset+8], record.Generation)
		offset += 8
		out[offset] = byte(len(record.LocalID))
		offset++
		copy(out[offset:], record.LocalID)
		offset += len(record.LocalID)
		binary.BigEndian.PutUint32(out[offset:offset+4], uint32(len(record.ExactBytes)))
		offset += 4
		copy(out[offset:], record.ExactBytes)
		offset += len(record.ExactBytes)
	}
	return out, nil
}

func DecodeBackupPayload(encoded []byte) (backup.Payload, error) {
	if len(encoded) < 6 || len(encoded) > backup.MaxPayloadBytes ||
		(string(encoded[:4]) != backupPayloadMagic && string(encoded[:4]) != "KBP2") {
		return backup.Payload{}, backup.ErrInvalidPayload
	}
	count := int(binary.BigEndian.Uint16(encoded[4:6]))
	if count > backup.MaxRecords {
		return backup.Payload{}, backup.ErrInvalidPayload
	}
	payload := backup.Payload{Version: 1, Records: make([]backup.Record, count)}
	if string(encoded[:4]) == "KBP2" {
		payload.Version = 2
	}
	valid := false
	defer func() {
		if !valid {
			destroyBackupPayload(&payload)
		}
	}()
	offset := 6
	for index := range payload.Records {
		if offset+14 > len(encoded) {
			return backup.Payload{}, backup.ErrInvalidPayload
		}
		kind := backup.RecordKind(encoded[offset])
		offset++
		generation := binary.BigEndian.Uint64(encoded[offset : offset+8])
		offset += 8
		idLength := int(encoded[offset])
		offset++
		if idLength == 0 || idLength > 128 || offset+idLength+4 > len(encoded) {
			return backup.Payload{}, backup.ErrInvalidPayload
		}
		localID := string(encoded[offset : offset+idLength])
		offset += idLength
		byteLength := uint64(binary.BigEndian.Uint32(encoded[offset : offset+4]))
		offset += 4
		if byteLength == 0 || byteLength > backup.MaxPayloadBytes || byteLength > uint64(len(encoded)-offset) {
			return backup.Payload{}, backup.ErrInvalidPayload
		}
		payload.Records[index] = backup.Record{
			Kind:       kind,
			LocalID:    localID,
			Generation: generation,
			ExactBytes: append([]byte(nil), encoded[offset:offset+int(byteLength)]...),
		}
		offset += int(byteLength)
	}
	if offset != len(encoded) {
		return backup.Payload{}, backup.ErrInvalidPayload
	}
	canonical, err := EncodeBackupPayload(payload)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return backup.Payload{}, backup.ErrInvalidPayload
	}
	valid = true
	return payload, nil
}

func BackupCreate(encodedPayload, passphrase []byte) ([]byte, ErrorCode) {
	payload, err := DecodeBackupPayload(encodedPayload)
	if err != nil {
		return nil, CodeInvalidArgument
	}
	defer destroyBackupPayload(&payload)
	encoded, err := backup.Create(string(passphrase), payload)
	if err != nil {
		if errors.Is(err, backup.ErrInvalidPassphrase) {
			return nil, CodeInvalidArgument
		}
		return nil, CodeInternalFailure
	}
	return encoded, CodeOK
}

func BackupOpenPreview(registry *HandleRegistry, encodedBackup, passphrase []byte) (Handle, []byte, ErrorCode) {
	opened, preview, err := backup.OpenPreview(string(passphrase), encodedBackup)
	if err != nil {
		if errors.Is(err, backup.ErrResourceLimit) || errors.Is(err, backup.ErrInvalidHeader) {
			return 0, nil, CodePolicyRejected
		}
		return 0, nil, CodeVerificationRejected
	}
	encodedPreview, err := encodeBackupPreview(preview)
	if err != nil {
		opened.Destroy()
		return 0, nil, CodeInternalFailure
	}
	state := &backupHandle{opened: opened, preview: preview}
	handle, code := registry.Open(HandleBackup, state)
	if code != CodeOK {
		state.Destroy()
		clear(encodedPreview)
		return 0, nil, code
	}
	return handle, encodedPreview, code
}

func BackupRestore(registry *HandleRegistry, handle Handle, encodedPreview []byte, environment BackupEnvironment) ([]byte, ErrorCode) {
	if environment == nil {
		return nil, CodeTrustUnavailable
	}
	value, code := registry.Get(handle, HandleBackup)
	if code != CodeOK {
		return nil, code
	}
	state, ok := value.(*backupHandle)
	if !ok {
		return nil, CodeInternalFailure
	}
	preview, err := decodeBackupPreview(encodedPreview)
	if err != nil {
		return nil, CodeInvalidArgument
	}
	payload, err := backup.Restore(state.opened, preview, environment)
	if err != nil {
		return nil, CodeVerificationRejected
	}
	defer destroyBackupPayload(&payload)
	encoded, err := EncodeBackupPayload(payload)
	if err != nil {
		return nil, CodeInternalFailure
	}
	return encoded, CodeOK
}

func destroyBackupPayload(payload *backup.Payload) {
	if payload == nil {
		return
	}
	for index := range payload.Records {
		clear(payload.Records[index].ExactBytes)
		payload.Records[index] = backup.Record{}
	}
	clear(payload.Records)
	payload.Records = nil
	payload.Version = 0
}

func encodeBackupPreview(preview backup.Preview) ([]byte, error) {
	if (preview.Version != backup.Version && preview.Version != backup.LegacyVersion) || preview.RecordCount < 0 || preview.RecordCount > backup.MaxRecords {
		return nil, backup.ErrInvalidPayload
	}
	total := 0
	for kind, count := range preview.KindCounts {
		if kind < backup.RecordNativeProfile || kind > backup.RecordRoutingPreferences || count < 0 || count > backup.MaxRecords {
			return nil, backup.ErrInvalidPayload
		}
		total += count
	}
	if total != preview.RecordCount {
		return nil, backup.ErrInvalidPayload
	}
	out := make([]byte, 4+2+5*2)
	copy(out[:4], backupPreviewMagic)
	if preview.Version == backup.Version {
		copy(out[:4], "KBV2")
	}
	binary.BigEndian.PutUint16(out[4:6], uint16(preview.RecordCount))
	for index := 0; index < 5; index++ {
		count := preview.KindCounts[backup.RecordKind(index+1)]
		if count < 0 || count > backup.MaxRecords {
			return nil, backup.ErrInvalidPayload
		}
		binary.BigEndian.PutUint16(out[6+index*2:8+index*2], uint16(count))
	}
	return out, nil
}

func decodeBackupPreview(encoded []byte) (backup.Preview, error) {
	if len(encoded) != 16 || (string(encoded[:4]) != backupPreviewMagic && string(encoded[:4]) != "KBV2") {
		return backup.Preview{}, backup.ErrInvalidPayload
	}
	preview := backup.Preview{
		Version:     backup.LegacyVersion,
		RecordCount: int(binary.BigEndian.Uint16(encoded[4:6])),
		KindCounts:  make(map[backup.RecordKind]int),
	}
	if string(encoded[:4]) == "KBV2" {
		preview.Version = backup.Version
	}
	total := 0
	for index := 0; index < 5; index++ {
		count := int(binary.BigEndian.Uint16(encoded[6+index*2 : 8+index*2]))
		if count != 0 {
			preview.KindCounts[backup.RecordKind(index+1)] = count
		}
		total += count
	}
	if total != preview.RecordCount || total > backup.MaxRecords {
		return backup.Preview{}, backup.ErrInvalidPayload
	}
	canonical, err := encodeBackupPreview(preview)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return backup.Preview{}, backup.ErrInvalidPayload
	}
	return preview, nil
}
