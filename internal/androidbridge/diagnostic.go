// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"encoding/binary"
	"errors"

	"kurdistan/internal/product/diagnosticexport"
)

const (
	diagnosticRequestMagic = "KDR1"
	diagnosticPreviewMagic = "KDP1"
)

var diagnosticCategories = []diagnosticexport.Category{
	diagnosticexport.CategoryContractVersions,
	diagnosticexport.CategoryProfileLifecycle,
	diagnosticexport.CategoryFallbackSelection,
	diagnosticexport.CategoryRelayAdmission,
	diagnosticexport.CategoryRuntimeDisposition,
	diagnosticexport.CategoryFailureSummary,
}

var diagnosticValues = []diagnosticexport.Value{
	diagnosticexport.ValueSupported,
	diagnosticexport.ValueIncompatible,
	diagnosticexport.ValueUnknown,
	diagnosticexport.ValueAbsent,
	diagnosticexport.ValueAdmitted,
	diagnosticexport.ValueSuperseded,
	diagnosticexport.ValueRevoked,
	diagnosticexport.ValueDisabled,
	diagnosticexport.ValueSelected,
	diagnosticexport.ValueBlocked,
	diagnosticexport.ValueRejected,
	diagnosticexport.ValueEligible,
	diagnosticexport.ValueShutdownRequired,
	diagnosticexport.ValueUnavailable,
	diagnosticexport.ValuePermissionRequired,
	diagnosticexport.ValueProtectedStorageUnavailable,
	diagnosticexport.ValueRoutingUnsafe,
	diagnosticexport.ValueDNSUnsafe,
	diagnosticexport.ValueKillSwitchUnavailable,
	diagnosticexport.ValueProfileNotAdmitted,
	diagnosticexport.ValueFallbackNotSelected,
	diagnosticexport.ValueRelayNotAdmitted,
	diagnosticexport.ValueIncompatibleContract,
	diagnosticexport.ValueMalformedInput,
}

var diagnosticCounts = []diagnosticexport.CountBucket{
	"",
	diagnosticexport.CountZero,
	diagnosticexport.CountOne,
	diagnosticexport.CountFew,
	diagnosticexport.CountMany,
}

type diagnosticHandle struct {
	prepared  diagnosticexport.Prepared
	previewed diagnosticexport.Previewed
	preview   diagnosticexport.Preview
	confirmed diagnosticexport.Confirmed
	stage     uint8
}

func EncodeDiagnosticRequest(request diagnosticexport.Request) ([]byte, error) {
	if len(request.Entries) > diagnosticexport.MaxEntries {
		return nil, diagnosticexport.ErrTooLarge
	}
	out := make([]byte, 4+8+1+len(request.Entries)*3)
	copy(out[:4], diagnosticRequestMagic)
	binary.BigEndian.PutUint64(out[4:12], request.Revision)
	out[12] = byte(len(request.Entries))
	offset := 13
	for _, entry := range request.Entries {
		category, ok := enumIndex(diagnosticCategories, entry.Category)
		if !ok {
			return nil, diagnosticexport.ErrVocabulary
		}
		value, ok := enumIndex(diagnosticValues, entry.Value)
		if !ok {
			return nil, diagnosticexport.ErrVocabulary
		}
		count, ok := enumIndex(diagnosticCounts, entry.Count)
		if !ok {
			return nil, diagnosticexport.ErrCount
		}
		out[offset], out[offset+1], out[offset+2] = byte(category+1), byte(value+1), byte(count)
		offset += 3
	}
	return out, nil
}

func DecodeDiagnosticRequest(encoded []byte) (diagnosticexport.Request, error) {
	if len(encoded) < 13 || string(encoded[:4]) != diagnosticRequestMagic {
		return diagnosticexport.Request{}, diagnosticexport.ErrInvalidRequest
	}
	count := int(encoded[12])
	if count > diagnosticexport.MaxEntries || len(encoded) != 13+count*3 {
		return diagnosticexport.Request{}, diagnosticexport.ErrTooLarge
	}
	request := diagnosticexport.Request{
		Version:       diagnosticexport.Version,
		Revision:      binary.BigEndian.Uint64(encoded[4:12]),
		UserInitiated: true,
		Entries:       make([]diagnosticexport.Entry, count),
	}
	offset := 13
	for index := range request.Entries {
		category := int(encoded[offset]) - 1
		value := int(encoded[offset+1]) - 1
		countIndex := int(encoded[offset+2])
		if category < 0 || category >= len(diagnosticCategories) ||
			value < 0 || value >= len(diagnosticValues) ||
			countIndex < 0 || countIndex >= len(diagnosticCounts) {
			return diagnosticexport.Request{}, diagnosticexport.ErrVocabulary
		}
		request.Entries[index] = diagnosticexport.Entry{
			Category: diagnosticCategories[category],
			Value:    diagnosticValues[value],
			Count:    diagnosticCounts[countIndex],
		}
		offset += 3
	}
	canonical, err := EncodeDiagnosticRequest(request)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return diagnosticexport.Request{}, diagnosticexport.ErrInvalidRequest
	}
	return request, nil
}

func DiagnosticPrepare(registry *HandleRegistry, encoded []byte) (Handle, ErrorCode) {
	request, err := DecodeDiagnosticRequest(encoded)
	if err != nil {
		return 0, CodeInvalidArgument
	}
	prepared, err := diagnosticexport.Prepare(request)
	if err != nil {
		return 0, CodePolicyRejected
	}
	return registry.Open(HandleDiagnostic, &diagnosticHandle{prepared: prepared, stage: 1})
}

func DiagnosticPreview(registry *HandleRegistry, handle Handle) ([]byte, ErrorCode) {
	state, code := getDiagnostic(registry, handle)
	if code != CodeOK {
		return nil, code
	}
	if state.stage != 1 {
		return nil, CodePolicyRejected
	}
	previewed, preview, err := diagnosticexport.PreviewPrepared(state.prepared)
	if err != nil {
		return nil, CodePolicyRejected
	}
	state.previewed, state.preview, state.stage = previewed, preview, 2
	encoded, err := encodeDiagnosticPreview(preview)
	if err != nil {
		return nil, CodeInternalFailure
	}
	return encoded, CodeOK
}

func DiagnosticConfirm(registry *HandleRegistry, handle Handle, approved bool, encodedPreview []byte) ErrorCode {
	state, code := getDiagnostic(registry, handle)
	if code != CodeOK {
		return code
	}
	if state.stage != 2 {
		return CodePolicyRejected
	}
	preview, err := decodeDiagnosticPreview(encodedPreview)
	if err != nil {
		return CodeInvalidArgument
	}
	confirmed, err := diagnosticexport.Confirm(state.previewed, diagnosticexport.Confirmation{
		Approved: approved,
		Version:  diagnosticexport.Version,
		Revision: preview.Revision,
		Preview:  preview,
	})
	if err != nil {
		return CodePolicyRejected
	}
	state.confirmed, state.stage = confirmed, 3
	return CodeOK
}

func DiagnosticBuild(registry *HandleRegistry, handle Handle) ([]byte, ErrorCode) {
	state, code := getDiagnostic(registry, handle)
	if code != CodeOK {
		return nil, code
	}
	if state.stage != 3 {
		return nil, CodePolicyRejected
	}
	bundle, err := diagnosticexport.Build(state.confirmed)
	if err != nil {
		return nil, CodePolicyRejected
	}
	state.stage = 4
	return append([]byte(nil), bundle.Bytes...), CodeOK
}

func getDiagnostic(registry *HandleRegistry, handle Handle) (*diagnosticHandle, ErrorCode) {
	value, code := registry.Get(handle, HandleDiagnostic)
	if code != CodeOK {
		return nil, code
	}
	state, ok := value.(*diagnosticHandle)
	if !ok {
		return nil, CodeInternalFailure
	}
	return state, CodeOK
}

func encodeDiagnosticPreview(preview diagnosticexport.Preview) ([]byte, error) {
	var mask byte
	for _, category := range preview.Categories {
		index, ok := enumIndex(diagnosticCategories, category)
		if !ok {
			return nil, errors.New("androidbridge: unknown diagnostic category")
		}
		mask |= 1 << index
	}
	total, ok := enumIndex(diagnosticCounts, preview.TotalEntries)
	if !ok || total == 0 {
		return nil, errors.New("androidbridge: invalid diagnostic count")
	}
	var size byte
	switch preview.EncodedSize {
	case diagnosticexport.SizeSmall:
		size = 1
	case diagnosticexport.SizeMaximum:
		size = 2
	default:
		return nil, errors.New("androidbridge: invalid diagnostic size")
	}
	out := make([]byte, 15)
	copy(out[:4], diagnosticPreviewMagic)
	binary.BigEndian.PutUint64(out[4:12], preview.Revision)
	out[12], out[13], out[14] = mask, byte(total), size
	return out, nil
}

func decodeDiagnosticPreview(encoded []byte) (diagnosticexport.Preview, error) {
	if len(encoded) != 15 || string(encoded[:4]) != diagnosticPreviewMagic {
		return diagnosticexport.Preview{}, errors.New("androidbridge: invalid diagnostic preview")
	}
	preview := diagnosticexport.Preview{
		Version:  diagnosticexport.Version,
		Revision: binary.BigEndian.Uint64(encoded[4:12]),
	}
	for index, category := range diagnosticCategories {
		if encoded[12]&(1<<index) != 0 {
			preview.Categories = append(preview.Categories, category)
		}
	}
	countIndex := int(encoded[13])
	if countIndex <= 0 || countIndex >= len(diagnosticCounts) {
		return diagnosticexport.Preview{}, errors.New("androidbridge: invalid diagnostic count")
	}
	preview.TotalEntries = diagnosticCounts[countIndex]
	switch encoded[14] {
	case 1:
		preview.EncodedSize = diagnosticexport.SizeSmall
	case 2:
		preview.EncodedSize = diagnosticexport.SizeMaximum
	default:
		return diagnosticexport.Preview{}, errors.New("androidbridge: invalid diagnostic size")
	}
	canonical, err := encodeDiagnosticPreview(preview)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return diagnosticexport.Preview{}, errors.New("androidbridge: non-canonical diagnostic preview")
	}
	return preview, nil
}

func enumIndex[T comparable](values []T, wanted T) (int, bool) {
	for index, value := range values {
		if value == wanted {
			return index, true
		}
	}
	return 0, false
}
