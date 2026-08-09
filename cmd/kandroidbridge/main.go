// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

/*
#include <stdint.h>
*/
import "C"

import (
	"crypto/rand"
	"runtime/debug"
	"time"
	"unsafe"

	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/backup"
	"kurdistan/internal/product/diagnosticexport"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/profile"
)

var (
	registry              androidbridge.HandleRegistry
	environment           = newBridgeEnvironment()
	runtimeNetworkFactory = newReleaseRuntimeNetworkFactory()
)

func main() {}

func recoverCode(result *C.int32_t) {
	if recover() != nil {
		debug.FreeOSMemory()
		*result = C.int32_t(androidbridge.CodeInternalFailure)
	}
}

func inputBytes(pointer *C.uint8_t, length C.uint32_t, maximum int) ([]byte, androidbridge.ErrorCode) {
	if length == 0 {
		return nil, androidbridge.CodeOK
	}
	if pointer == nil || uint64(length) > uint64(maximum) {
		return nil, androidbridge.CodeSizeLimit
	}
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(pointer)), int(length))...), androidbridge.CodeOK
}

func writeBytes(value []byte, output *C.uint8_t, capacity C.uint32_t, outputLength *C.uint32_t) androidbridge.ErrorCode {
	if outputLength == nil {
		return androidbridge.CodeInvalidArgument
	}
	*outputLength = C.uint32_t(len(value))
	if len(value) == 0 {
		return androidbridge.CodeOK
	}
	if output == nil || uint64(capacity) < uint64(len(value)) {
		return androidbridge.CodeSizeLimit
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(output)), int(capacity)), value)
	return androidbridge.CodeOK
}

//export kvpn_abi_info
func kvpn_abi_info(output *C.uint8_t, capacity C.uint32_t, outputLength *C.uint32_t) (result C.int32_t) {
	defer recoverCode(&result)
	encoded, err := androidbridge.EncodeABIInfo(androidbridge.CurrentABIInfo())
	if err != nil {
		return C.int32_t(androidbridge.CodeInternalFailure)
	}
	return C.int32_t(writeBytes(encoded, output, capacity, outputLength))
}

//export kvpn_verify_preview
func kvpn_verify_preview(
	input *C.uint8_t,
	inputLength C.uint32_t,
	outputHandle *C.uint64_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	if outputHandle == nil || environment == nil {
		return C.int32_t(androidbridge.CodeTrustUnavailable)
	}
	encoded, code := inputBytes(input, inputLength, androidbridge.MaxVerifyRequestBytes)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(encoded)
	handle, preview, code := androidbridge.OpenVerifyPreview(&registry, encoded, environment)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	if code = writeBytes(preview, output, capacity, outputLength); code != androidbridge.CodeOK {
		_ = registry.Free(handle)
		return C.int32_t(code)
	}
	*outputHandle = C.uint64_t(handle)
	return C.int32_t(androidbridge.CodeOK)
}

//export kvpn_recipient_create
func kvpn_recipient_create(validitySeconds C.uint32_t, outputHandle *C.uint64_t) (result C.int32_t) {
	defer recoverCode(&result)
	if outputHandle == nil || validitySeconds == 0 || uint32(validitySeconds) > androidbridge.MaxRecipientValiditySeconds {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	handle, code := androidbridge.CreateRecipient(
		&registry,
		time.Now().UTC(),
		time.Duration(uint32(validitySeconds))*time.Second,
		rand.Reader,
	)
	if code == androidbridge.CodeOK {
		*outputHandle = C.uint64_t(handle)
	}
	return C.int32_t(code)
}

//export kvpn_recipient_request
func kvpn_recipient_request(
	handle C.uint64_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	encoded, code := androidbridge.RecipientRequest(&registry, androidbridge.Handle(handle))
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(encoded)
	return C.int32_t(writeBytes(encoded, output, capacity, outputLength))
}

//export kvpn_recipient_private_export
func kvpn_recipient_private_export(
	handle C.uint64_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	encoded, code := androidbridge.RecipientPrivateExport(&registry, androidbridge.Handle(handle))
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(encoded)
	return C.int32_t(writeBytes(encoded, output, capacity, outputLength))
}

//export kvpn_recipient_validate
func kvpn_recipient_validate(
	recipientRequest *C.uint8_t,
	recipientRequestLength C.uint32_t,
	recipientPrivate *C.uint8_t,
	recipientPrivateLength C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	requestBytes, code := inputBytes(recipientRequest, recipientRequestLength, enrollment.MaxRequestBytes)
	if code != androidbridge.CodeOK || len(requestBytes) == 0 {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	defer clear(requestBytes)
	privateBytes, code := inputBytes(recipientPrivate, recipientPrivateLength, enrollment.MaxPrivateBundleBytes)
	if code != androidbridge.CodeOK || len(privateBytes) == 0 {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	defer clear(privateBytes)
	return C.int32_t(androidbridge.ValidateRecipientCredentialsBytes(requestBytes, privateBytes))
}

//export kvpn_verify_preview_with_recipient
func kvpn_verify_preview_with_recipient(
	input *C.uint8_t,
	inputLength C.uint32_t,
	recipientRequest *C.uint8_t,
	recipientRequestLength C.uint32_t,
	recipientPrivate *C.uint8_t,
	recipientPrivateLength C.uint32_t,
	outputHandle *C.uint64_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	if outputHandle == nil || environment == nil {
		return C.int32_t(androidbridge.CodeTrustUnavailable)
	}
	encoded, code := inputBytes(input, inputLength, androidbridge.MaxVerifyRequestBytes)
	if code != androidbridge.CodeOK || len(encoded) == 0 {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	defer clear(encoded)
	requestBytes, code := inputBytes(recipientRequest, recipientRequestLength, enrollment.MaxRequestBytes)
	if code != androidbridge.CodeOK || len(requestBytes) == 0 {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	defer clear(requestBytes)
	privateBytes, code := inputBytes(recipientPrivate, recipientPrivateLength, enrollment.MaxPrivateBundleBytes)
	if code != androidbridge.CodeOK || len(privateBytes) == 0 {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	defer clear(privateBytes)
	handle, preview, code := androidbridge.OpenVerifyPreviewWithRecipient(
		&registry,
		encoded,
		requestBytes,
		privateBytes,
		environment,
	)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(preview)
	if code = writeBytes(preview, output, capacity, outputLength); code != androidbridge.CodeOK {
		_ = registry.Free(handle)
		return C.int32_t(code)
	}
	*outputHandle = C.uint64_t(handle)
	return C.int32_t(androidbridge.CodeOK)
}

//export kvpn_activation_open
func kvpn_activation_open(verified C.uint64_t, outputHandle *C.uint64_t) (result C.int32_t) {
	defer recoverCode(&result)
	if outputHandle == nil || environment == nil {
		return C.int32_t(androidbridge.CodeTrustUnavailable)
	}
	handle, code := androidbridge.OpenActivation(&registry, androidbridge.Handle(verified), environment)
	if code == androidbridge.CodeOK {
		*outputHandle = C.uint64_t(handle)
	}
	return C.int32_t(code)
}

func encodeActivationKind(kind profile.ActivationCommandKind) (C.uint32_t, bool) {
	switch kind {
	case profile.ActivationCommandSnapshot:
		return 1, true
	case profile.ActivationCommandStageCandidate:
		return 2, true
	case profile.ActivationCommandReopenCandidate:
		return 3, true
	case profile.ActivationCommandMarkActivation:
		return 4, true
	case profile.ActivationCommandCommitMarked:
		return 5, true
	case profile.ActivationCommandFinalizeActivation:
		return 6, true
	case profile.ActivationCommandRecover:
		return 7, true
	case profile.ActivationCommandQuarantine:
		return 8, true
	case androidbridge.ActivationCommandComplete:
		return 9, true
	default:
		return 0, false
	}
}

func decodeActivationKind(kind C.uint32_t) (profile.ActivationCommandKind, bool) {
	switch kind {
	case 1:
		return profile.ActivationCommandSnapshot, true
	case 2:
		return profile.ActivationCommandStageCandidate, true
	case 3:
		return profile.ActivationCommandReopenCandidate, true
	case 4:
		return profile.ActivationCommandMarkActivation, true
	case 5:
		return profile.ActivationCommandCommitMarked, true
	case 6:
		return profile.ActivationCommandFinalizeActivation, true
	case 7:
		return profile.ActivationCommandRecover, true
	case 8:
		return profile.ActivationCommandQuarantine, true
	default:
		return "", false
	}
}

//export kvpn_activation_next
func kvpn_activation_next(
	handle C.uint64_t,
	sequence *C.uint64_t,
	kind *C.uint32_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	if sequence == nil || kind == nil {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	next, code := androidbridge.ActivationNextCommand(&registry, androidbridge.Handle(handle))
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(next.Payload)
	wireKind, ok := encodeActivationKind(next.Kind)
	if !ok {
		return C.int32_t(androidbridge.CodeInternalFailure)
	}
	if code = writeBytes(next.Payload, output, capacity, outputLength); code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	*sequence = C.uint64_t(next.Sequence)
	*kind = wireKind
	return C.int32_t(androidbridge.CodeOK)
}

//export kvpn_activation_submit
func kvpn_activation_submit(
	handle C.uint64_t,
	sequence C.uint64_t,
	kind C.uint32_t,
	storageOK C.uint8_t,
	active *C.uint8_t,
	activeLength C.uint32_t,
	lastKnownGood *C.uint8_t,
	lastKnownGoodLength C.uint32_t,
	reopened *C.uint8_t,
	reopenedLength C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	commandKind, ok := decodeActivationKind(kind)
	if !ok || storageOK > 1 {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	activeBytes, code := inputBytes(active, activeLength, androidbridge.MaxBridgeResultBytes)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(activeBytes)
	lastBytes, code := inputBytes(lastKnownGood, lastKnownGoodLength, androidbridge.MaxBridgeResultBytes)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(lastBytes)
	reopenedBytes, code := inputBytes(reopened, reopenedLength, androidbridge.MaxBridgeResultBytes)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(reopenedBytes)
	return C.int32_t(androidbridge.SubmitActivationCommand(
		&registry,
		androidbridge.Handle(handle),
		uint64(sequence),
		commandKind,
		storageOK == 1,
		activeBytes,
		lastBytes,
		reopenedBytes,
	))
}

//export kvpn_diagnostic_prepare
func kvpn_diagnostic_prepare(
	input *C.uint8_t,
	inputLength C.uint32_t,
	outputHandle *C.uint64_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	if outputHandle == nil {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	encoded, code := inputBytes(input, inputLength, 13+diagnosticexport.MaxEntries*3)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	handle, code := androidbridge.DiagnosticPrepare(&registry, encoded)
	if code == androidbridge.CodeOK {
		*outputHandle = C.uint64_t(handle)
	}
	return C.int32_t(code)
}

//export kvpn_diagnostic_preview
func kvpn_diagnostic_preview(
	handle C.uint64_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	encoded, code := androidbridge.DiagnosticPreview(&registry, androidbridge.Handle(handle))
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	return C.int32_t(writeBytes(encoded, output, capacity, outputLength))
}

//export kvpn_diagnostic_confirm
func kvpn_diagnostic_confirm(
	handle C.uint64_t,
	approved C.uint8_t,
	preview *C.uint8_t,
	previewLength C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	if approved > 1 {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	encoded, code := inputBytes(preview, previewLength, 64)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	return C.int32_t(androidbridge.DiagnosticConfirm(
		&registry,
		androidbridge.Handle(handle),
		approved == 1,
		encoded,
	))
}

//export kvpn_diagnostic_build
func kvpn_diagnostic_build(
	handle C.uint64_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	encoded, code := androidbridge.DiagnosticBuild(&registry, androidbridge.Handle(handle))
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	return C.int32_t(writeBytes(encoded, output, capacity, outputLength))
}

//export kvpn_backup_create
func kvpn_backup_create(
	payload *C.uint8_t,
	payloadLength C.uint32_t,
	passphrase *C.uint8_t,
	passphraseLength C.uint32_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	payloadBytes, code := inputBytes(payload, payloadLength, backup.MaxPayloadBytes)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(payloadBytes)
	passphraseBytes, code := inputBytes(passphrase, passphraseLength, backup.MaximumPassBytes)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(passphraseBytes)
	encoded, code := androidbridge.BackupCreate(payloadBytes, passphraseBytes)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	return C.int32_t(writeBytes(encoded, output, capacity, outputLength))
}

//export kvpn_backup_open_preview
func kvpn_backup_open_preview(
	input *C.uint8_t,
	inputLength C.uint32_t,
	passphrase *C.uint8_t,
	passphraseLength C.uint32_t,
	outputHandle *C.uint64_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	if outputHandle == nil {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	backupBytes, code := inputBytes(input, inputLength, backup.MaxPayloadBytes+128)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(backupBytes)
	passphraseBytes, code := inputBytes(passphrase, passphraseLength, backup.MaximumPassBytes)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(passphraseBytes)
	handle, preview, code := androidbridge.BackupOpenPreview(&registry, backupBytes, passphraseBytes)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	if code = writeBytes(preview, output, capacity, outputLength); code != androidbridge.CodeOK {
		_ = registry.Free(handle)
		return C.int32_t(code)
	}
	*outputHandle = C.uint64_t(handle)
	return C.int32_t(androidbridge.CodeOK)
}

//export kvpn_backup_restore
func kvpn_backup_restore(
	handle C.uint64_t,
	preview *C.uint8_t,
	previewLength C.uint32_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	if environment == nil {
		return C.int32_t(androidbridge.CodeTrustUnavailable)
	}
	previewBytes, code := inputBytes(preview, previewLength, 64)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	encoded, code := androidbridge.BackupRestore(
		&registry,
		androidbridge.Handle(handle),
		previewBytes,
		environment,
	)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	return C.int32_t(writeBytes(encoded, output, capacity, outputLength))
}

//export kvpn_cancel
func kvpn_cancel(handle C.uint64_t) (result C.int32_t) {
	defer recoverCode(&result)
	return C.int32_t(registry.Cancel(androidbridge.Handle(handle)))
}

//export kvpn_free
func kvpn_free(handle C.uint64_t) (result C.int32_t) {
	defer recoverCode(&result)
	return C.int32_t(registry.Free(androidbridge.Handle(handle)))
}

//export kvpn_phase11_roundtrip
func kvpn_phase11_roundtrip(
	input *C.uint8_t,
	inputLength C.uint32_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	encoded, code := inputBytes(input, inputLength, phase11MaximumPayloadBytes)
	if code != androidbridge.CodeOK || len(encoded) == 0 {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	defer clear(encoded)
	roundTripped, code := phase11RoundTrip(encoded)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(roundTripped)
	return C.int32_t(writeBytes(roundTripped, output, capacity, outputLength))
}

//export kvpn_runtime_session_open
func kvpn_runtime_session_open(
	input *C.uint8_t,
	inputLength C.uint32_t,
	outputHandle *C.uint64_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	if outputHandle == nil || environment == nil {
		return C.int32_t(androidbridge.CodeTrustUnavailable)
	}
	encoded, code := inputBytes(input, inputLength, androidbridge.MaxRuntimeOpenBytes)
	if code != androidbridge.CodeOK || len(encoded) == 0 {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	defer clear(encoded)
	handle, snapshot, code := androidbridge.OpenRuntimeSession(&registry, encoded, environment)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	snapshotBytes, err := androidbridge.EncodeRuntimeSessionSnapshot(snapshot)
	if err != nil {
		_ = registry.Free(handle)
		return C.int32_t(androidbridge.CodeInternalFailure)
	}
	if code = writeBytes(snapshotBytes, output, capacity, outputLength); code != androidbridge.CodeOK {
		_ = registry.Free(handle)
		return C.int32_t(code)
	}
	*outputHandle = C.uint64_t(handle)
	return C.int32_t(androidbridge.CodeOK)
}

//export kvpn_runtime_session_roundtrip
func kvpn_runtime_session_roundtrip(
	handle C.uint64_t,
	input *C.uint8_t,
	inputLength C.uint32_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	encoded, code := inputBytes(input, inputLength, androidbridge.MaxRuntimePayloadBytes)
	if code != androidbridge.CodeOK || len(encoded) == 0 {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	defer clear(encoded)
	roundTripped, code := androidbridge.RuntimeSessionRoundTrip(
		&registry,
		androidbridge.Handle(handle),
		encoded,
		phase11RoundTrip,
	)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	defer clear(roundTripped)
	return C.int32_t(writeBytes(roundTripped, output, capacity, outputLength))
}

//export kvpn_runtime_session_open_v2
func kvpn_runtime_session_open_v2(
	input *C.uint8_t,
	inputLength C.uint32_t,
	outputHandle *C.uint64_t,
	output *C.uint8_t,
	capacity C.uint32_t,
	outputLength *C.uint32_t,
) (result C.int32_t) {
	defer recoverCode(&result)
	if outputHandle == nil || environment == nil || runtimeNetworkFactory == nil {
		return C.int32_t(androidbridge.CodeTrustUnavailable)
	}
	encoded, code := inputBytes(input, inputLength, androidbridge.MaxRuntimeOpenV2Bytes)
	if code != androidbridge.CodeOK || len(encoded) == 0 {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	defer clear(encoded)
	handle, snapshot, code := androidbridge.OpenRuntimeSessionV2(
		&registry,
		encoded,
		environment,
		runtimeNetworkFactory,
		time.Now().UTC(),
	)
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	snapshotBytes, err := androidbridge.EncodeRuntimeSessionSnapshotV2(snapshot)
	if err != nil {
		_ = registry.Free(handle)
		return C.int32_t(androidbridge.CodeInternalFailure)
	}
	defer clear(snapshotBytes)
	if code = writeBytes(snapshotBytes, output, capacity, outputLength); code != androidbridge.CodeOK {
		_ = registry.Free(handle)
		return C.int32_t(code)
	}
	*outputHandle = C.uint64_t(handle)
	return C.int32_t(androidbridge.CodeOK)
}

//export kvpn_runtime_socket_prepare
func kvpn_runtime_socket_prepare(handle C.uint64_t, outputFD *C.int32_t) (result C.int32_t) {
	defer recoverCode(&result)
	if outputFD == nil {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	fd, code := androidbridge.RuntimeSocketPrepare(&registry, androidbridge.Handle(handle))
	if code == androidbridge.CodeOK {
		*outputFD = C.int32_t(fd)
	}
	return C.int32_t(code)
}

//export kvpn_runtime_socket_commit_protected
func kvpn_runtime_socket_commit_protected(handle C.uint64_t, protected C.uint8_t) (result C.int32_t) {
	defer recoverCode(&result)
	if protected > 1 {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	return C.int32_t(androidbridge.RuntimeSocketCommitProtected(
		&registry,
		androidbridge.Handle(handle),
		protected == 1,
	))
}

//export kvpn_runtime_tun_attach
func kvpn_runtime_tun_attach(handle C.uint64_t, fd C.int32_t) (result C.int32_t) {
	defer recoverCode(&result)
	if fd < 0 {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	return C.int32_t(androidbridge.RuntimeTUNAttach(&registry, androidbridge.Handle(handle), int(fd)))
}

//export kvpn_runtime_status
func kvpn_runtime_status(handle C.uint64_t, outputState *C.uint32_t) (result C.int32_t) {
	defer recoverCode(&result)
	if outputState == nil {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	state, code := androidbridge.RuntimeStatus(&registry, androidbridge.Handle(handle))
	if code == androidbridge.CodeOK {
		*outputState = C.uint32_t(state)
	}
	return C.int32_t(code)
}

//export kvpn_runtime_diagnostics_v1
func kvpn_runtime_diagnostics_v1(handle C.uint64_t, output *C.uint64_t, outputCount C.uint32_t) (result C.int32_t) {
	defer recoverCode(&result)
	const diagnosticsCount = 13
	if output == nil || outputCount != diagnosticsCount {
		return C.int32_t(androidbridge.CodeInvalidArgument)
	}
	diagnostics, code := androidbridge.RuntimeNetworkDiagnostics(&registry, androidbridge.Handle(handle))
	if code != androidbridge.CodeOK {
		return C.int32_t(code)
	}
	values := [...]uint64{
		diagnostics.TUNPacketsRead,
		diagnostics.OutboundPacketsAccepted,
		diagnostics.CarrierRecordsWritten,
		diagnostics.CarrierRecordsRead,
		diagnostics.AuthenticatedOperations,
		diagnostics.InnerPacketsAccepted,
		diagnostics.InnerPacketsRejected,
		diagnostics.TUNWriteAttempts,
		diagnostics.TUNWriteFailures,
		uint64(diagnostics.TUNWriteFailureCode),
		uint64(diagnostics.TUNWriteErrno),
		diagnostics.TUNPacketsWritten,
		diagnostics.RejectedTUNPackets,
	}
	target := unsafe.Slice(output, diagnosticsCount)
	for index, value := range values {
		target[index] = C.uint64_t(value)
	}
	return C.int32_t(androidbridge.CodeOK)
}

//export kvpn_runtime_stop
func kvpn_runtime_stop(handle C.uint64_t) (result C.int32_t) {
	defer recoverCode(&result)
	return C.int32_t(androidbridge.RuntimeStop(&registry, androidbridge.Handle(handle)))
}
