// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.nativeapi

import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.RedactedProfilePreview

data class NativeCompatibility(
    val bridgeVersion: String,
    val goCoreVersion: String,
    val profileSchema: String,
    val strategyRegistry: String,
    val relaySchema: String,
    val diagnosticSchema: String,
    val cryptoSuite: Int,
    val maxInputBytes: Int,
    val maxQrChunks: Int,
    val maxQrChunkChars: Int,
    val maxResultBytes: Int,
    val maxConcurrentHandles: Int,
)

data class VerifiedPreviewHandle(
    val handle: Long,
    val preview: RedactedProfilePreview,
)

data class DiagnosticPreviewHandle(
    val handle: Long,
    val previewBytes: ByteArray,
)

data class BackupPreviewHandle(
    val handle: Long,
    val previewBytes: ByteArray,
)

data class ActivationCommand(
    val sequence: Long,
    val kind: ActivationCommandKind,
    val opaqueRecord: ByteArray = byteArrayOf(),
)

enum class ActivationCommandKind {
    SNAPSHOT,
    STAGE_CANDIDATE,
    REOPEN_CANDIDATE,
    MARK_ACTIVATION,
    COMMIT_MARKED,
    FINALIZE_ACTIVATION,
    RECOVER,
    QUARANTINE,
    COMPLETE,
}

sealed interface NativeResult<out T> {
    data class Success<T>(val value: T) : NativeResult<T>
    data class Failure(val error: OperationError) : NativeResult<Nothing>
}

interface NativeActivationSession : AutoCloseable {
    fun next(): NativeResult<ActivationCommand>

    fun submit(
        command: ActivationCommand,
        storageSucceeded: Boolean,
        active: ByteArray = byteArrayOf(),
        lastKnownGood: ByteArray = byteArrayOf(),
        reopened: ByteArray = byteArrayOf(),
    ): NativeResult<Unit>

    fun cancel(): NativeResult<Unit>
}

interface KurdNativeCore {
    fun compatibility(): NativeResult<NativeCompatibility>
    fun verifyPreview(request: ByteArray): NativeResult<VerifiedPreviewHandle>
    fun openActivation(verified: VerifiedPreviewHandle): NativeResult<NativeActivationSession>
    fun releaseVerified(verified: VerifiedPreviewHandle): NativeResult<Unit>
    fun prepareDiagnostic(request: ByteArray): NativeResult<DiagnosticPreviewHandle>
    fun confirmAndBuildDiagnostic(preview: DiagnosticPreviewHandle): NativeResult<ByteArray>
    fun createBackup(payload: ByteArray, passphrase: ByteArray): NativeResult<ByteArray>
    fun openBackup(backup: ByteArray, passphrase: ByteArray): NativeResult<BackupPreviewHandle>
    fun restoreBackup(preview: BackupPreviewHandle): NativeResult<ByteArray>
    fun phase11RoundTrip(payload: ByteArray): NativeResult<ByteArray>
    fun releaseDiagnostic(preview: DiagnosticPreviewHandle): NativeResult<Unit>
    fun releaseBackup(preview: BackupPreviewHandle): NativeResult<Unit>
}
