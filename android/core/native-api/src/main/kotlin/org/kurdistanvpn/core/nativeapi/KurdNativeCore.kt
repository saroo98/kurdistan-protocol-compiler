// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.nativeapi

import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.RedactedProfilePreview
import org.kurdistanvpn.core.model.DnsMode
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.model.SelectionMode

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

data class NativeRuntimeSessionSnapshot(
    val generation: Long,
    val planDigest: ByteArray,
    val profileFingerprint: ByteArray,
    val strategyFingerprint: ByteArray,
    val relayFingerprint: ByteArray,
    val selectionMode: SelectionMode,
    val perAppMode: PerAppSelectionMode,
    val packages: List<String>,
    val ipMode: IpMode,
    val dnsMode: DnsMode,
    val mtu: Int,
    val metered: Boolean,
    val loopbackOnly: Boolean,
)

data class NativeRoute(
    val address: ByteArray,
    val prefixLength: Int,
)

enum class NativePayloadProtocol { ICMP, ICMPV6, TCP, UDP }

enum class NativeRuntimeState {
    VERIFIED,
    SOCKET_PREPARED,
    SOCKET_PROTECTED_COMMITTED,
    TLS_AUTHENTICATED,
    KURD_AUTHENTICATED,
    TUN_ATTACHED,
    RUNNING,
    STOPPING,
    CLOSED,
}

data class NativeLiveRuntimeSessionSnapshot(
    val generation: Long,
    val planDigest: ByteArray,
    val profileFingerprint: ByteArray,
    val strategyFingerprint: ByteArray,
    val relayFingerprint: ByteArray,
    val selectionMode: SelectionMode,
    val perAppMode: PerAppSelectionMode,
    val packages: List<String>,
    val ipMode: IpMode,
    val dnsMode: DnsMode,
    val mtu: Int,
    val metered: Boolean,
    val clientIpv4: ByteArray,
    val dnsIpv4: ByteArray,
    val clientIpv6: ByteArray,
    val dnsIpv6: ByteArray,
    val routes: List<NativeRoute>,
    val payloadProtocols: Set<NativePayloadProtocol>,
    val maxQueuePackets: Int,
    val maxIncompleteOperations: Int,
    val maxReconnectAttempts: Int,
    val dialTimeoutMillis: Long,
    val idleTimeoutMillis: Long,
)

interface NativeRecipient : AutoCloseable {
    fun publicRequest(): NativeResult<ByteArray>
    fun privateBundle(): NativeResult<ByteArray>
    fun cancel(): NativeResult<Unit>
}

interface NativeLiveRuntimeSession : AutoCloseable {
    val snapshot: NativeLiveRuntimeSessionSnapshot
    fun prepareSocket(): NativeResult<Int>
    fun commitProtected(protectedSocket: Boolean): NativeResult<Unit>
    fun attachTun(fileDescriptor: Int): NativeResult<Unit>
    fun status(): NativeResult<NativeRuntimeState>
    fun stop(): NativeResult<Unit>
}

interface NativeRuntimeSession : AutoCloseable {
    val snapshot: NativeRuntimeSessionSnapshot
    fun roundTrip(payload: ByteArray): NativeResult<ByteArray>
    fun cancel(): NativeResult<Unit>
}

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
    fun createRecipient(validitySeconds: Int): NativeResult<NativeRecipient>
    fun validateRecipient(
        recipientRequest: ByteArray,
        recipientPrivate: ByteArray,
    ): NativeResult<Unit> = NativeResult.Failure(OperationError.INTERNAL_FAILURE)
    fun verifyPreview(request: ByteArray): NativeResult<VerifiedPreviewHandle>
    fun verifyPreviewWithRecipient(
        request: ByteArray,
        recipientRequest: ByteArray,
        recipientPrivate: ByteArray,
    ): NativeResult<VerifiedPreviewHandle>
    fun openActivation(verified: VerifiedPreviewHandle): NativeResult<NativeActivationSession>
    fun releaseVerified(verified: VerifiedPreviewHandle): NativeResult<Unit>
    fun prepareDiagnostic(request: ByteArray): NativeResult<DiagnosticPreviewHandle>
    fun confirmAndBuildDiagnostic(preview: DiagnosticPreviewHandle): NativeResult<ByteArray>
    fun createBackup(payload: ByteArray, passphrase: ByteArray): NativeResult<ByteArray>
    fun openBackup(backup: ByteArray, passphrase: ByteArray): NativeResult<BackupPreviewHandle>
    fun restoreBackup(preview: BackupPreviewHandle): NativeResult<ByteArray>
    fun phase11RoundTrip(payload: ByteArray): NativeResult<ByteArray>
    fun openRuntimeSession(request: ByteArray): NativeResult<NativeRuntimeSession>
    fun openLiveRuntimeSession(request: ByteArray): NativeResult<NativeLiveRuntimeSession>
    fun releaseDiagnostic(preview: DiagnosticPreviewHandle): NativeResult<Unit>
    fun releaseBackup(preview: BackupPreviewHandle): NativeResult<Unit>
}
