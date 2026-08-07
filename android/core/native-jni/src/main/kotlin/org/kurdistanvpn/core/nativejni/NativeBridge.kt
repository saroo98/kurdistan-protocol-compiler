// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.RedactedProfilePreview
import org.kurdistanvpn.core.nativeapi.ActivationCommand
import org.kurdistanvpn.core.nativeapi.ActivationCommandKind
import org.kurdistanvpn.core.nativeapi.BackupPreviewHandle
import org.kurdistanvpn.core.nativeapi.DiagnosticPreviewHandle
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.core.nativeapi.NativeActivationSession
import org.kurdistanvpn.core.nativeapi.NativeCompatibility
import org.kurdistanvpn.core.nativeapi.NativeLiveRuntimeSession
import org.kurdistanvpn.core.nativeapi.NativeLiveRuntimeSessionSnapshot
import org.kurdistanvpn.core.nativeapi.NativePayloadProtocol
import org.kurdistanvpn.core.nativeapi.NativeRecipient
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.NativeRoute
import org.kurdistanvpn.core.nativeapi.NativeRuntimeSession
import org.kurdistanvpn.core.nativeapi.NativeRuntimeSessionSnapshot
import org.kurdistanvpn.core.nativeapi.NativeRuntimeState
import org.kurdistanvpn.core.nativeapi.VerifiedPreviewHandle
import org.kurdistanvpn.core.model.DnsMode
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.model.SelectionMode

class NativeBridge : KurdNativeCore {
    override fun compatibility(): NativeResult<NativeCompatibility> {
        val output = ByteBuffer.allocateDirect(MAX_ABI_BYTES)
        val length = IntArray(1)
        val code = nativeAbiInfo(output, length)
        if (code != CODE_OK) return NativeResult.Failure(mapError(code))
        return decodeCompatibility(readBytes(output, length[0]))
    }

    override fun createRecipient(validitySeconds: Int): NativeResult<NativeRecipient> {
        if (validitySeconds !in 1..MAX_RECIPIENT_VALIDITY_SECONDS) {
            return NativeResult.Failure(OperationError.INVALID_INPUT)
        }
        val output = LongArray(1)
        val code = nativeRecipientCreate(validitySeconds, output)
        return if (code == CODE_OK) {
            NativeResult.Success(JniRecipient(output[0]))
        } else {
            NativeResult.Failure(mapError(code))
        }
    }

    override fun validateRecipient(
        recipientRequest: ByteArray,
        recipientPrivate: ByteArray,
    ): NativeResult<Unit> {
        if (
            recipientRequest.isEmpty() || recipientRequest.size > MAX_RECIPIENT_REQUEST_BYTES ||
            recipientPrivate.isEmpty() || recipientPrivate.size > MAX_RECIPIENT_PRIVATE_BYTES
        ) {
            return NativeResult.Failure(OperationError.SIZE_LIMIT)
        }
        return unitResult(nativeRecipientValidate(recipientRequest, recipientPrivate))
    }

    override fun verifyPreview(request: ByteArray): NativeResult<VerifiedPreviewHandle> {
        if (request.isEmpty() || request.size > MAX_VERIFY_REQUEST_BYTES) {
            return NativeResult.Failure(OperationError.SIZE_LIMIT)
        }
        val output = ByteBuffer.allocateDirect(MAX_PREVIEW_BYTES)
        val metadata = LongArray(2)
        val code = nativeVerifyPreview(request, output, metadata)
        if (code != CODE_OK) return NativeResult.Failure(mapError(code))
        val preview = decodePreview(readBytes(output, metadata[1].toInt()))
        return when (preview) {
            is NativeResult.Failure -> preview
            is NativeResult.Success ->
                NativeResult.Success(VerifiedPreviewHandle(metadata[0], preview.value))
        }
    }

    override fun verifyPreviewWithRecipient(
        request: ByteArray,
        recipientRequest: ByteArray,
        recipientPrivate: ByteArray,
    ): NativeResult<VerifiedPreviewHandle> {
        if (request.isEmpty() || request.size > MAX_VERIFY_REQUEST_BYTES ||
            recipientRequest.isEmpty() || recipientRequest.size > MAX_RECIPIENT_REQUEST_BYTES ||
            recipientPrivate.isEmpty() || recipientPrivate.size > MAX_RECIPIENT_PRIVATE_BYTES
        ) {
            return NativeResult.Failure(OperationError.SIZE_LIMIT)
        }
        val output = ByteBuffer.allocateDirect(MAX_PREVIEW_BYTES)
        val metadata = LongArray(2)
        val code = nativeVerifyPreviewWithRecipient(
            request,
            recipientRequest,
            recipientPrivate,
            output,
            metadata,
        )
        if (code != CODE_OK) return NativeResult.Failure(mapError(code))
        return when (val preview = decodePreview(readBytes(output, metadata[1].toInt()))) {
            is NativeResult.Failure -> {
                nativeFree(metadata[0])
                preview
            }
            is NativeResult.Success -> NativeResult.Success(
                VerifiedPreviewHandle(metadata[0], preview.value),
            )
        }
    }

    override fun openActivation(verified: VerifiedPreviewHandle): NativeResult<NativeActivationSession> {
        val output = LongArray(1)
        val code = nativeActivationOpen(verified.handle, output)
        return if (code == CODE_OK) {
            NativeResult.Success(JniActivationSession(output[0]))
        } else {
            NativeResult.Failure(mapError(code))
        }
    }

    override fun releaseVerified(verified: VerifiedPreviewHandle): NativeResult<Unit> =
        unitResult(nativeFree(verified.handle))

    override fun prepareDiagnostic(request: ByteArray): NativeResult<DiagnosticPreviewHandle> {
        val handle = LongArray(1)
        var code = nativeDiagnosticPrepare(request, handle)
        if (code != CODE_OK) return NativeResult.Failure(mapError(code))
        val output = ByteBuffer.allocateDirect(MAX_PREVIEW_BYTES)
        val length = IntArray(1)
        code = nativeDiagnosticPreview(handle[0], output, length)
        if (code != CODE_OK) {
            nativeFree(handle[0])
            return NativeResult.Failure(mapError(code))
        }
        return NativeResult.Success(
            DiagnosticPreviewHandle(handle[0], readBytes(output, length[0])),
        )
    }

    override fun confirmAndBuildDiagnostic(
        preview: DiagnosticPreviewHandle,
    ): NativeResult<ByteArray> {
        var code = nativeDiagnosticConfirm(preview.handle, true, preview.previewBytes)
        if (code != CODE_OK) return NativeResult.Failure(mapError(code))
        val output = ByteBuffer.allocateDirect(MAX_DIAGNOSTIC_BYTES)
        val length = IntArray(1)
        code = nativeDiagnosticBuild(preview.handle, output, length)
        return if (code == CODE_OK) {
            NativeResult.Success(readBytes(output, length[0]))
        } else {
            NativeResult.Failure(mapError(code))
        }
    }

    override fun createBackup(
        payload: ByteArray,
        passphrase: ByteArray,
    ): NativeResult<ByteArray> {
        val output = ByteBuffer.allocateDirect(MAX_BACKUP_BYTES)
        val length = IntArray(1)
        val code = nativeBackupCreate(payload, passphrase, output, length)
        return if (code == CODE_OK) {
            NativeResult.Success(readBytes(output, length[0]))
        } else {
            NativeResult.Failure(mapError(code))
        }
    }

    override fun openBackup(
        backup: ByteArray,
        passphrase: ByteArray,
    ): NativeResult<BackupPreviewHandle> {
        val output = ByteBuffer.allocateDirect(MAX_PREVIEW_BYTES)
        val metadata = LongArray(2)
        val code = nativeBackupOpenPreview(backup, passphrase, output, metadata)
        return if (code == CODE_OK) {
            NativeResult.Success(
                BackupPreviewHandle(
                    handle = metadata[0],
                    previewBytes = readBytes(output, metadata[1].toInt()),
                ),
            )
        } else {
            NativeResult.Failure(mapError(code))
        }
    }

    override fun restoreBackup(preview: BackupPreviewHandle): NativeResult<ByteArray> {
        val output = ByteBuffer.allocateDirect(MAX_BACKUP_BYTES)
        val length = IntArray(1)
        val code = nativeBackupRestore(preview.handle, preview.previewBytes, output, length)
        return if (code == CODE_OK) {
            NativeResult.Success(readBytes(output, length[0]))
        } else {
            NativeResult.Failure(mapError(code))
        }
    }

    override fun phase11RoundTrip(payload: ByteArray): NativeResult<ByteArray> {
        if (payload.isEmpty() || payload.size > MAX_PHASE11_PAYLOAD_BYTES) {
            return NativeResult.Failure(OperationError.SIZE_LIMIT)
        }
        val output = ByteBuffer.allocateDirect(MAX_PHASE11_PAYLOAD_BYTES)
        val length = IntArray(1)
        val code = nativePhase11RoundTrip(payload, output, length)
        return if (code == CODE_OK) {
            NativeResult.Success(readBytes(output, length[0]))
        } else {
            NativeResult.Failure(mapError(code))
        }
    }

    override fun openRuntimeSession(request: ByteArray): NativeResult<NativeRuntimeSession> {
        if (request.isEmpty() || request.size > MAX_RUNTIME_OPEN_BYTES) {
            return NativeResult.Failure(OperationError.SIZE_LIMIT)
        }
        val output = ByteBuffer.allocateDirect(MAX_RUNTIME_SNAPSHOT_BYTES)
        val metadata = LongArray(2)
        val code = nativeRuntimeSessionOpen(request, output, metadata)
        if (code != CODE_OK) return NativeResult.Failure(mapError(code))
        val decoded = decodeRuntimeSnapshot(readBytes(output, metadata[1].toInt()))
        return when (decoded) {
            is NativeResult.Failure -> {
                nativeFree(metadata[0])
                decoded
            }
            is NativeResult.Success -> NativeResult.Success(
                JniRuntimeSession(metadata[0], decoded.value),
            )
        }
    }

    override fun openLiveRuntimeSession(request: ByteArray): NativeResult<NativeLiveRuntimeSession> {
        if (request.isEmpty() || request.size > MAX_RUNTIME_OPEN_V2_BYTES) {
            return NativeResult.Failure(OperationError.SIZE_LIMIT)
        }
        val output = ByteBuffer.allocateDirect(MAX_RUNTIME_SNAPSHOT_BYTES)
        val metadata = LongArray(2)
        val code = nativeRuntimeSessionOpenV2(request, output, metadata)
        if (code != CODE_OK) return NativeResult.Failure(mapError(code))
        return when (val decoded = decodeLiveRuntimeSnapshot(readBytes(output, metadata[1].toInt()))) {
            is NativeResult.Failure -> {
                nativeFree(metadata[0])
                decoded
            }
            is NativeResult.Success -> NativeResult.Success(
                JniLiveRuntimeSession(metadata[0], decoded.value),
            )
        }
    }

    override fun releaseDiagnostic(preview: DiagnosticPreviewHandle): NativeResult<Unit> =
        unitResult(nativeFree(preview.handle))

    override fun releaseBackup(preview: BackupPreviewHandle): NativeResult<Unit> =
        unitResult(nativeFree(preview.handle))

    private inner class JniRecipient(
        private val handle: Long,
    ) : NativeRecipient {
        private var closed = false

        override fun publicRequest(): NativeResult<ByteArray> = recipientBytes(
            MAX_RECIPIENT_REQUEST_BYTES,
            ::nativeRecipientRequest,
        )

        override fun privateBundle(): NativeResult<ByteArray> = recipientBytes(
            MAX_RECIPIENT_PRIVATE_BYTES,
            ::nativeRecipientPrivateExport,
        )

        private fun recipientBytes(
            maximum: Int,
            operation: (Long, ByteBuffer, IntArray) -> Int,
        ): NativeResult<ByteArray> {
            if (closed) return NativeResult.Failure(OperationError.CANCELLED)
            val output = ByteBuffer.allocateDirect(maximum)
            val length = IntArray(1)
            val code = operation(handle, output, length)
            return if (code == CODE_OK) {
                NativeResult.Success(readBytes(output, length[0]))
            } else {
                NativeResult.Failure(mapError(code))
            }
        }

        override fun cancel(): NativeResult<Unit> {
            if (closed) return NativeResult.Failure(OperationError.CANCELLED)
            val result = unitResult(nativeCancel(handle))
            close()
            return result
        }

        override fun close() {
            if (!closed) {
                closed = true
                nativeFree(handle)
            }
        }
    }

    private inner class JniActivationSession(
        private val handle: Long,
    ) : NativeActivationSession {
        private var closed = false

        override fun next(): NativeResult<ActivationCommand> {
            if (closed) return NativeResult.Failure(OperationError.CANCELLED)
            val output = ByteBuffer.allocateDirect(MAX_RESULT_BYTES)
            val metadata = LongArray(3)
            val code = nativeActivationNext(handle, output, metadata)
            if (code != CODE_OK) return NativeResult.Failure(mapError(code))
            val kind = ActivationCommandKind.entries.getOrNull(metadata[1].toInt() - 1)
                ?: return NativeResult.Failure(OperationError.INTERNAL_FAILURE)
            return NativeResult.Success(
                ActivationCommand(
                    sequence = metadata[0],
                    kind = kind,
                    opaqueRecord = readBytes(output, metadata[2].toInt()),
                ),
            )
        }

        override fun submit(
            command: ActivationCommand,
            storageSucceeded: Boolean,
            active: ByteArray,
            lastKnownGood: ByteArray,
            reopened: ByteArray,
        ): NativeResult<Unit> {
            if (closed || command.kind == ActivationCommandKind.COMPLETE) {
                return NativeResult.Failure(OperationError.INVALID_INPUT)
            }
            return unitResult(
                nativeActivationSubmit(
                    handle,
                    command.sequence,
                    command.kind.ordinal + 1,
                    storageSucceeded,
                    active,
                    lastKnownGood,
                    reopened,
                ),
            )
        }

        override fun cancel(): NativeResult<Unit> {
            if (closed) return NativeResult.Failure(OperationError.CANCELLED)
            val result = unitResult(nativeCancel(handle))
            close()
            return result
        }

        override fun close() {
            if (!closed) {
                closed = true
                nativeFree(handle)
            }
        }
    }

    private inner class JniRuntimeSession(
        private val handle: Long,
        override val snapshot: NativeRuntimeSessionSnapshot,
    ) : NativeRuntimeSession {
        private var closed = false

        override fun roundTrip(payload: ByteArray): NativeResult<ByteArray> {
            if (closed) return NativeResult.Failure(OperationError.CANCELLED)
            if (payload.isEmpty() || payload.size > MAX_PHASE11_PAYLOAD_BYTES) {
                return NativeResult.Failure(OperationError.SIZE_LIMIT)
            }
            val output = ByteBuffer.allocateDirect(MAX_PHASE11_PAYLOAD_BYTES)
            val length = IntArray(1)
            val code = nativeRuntimeSessionRoundTrip(handle, payload, output, length)
            return if (code == CODE_OK) {
                NativeResult.Success(readBytes(output, length[0]))
            } else {
                NativeResult.Failure(mapError(code))
            }
        }

        override fun cancel(): NativeResult<Unit> {
            if (closed) return NativeResult.Failure(OperationError.CANCELLED)
            val result = unitResult(nativeCancel(handle))
            close()
            return result
        }

        override fun close() {
            if (!closed) {
                closed = true
                nativeFree(handle)
            }
        }
    }

    private inner class JniLiveRuntimeSession(
        private val handle: Long,
        override val snapshot: NativeLiveRuntimeSessionSnapshot,
    ) : NativeLiveRuntimeSession {
        private var closed = false

        override fun prepareSocket(): NativeResult<Int> {
            if (closed) return NativeResult.Failure(OperationError.CANCELLED)
            val output = IntArray(1)
            val code = nativeRuntimeSocketPrepare(handle, output)
            return if (code == CODE_OK && output[0] >= 0) {
                NativeResult.Success(output[0])
            } else if (code == CODE_OK) {
                NativeResult.Failure(OperationError.INTERNAL_FAILURE)
            } else {
                NativeResult.Failure(mapError(code))
            }
        }

        override fun commitProtected(protectedSocket: Boolean): NativeResult<Unit> {
            if (closed) return NativeResult.Failure(OperationError.CANCELLED)
            return unitResult(nativeRuntimeSocketCommitProtected(handle, protectedSocket))
        }

        override fun attachTun(fileDescriptor: Int): NativeResult<Unit> {
            if (closed || fileDescriptor < 0) {
                return NativeResult.Failure(OperationError.INVALID_INPUT)
            }
            return unitResult(nativeRuntimeTunAttach(handle, fileDescriptor))
        }

        override fun status(): NativeResult<NativeRuntimeState> {
            if (closed) return NativeResult.Failure(OperationError.CANCELLED)
            val output = IntArray(1)
            val code = nativeRuntimeStatus(handle, output)
            if (code != CODE_OK) return NativeResult.Failure(mapError(code))
            val state = NativeRuntimeState.entries.getOrNull(output[0] - 1)
                ?: return NativeResult.Failure(OperationError.INTERNAL_FAILURE)
            return NativeResult.Success(state)
        }

        override fun stop(): NativeResult<Unit> {
            if (closed) return NativeResult.Failure(OperationError.CANCELLED)
            return unitResult(nativeRuntimeStop(handle))
        }

        override fun close() {
            if (!closed) {
                closed = true
                nativeRuntimeStop(handle)
                nativeFree(handle)
            }
        }
    }

    private external fun nativeAbiInfo(output: ByteBuffer, outputLength: IntArray): Int
    private external fun nativeRecipientCreate(validitySeconds: Int, outputHandle: LongArray): Int
    private external fun nativeRecipientRequest(handle: Long, output: ByteBuffer, outputLength: IntArray): Int
    private external fun nativeRecipientPrivateExport(handle: Long, output: ByteBuffer, outputLength: IntArray): Int
    private external fun nativeRecipientValidate(recipientRequest: ByteArray, recipientPrivate: ByteArray): Int
    private external fun nativeVerifyPreview(input: ByteArray, output: ByteBuffer, metadata: LongArray): Int
    private external fun nativeVerifyPreviewWithRecipient(
        input: ByteArray,
        recipientRequest: ByteArray,
        recipientPrivate: ByteArray,
        output: ByteBuffer,
        metadata: LongArray,
    ): Int
    private external fun nativeActivationOpen(verified: Long, outputHandle: LongArray): Int
    private external fun nativeActivationNext(handle: Long, output: ByteBuffer, metadata: LongArray): Int
    private external fun nativeActivationSubmit(
        handle: Long,
        sequence: Long,
        kind: Int,
        storageSucceeded: Boolean,
        active: ByteArray,
        lastKnownGood: ByteArray,
        reopened: ByteArray,
    ): Int
    private external fun nativeCancel(handle: Long): Int
    private external fun nativeFree(handle: Long): Int
    private external fun nativeDiagnosticPrepare(request: ByteArray, outputHandle: LongArray): Int
    private external fun nativeDiagnosticPreview(handle: Long, output: ByteBuffer, outputLength: IntArray): Int
    private external fun nativeDiagnosticConfirm(handle: Long, approved: Boolean, preview: ByteArray): Int
    private external fun nativeDiagnosticBuild(handle: Long, output: ByteBuffer, outputLength: IntArray): Int
    private external fun nativeBackupCreate(
        payload: ByteArray,
        passphrase: ByteArray,
        output: ByteBuffer,
        outputLength: IntArray,
    ): Int
    private external fun nativeBackupOpenPreview(
        backup: ByteArray,
        passphrase: ByteArray,
        output: ByteBuffer,
        metadata: LongArray,
    ): Int
    private external fun nativeBackupRestore(
        handle: Long,
        preview: ByteArray,
        output: ByteBuffer,
        outputLength: IntArray,
    ): Int
    private external fun nativePhase11RoundTrip(
        input: ByteArray,
        output: ByteBuffer,
        outputLength: IntArray,
    ): Int
    private external fun nativeRuntimeSessionOpen(
        input: ByteArray,
        output: ByteBuffer,
        metadata: LongArray,
    ): Int
    private external fun nativeRuntimeSessionRoundTrip(
        handle: Long,
        input: ByteArray,
        output: ByteBuffer,
        outputLength: IntArray,
    ): Int
    private external fun nativeRuntimeSessionOpenV2(
        input: ByteArray,
        output: ByteBuffer,
        metadata: LongArray,
    ): Int
    private external fun nativeRuntimeSocketPrepare(handle: Long, outputFileDescriptor: IntArray): Int
    private external fun nativeRuntimeSocketCommitProtected(handle: Long, protectedSocket: Boolean): Int
    private external fun nativeRuntimeTunAttach(handle: Long, fileDescriptor: Int): Int
    private external fun nativeRuntimeStatus(handle: Long, outputState: IntArray): Int
    private external fun nativeRuntimeStop(handle: Long): Int

    companion object {
        private const val CODE_OK = 0
        private const val MAX_ABI_BYTES = 512
        private const val MAX_PREVIEW_BYTES = 4096
        private const val MAX_VERIFY_REQUEST_BYTES = 1_500_000
        private const val MAX_RECIPIENT_VALIDITY_SECONDS = 24 * 60 * 60
        private const val MAX_RECIPIENT_REQUEST_BYTES = 4096
        private const val MAX_RECIPIENT_PRIVATE_BYTES = 4096
        private const val MAX_RESULT_BYTES = 1_200_000
        private const val MAX_DIAGNOSTIC_BYTES = 4096
        private const val MAX_BACKUP_BYTES = 8 * 1024 * 1024 + 128
        private const val MAX_RUNTIME_OPEN_BYTES = 1_500_000 + 1_200_000 + 32 * 1024
        private const val MAX_RUNTIME_OPEN_V2_BYTES =
            1_500_000 + 1_200_000 + MAX_RECIPIENT_REQUEST_BYTES + MAX_RECIPIENT_PRIVATE_BYTES + 32 * 1024
        private const val MAX_RUNTIME_SNAPSHOT_BYTES = 32 * 1024
        private const val MAX_PHASE11_PAYLOAD_BYTES = 32 * 1024

        init {
            System.loadLibrary("kurdistan_bridge")
            System.loadLibrary("kurdistan_jni")
        }

        private fun readBytes(buffer: ByteBuffer, length: Int): ByteArray {
            require(length in 0..buffer.capacity())
            val result = ByteArray(length)
            try {
                buffer.position(0)
                buffer.get(result)
            } finally {
                val wipe = buffer.duplicate()
                wipe.position(0)
                repeat(length) { wipe.put(0.toByte()) }
            }
            return result
        }

        private fun decodeCompatibility(encoded: ByteArray): NativeResult<NativeCompatibility> =
            runCatching {
                val reader = BinaryReader(encoded)
                require(reader.ascii(4) == "KVAB")
                require(reader.u8() == 1)
                require(reader.u8() == 7)
                require(reader.u16() == encoded.size)
                val fields = List(6) { reader.boundedString() }
                NativeCompatibility(
                    bridgeVersion = fields[0],
                    goCoreVersion = fields[1],
                    profileSchema = fields[2],
                    strategyRegistry = fields[3],
                    relaySchema = fields[4],
                    diagnosticSchema = fields[5],
                    cryptoSuite = reader.u16(),
                    maxInputBytes = reader.u32(),
                    maxQrChunks = reader.u16(),
                    maxQrChunkChars = reader.u16(),
                    maxResultBytes = reader.u32(),
                    maxConcurrentHandles = reader.u16(),
                ).also { require(reader.exhausted()) }
            }.fold(
                onSuccess = { NativeResult.Success(it) },
                onFailure = { NativeResult.Failure(OperationError.INCOMPATIBLE_NATIVE_CORE) },
            )

        private fun decodePreview(encoded: ByteArray): NativeResult<RedactedProfilePreview> =
            runCatching {
                val reader = BinaryReader(encoded)
                require(reader.ascii(4) == "KVP2")
                val artifactClass = reader.boundedString()
                val audienceClass = reader.boundedString()
                val contentFingerprint = reader.boundedString()
                val lineageFingerprint = reader.boundedString()
                val deploymentFingerprint = reader.boundedString()
                val relayEndpointSummary = reader.boundedString()
                val authorityScope = reader.boundedString()
                val updateLocation = reader.boundedString()
                val flags = reader.u8()
                require(flags and 0xf8 == 0)
                RedactedProfilePreview(
                    artifactClass = artifactClass,
                    audienceClass = audienceClass,
                    contentFingerprint = contentFingerprint,
                    lineageFingerprint = lineageFingerprint,
                    sealed = flags and 1 != 0,
                    generation = reader.u64().toULong(),
                    validUntilEpochSeconds = reader.i64(),
                    deploymentFingerprint = deploymentFingerprint,
                    relayEndpointSummary = relayEndpointSummary,
                    authorityScope = authorityScope,
                    updateLocation = updateLocation,
                    ownerControlled = flags and 2 != 0,
                    updatesEnabled = flags and 4 != 0,
                ).also { require(reader.exhausted()) }
            }.fold(
                onSuccess = { NativeResult.Success(it) },
                onFailure = { NativeResult.Failure(OperationError.INTERNAL_FAILURE) },
            )

        private fun decodeRuntimeSnapshot(
            encoded: ByteArray,
        ): NativeResult<NativeRuntimeSessionSnapshot> = runCatching {
            val reader = BinaryReader(encoded)
            require(reader.ascii(4) == "KSS1")
            require(reader.u8() == 1)
            val flags = reader.u8()
            require(flags and 0xfc == 0)
            val selection = SelectionMode.entries.getOrNull(reader.u8() - 1)
                ?: error("invalid selection")
            val perApp = PerAppSelectionMode.entries.getOrNull(reader.u8() - 1)
                ?: error("invalid per-app mode")
            val ipMode = IpMode.entries.getOrNull(reader.u8() - 1)
                ?: error("invalid IP mode")
            val dnsMode = when (reader.u8()) {
                1 -> DnsMode.INTERNAL_TUN
                2 -> DnsMode.CUSTOM
                else -> error("invalid DNS mode")
            }
            val mtu = reader.u16()
            require(mtu in 1280..1500)
            val generation = reader.u64()
            val planDigest = reader.fixedBytes(32)
            require(planDigest.any { it != 0.toByte() })
            val profileFingerprint = reader.fixedBytes(16)
            val strategyFingerprint = reader.fixedBytes(16)
            val relayFingerprint = reader.fixedBytes(16)
            val packageCount = reader.u16()
            require(packageCount <= 64)
            val packages = List(packageCount) { reader.u16String() }
            require(packages == packages.sorted() && packages.distinct().size == packages.size)
            NativeRuntimeSessionSnapshot(
                generation = generation,
                planDigest = planDigest,
                profileFingerprint = profileFingerprint,
                strategyFingerprint = strategyFingerprint,
                relayFingerprint = relayFingerprint,
                selectionMode = selection,
                perAppMode = perApp,
                packages = packages,
                ipMode = ipMode,
                dnsMode = dnsMode,
                mtu = mtu,
                metered = flags and 2 != 0,
                loopbackOnly = flags and 1 != 0,
            ).also { require(reader.exhausted()) }
        }.fold(
            onSuccess = { NativeResult.Success(it) },
            onFailure = { NativeResult.Failure(OperationError.INTERNAL_FAILURE) },
        )

        private fun decodeLiveRuntimeSnapshot(
            encoded: ByteArray,
        ): NativeResult<NativeLiveRuntimeSessionSnapshot> = runCatching {
            val reader = BinaryReader(encoded)
            require(reader.ascii(4) == "KSV2")
            require(reader.u8() == 2)
            val flags = reader.u8()
            require(flags and 0xfe == 0)
            val selection = SelectionMode.entries.getOrNull(reader.u8() - 1)
                ?: error("invalid selection")
            val perApp = PerAppSelectionMode.entries.getOrNull(reader.u8() - 1)
                ?: error("invalid per-app mode")
            val ipMode = IpMode.entries.getOrNull(reader.u8() - 1)
                ?: error("invalid IP mode")
            val dnsMode = when (reader.u8()) {
                1 -> DnsMode.INTERNAL_TUN
                2 -> DnsMode.CUSTOM
                else -> error("invalid DNS mode")
            }
            val mtu = reader.u16()
            require(mtu == 1280)
            val generation = reader.u64()
            val planDigest = reader.fixedBytes(32)
            require(planDigest.any { it != 0.toByte() })
            val profileFingerprint = reader.fixedBytes(16)
            val strategyFingerprint = reader.fixedBytes(16)
            val relayFingerprint = reader.fixedBytes(16)
            val clientIpv4 = reader.fixedBytes(4)
            val dnsIpv4 = reader.fixedBytes(4)
            val clientIpv6 = reader.fixedBytes(16)
            val dnsIpv6 = reader.fixedBytes(16)
            val maxQueuePackets = reader.u16()
            val maxIncompleteOperations = reader.u16()
            val maxReconnectAttempts = reader.u8()
            val packageCount = reader.u16()
            val routeCount = reader.u8()
            val protocolCount = reader.u8()
            val dialTimeoutMillis = reader.u32().toLong()
            val idleTimeoutMillis = reader.u32().toLong()
            require(packageCount <= 64 && routeCount in 1..2 && protocolCount in 1..4)
            require(maxQueuePackets > 0 && maxIncompleteOperations > 0 && maxReconnectAttempts > 0)
            require(dialTimeoutMillis > 0 && idleTimeoutMillis > 0)
            val packages = List(packageCount) { reader.u16String() }
            require(packages == packages.sorted() && packages.distinct().size == packages.size)
            val routes = List(routeCount) {
                val addressLength = reader.u8()
                val prefixLength = reader.u8()
                require(addressLength == 4 || addressLength == 16)
                require(prefixLength <= if (addressLength == 4) 32 else 128)
                NativeRoute(reader.fixedBytes(addressLength), prefixLength)
            }
            val protocols = List(protocolCount) {
                NativePayloadProtocol.entries.getOrNull(reader.u8() - 1)
                    ?: error("invalid payload protocol")
            }
            require(protocols.distinct().size == protocols.size)
            NativeLiveRuntimeSessionSnapshot(
                generation = generation,
                planDigest = planDigest,
                profileFingerprint = profileFingerprint,
                strategyFingerprint = strategyFingerprint,
                relayFingerprint = relayFingerprint,
                selectionMode = selection,
                perAppMode = perApp,
                packages = packages,
                ipMode = ipMode,
                dnsMode = dnsMode,
                mtu = mtu,
                metered = flags and 1 != 0,
                clientIpv4 = clientIpv4,
                dnsIpv4 = dnsIpv4,
                clientIpv6 = clientIpv6,
                dnsIpv6 = dnsIpv6,
                routes = routes,
                payloadProtocols = protocols.toSet(),
                maxQueuePackets = maxQueuePackets,
                maxIncompleteOperations = maxIncompleteOperations,
                maxReconnectAttempts = maxReconnectAttempts,
                dialTimeoutMillis = dialTimeoutMillis,
                idleTimeoutMillis = idleTimeoutMillis,
            ).also { require(reader.exhausted()) }
        }.fold(
            onSuccess = { NativeResult.Success(it) },
            onFailure = { NativeResult.Failure(OperationError.INTERNAL_FAILURE) },
        )

        private fun unitResult(code: Int): NativeResult<Unit> =
            if (code == CODE_OK) NativeResult.Success(Unit) else NativeResult.Failure(mapError(code))

        private fun mapError(code: Int): OperationError =
            when (code) {
                1 -> OperationError.INVALID_INPUT
                2 -> OperationError.SIZE_LIMIT
                3, 4, 5 -> OperationError.INVALID_INPUT
                6 -> OperationError.CANCELLED
                7, 8 -> OperationError.TRUST_REJECTED
                9 -> OperationError.POLICY_REJECTED
                10 -> OperationError.STORAGE_FAILURE
                11 -> OperationError.RECOVERY_REQUIRED
                12 -> OperationError.QUARANTINED
                13 -> OperationError.INCOMPATIBLE_NATIVE_CORE
                else -> OperationError.INTERNAL_FAILURE
            }
    }
}

private class BinaryReader(
    encoded: ByteArray,
) {
    private val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)

    fun ascii(length: Int): String = bytes(length).toString(Charsets.US_ASCII)
    fun boundedString(): String = bytes(u8()).toString(Charsets.UTF_8)
    fun u8(): Int = buffer.get().toInt() and 0xff
    fun u16(): Int = buffer.short.toInt() and 0xffff
    fun u32(): Int = buffer.int.also { require(it >= 0) }
    fun u64(): Long = buffer.long.also { require(it >= 0) }
    fun i64(): Long = buffer.long
    fun fixedBytes(length: Int): ByteArray = bytes(length)
    fun u16String(): String = bytes(u16()).toString(Charsets.UTF_8).also {
        require(it.length in 3..255)
    }
    fun exhausted(): Boolean = !buffer.hasRemaining()

    private fun bytes(length: Int): ByteArray {
        require(length in 0..buffer.remaining())
        return ByteArray(length).also(buffer::get)
    }
}
