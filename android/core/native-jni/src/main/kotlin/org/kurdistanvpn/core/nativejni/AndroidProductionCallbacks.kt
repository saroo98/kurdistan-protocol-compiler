// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import java.io.Closeable
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.NativeProductResult
import org.kurdistanvpn.core.nativeapi.ProductionNativeSession
import org.kurdistanvpn.core.nativeapi.ProductionNativeMaintenance
import org.kurdistanvpn.core.nativeapi.NativeControlEvent

/** Trusted cross-module composition, never a public catalogue factory. */
interface AndroidProductionProbeBindingV1 {
    fun permits(target: Int): Boolean
    fun isCurrent(): Boolean
    fun observe(event: NativeControlEvent)
    fun invalidate()
}

/** One receiver's private reservation, not a token factory or native authority. */
internal class AndroidProductionReservationV1 {
    private val monitor = Any()
    private var started = false
    private var claimed = false
    private var closed = false
    private var kind = 0
    private var owner = 0L
    private var lease = 0L
    fun reserve(kind: Int, values: LongArray, register: () -> Int): Int {
        require(kind in 1..2 && values.size == 2 && values.all { it == 0L })
        synchronized(monitor) {
            if (started || closed) return 3
            started = true
        }
        val status = register()
        if (status != 0) return status
        synchronized(monitor) {
            if (values[0] == 0L || values[1] == 0L) return 18
            this.kind = kind; owner = values[0]; lease = values[1]
        }
        return 0
    }
    fun retire() = synchronized(monitor) { closed = true }
    fun <T> openProduction(open: (Long, Long) -> NativeProductResult<T>) = open(1, open)
    fun <T> openMaintenance(open: (Long, Long) -> NativeProductResult<T>) = open(2, open)
    private fun <T> open(expectedKind: Int, open: (Long, Long) -> NativeProductResult<T>): NativeProductResult<T> {
        val actualOwner: Long
        val actualLease: Long
        synchronized(monitor) {
            if (closed || claimed || kind != expectedKind || owner == 0L || lease == 0L)
                return NativeProductResult.Failure(ProductFailureCode.OPERATION_INTERRUPTED)
            claimed = true
            actualOwner = owner; actualLease = lease
        }
        // Never hold this monitor during capture, native opening or guard adoption.
        return open(actualOwner, actualLease)
    }
}

/** Trusted manual composition only. No framework objects or producer proof crosses this SPI. */
interface AndroidProductionPlatformDelegateV1 {
    /** Raw unsigned generation from this exact live bootstrap capture, not caller input. */
    fun capturedGeneration(owner: Long): Long
    fun bindActiveSelectors(owner: Long, generation: Long, digest: ByteArray): AndroidProductionProbeBindingV1
    fun bindDisconnectedSelectors(owner: Long): AndroidProductionProbeBindingV1
    fun owns(owner: Long): Boolean
    fun captureSizes(owner: Long, sizes: IntArray): Int
    fun captureCopyInto(owner: Long, verify: ByteBuffer, activation: ByteBuffer, recipient: ByteBuffer, privateRecipient: ByteBuffer, settings: ByteBuffer, written: IntArray): Int
    fun productionCurrentRegister(owner: Long, epoch: Long, signal: Long, out: LongArray): Int
    fun maintenanceCurrentRegister(owner: Long, epoch: Long, signal: Long, out: LongArray): Int
    fun revisionRevalidate(owner: Long, registration: Long, call: Long): Int
    fun publicationAcquire(owner: Long, registration: Long, call: Long, out: LongArray): Int
    fun publicationIsCurrent(owner: Long, registration: Long, publication: Long, out: IntArray): Int
    fun publicationClose(owner: Long, registration: Long, publication: Long): Int
    fun revisionClose(owner: Long, registration: Long): Int
    fun socketRegister(owner: Long, call: Long, epoch: Long, attempt: Long, token: Long, fd: Int, explicit: Int, hasNetwork: Int, network: Long, signal: Long, out: LongArray, binding: IntArray): Int
    fun socketConfirm(owner: Long, socket: Long, protected: Int, hasNetwork: Int, network: Long): Int
    fun socketClose(owner: Long, socket: Long): Int
    fun maintenanceNetworkAcquire(owner: Long, call: Long, signal: Long, out: LongArray): Int
    fun maintenanceNetworkSnapshot(owner: Long, network: Long, dns: ByteBuffer, metadata: IntArray): Int
    fun maintenanceNetworkIsCurrent(owner: Long, network: Long, out: IntArray): Int
    fun maintenanceNetworkBindSocket(owner: Long, network: Long, fd: Int): Int
    fun maintenanceNetworkClose(owner: Long, network: Long): Int
    fun cancelCall(owner: Long, call: Long): Int
    fun ownerClose(owner: Long): Int
}

/** One final object/global per fixed C owner. Borrowed buffers never survive a method return. */
class AndroidProductionCallbacks(private val delegate: AndroidProductionPlatformDelegateV1) {
    private val roots = AndroidSystemTrustRootsV1()
    private val reservation = AndroidProductionReservationV1()
    @Volatile private var unproven = false

    fun captureSizes(owner: Long, sizes: IntArray): Int = delegate.captureSizes(owner, sizes)
    fun captureCopyInto(owner: Long, verify: ByteBuffer, activation: ByteBuffer, recipient: ByteBuffer, privateRecipient: ByteBuffer, settings: ByteBuffer, written: IntArray): Int = delegate.captureCopyInto(owner, verify, activation, recipient, privateRecipient, settings, written)
    fun productionCurrentRegister(owner: Long, epoch: Long, signal: Long, out: LongArray): Int = delegate.productionCurrentRegister(owner, epoch, signal, out)
    fun maintenanceCurrentRegister(owner: Long, epoch: Long, signal: Long, out: LongArray): Int = delegate.maintenanceCurrentRegister(owner, epoch, signal, out)
    fun revisionRevalidate(owner: Long, registration: Long, call: Long): Int = delegate.revisionRevalidate(owner, registration, call)
    fun publicationAcquire(owner: Long, registration: Long, call: Long, out: LongArray): Int = delegate.publicationAcquire(owner, registration, call, out)
    fun publicationIsCurrent(owner: Long, registration: Long, publication: Long, out: IntArray): Int = delegate.publicationIsCurrent(owner, registration, publication, out)
    fun publicationClose(owner: Long, registration: Long, publication: Long): Int = delegate.publicationClose(owner, registration, publication)
    fun revisionClose(owner: Long, registration: Long): Int = delegate.revisionClose(owner, registration)
    fun socketRegister(owner: Long, call: Long, epoch: Long, attempt: Long, token: Long, fd: Int, explicit: Int, hasNetwork: Int, network: Long, signal: Long, out: LongArray, binding: IntArray): Int = delegate.socketRegister(owner, call, epoch, attempt, token, fd, explicit, hasNetwork, network, signal, out, binding)
    fun socketConfirm(owner: Long, socket: Long, protected: Int, hasNetwork: Int, network: Long): Int = delegate.socketConfirm(owner, socket, protected, hasNetwork, network)
    fun socketClose(owner: Long, socket: Long): Int = delegate.socketClose(owner, socket)
    fun maintenanceNetworkAcquire(owner: Long, call: Long, signal: Long, out: LongArray): Int = delegate.maintenanceNetworkAcquire(owner, call, signal, out)
    fun maintenanceNetworkSnapshot(owner: Long, network: Long, dns: ByteBuffer, metadata: IntArray): Int = delegate.maintenanceNetworkSnapshot(owner, network, dns, metadata)
    fun maintenanceNetworkIsCurrent(owner: Long, network: Long, out: IntArray): Int = delegate.maintenanceNetworkIsCurrent(owner, network, out)
    fun maintenanceNetworkBindSocket(owner: Long, network: Long, fd: Int): Int = delegate.maintenanceNetworkBindSocket(owner, network, fd)
    fun maintenanceNetworkClose(owner: Long, network: Long): Int = delegate.maintenanceNetworkClose(owner, network)
    fun cancelCall(owner: Long, call: Long): Int = delegate.cancelCall(owner, call)

    fun systemRootsInto(owner: Long, call: Long, destination: ByteBuffer, written: IntArray): Int {
        if (!delegate.owns(owner) || call == 0L) return 1
        return roots.copyInto(destination, written) { isCallCancelled(owner, call) }
    }
    fun ownerClose(owner: Long): Int {
        reservation.retire()
        val result = delegate.ownerClose(owner)
        if (result != 0 || unproven) { unproven = true; return 25 }
        return 0
    }

    fun reserve(kind: Int, ownerAndLease: LongArray): Int {
        require(ownerAndLease.size == 2 && ownerAndLease.all { it == 0L })
        check(libraries)
        return reservation.reserve(kind, ownerAndLease) { registerOwned(kind, ownerAndLease) }
    }
    /** Trusted runtime composition only; the successful reservation stays private. */
    fun openProduction(adopt: (Closeable) -> Unit, failedOpening: () -> Unit): NativeProductResult<ProductionNativeSession> {
        return reservation.openProduction { owner, lease ->
            val bridge = try { NativeBridge() } catch (_: Throwable) {
                failedOpening()
                return@openProduction NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
            }
            bridge.openProductionOwnerV1(delegate, owner, lease, adopt, failedOpening)
        }
    }
    fun openMaintenance(adopt: (Closeable) -> Unit, failedOpening: () -> Unit): NativeProductResult<ProductionNativeMaintenance> {
        return reservation.openMaintenance { owner, lease ->
            val bridge = try { NativeBridge() } catch (_: Throwable) {
                failedOpening()
                return@openMaintenance NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
            }
            bridge.openMaintenanceOwnerV1(delegate, owner, lease, adopt, failedOpening)
        }
    }
    fun abandon(lease: Long): Int = abandonUnclaimed(lease)
    /** Called only by trusted opening finally, after the output frame ended. */
    fun finishFailedOpening(kind: Int, lease: Long): Int {
        val abandoned = abandonUnclaimed(lease)
        return if (abandoned == 0) 0 else finalizeFailedOpening(kind, lease)
    }
    fun fenceRevision(owner: Long, signal: Long): Int = revisionFence(owner, signal)
    fun invalidateRevision(owner: Long, signal: Long): Int = revisionInvalidated(owner, signal)
    fun signalSocketLoss(owner: Long, signal: Long): Int = socketLost(owner, signal)
    fun signalNetworkLoss(owner: Long, signal: Long): Int = maintenanceNetworkLost(owner, signal)
    fun isCallCancelled(owner: Long, call: Long): Boolean {
        val out = IntArray(1)
        val status = callCancelled(owner, call, out)
        if (status != 0 || out[0] !in 0..1) { unproven = true; return true }
        return out[0] == 1
    }
    /** A missing deadline returns null, never a new cancellation context. */
    fun remainingMillis(owner: Long, call: Long): Long? {
        val present = IntArray(1); val remaining = LongArray(1)
        val status = callRemainingMillis(owner, call, present, remaining)
        if (status != 0 || present[0] !in 0..1 || remaining[0] < 0 ||
            (present[0] == 0 && remaining[0] != 0L)) {
            unproven = true
            throw IllegalStateException("PLATFORM_CALL_CONTEXT_UNPROVEN")
        }
        return if (present[0] == 0) null else remaining[0]
    }

    private external fun registerOwned(kind: Int, ownerAndLease: LongArray): Int
    private external fun abandonUnclaimed(lease: Long): Int
    private external fun finalizeFailedOpening(kind: Int, lease: Long): Int
    private external fun revisionFence(owner: Long, signal: Long): Int
    private external fun revisionInvalidated(owner: Long, signal: Long): Int
    private external fun socketLost(owner: Long, signal: Long): Int
    private external fun maintenanceNetworkLost(owner: Long, signal: Long): Int
    private external fun callCancelled(owner: Long, call: Long, out: IntArray): Int
    private external fun callRemainingMillis(owner: Long, call: Long, present: IntArray, remaining: LongArray): Int

    companion object {
        private val libraries: Boolean by lazy {
            System.loadLibrary("kurdistan_bridge")
            System.loadLibrary("kurdistan_jni")
            true
        }
    }
}
