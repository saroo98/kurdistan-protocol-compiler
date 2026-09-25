// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.io.Closeable
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.CancellationException
import java.util.concurrent.Executors
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import org.kurdistanvpn.core.nativeapi.DurableFilePrimitives
import org.kurdistanvpn.runtime.api.*

/** One synchronous JNI caller plus its actual worker. Cancellation never replaces that worker. */
internal class RuntimeProductionCallOwnerV1(private val ownerCancelled: () -> Boolean = { false }) : Closeable {
    private class Call<T>(val id: Long) {
        @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
        val condition = Object()
        var done = false
        var cancelled = false
        var value: T? = null
        var failure: Throwable? = null
    }
    private val monitor = Any()
    private var active: Call<*>? = null
    private var closed = false
    private var closeUnproven = false
    private var workerThread: Thread? = null
    // Numeric first rejection only. The internal fixture reads its own retained instance.
    @Volatile private var firstAdmissionRejection = 0
    // active admits only one call. One slot bridges done notification to the
    // previous runnable's actual return; it cannot queue a second admitted call.
    private val worker = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(1),
        { job -> Thread(job, "production-authority-client").apply { isDaemon = true; workerThread = this } },
        ThreadPoolExecutor.AbortPolicy())

    fun <T> run(id: Long, action: () -> T): T {
        require(id != 0L)
        return runOwned(id, action)
    }

    /** No borrowed native context exists for ownerClose; zero is never a cancellable call ID. */
    fun <T> runCleanup(action: () -> T): T = runOwned(0, action)

    private fun <T> runOwned(id: Long, action: () -> T): T {
        val call = synchronized(monitor) {
            if (firstAdmissionRejection == 0 && (closed || active != null || Thread.currentThread() === workerThread))
                firstAdmissionRejection = (if (closed) 1 else 0) or (if (active != null) 2 else 0) or
                    (if (Thread.currentThread() === workerThread) 4 else 0)
            check(!closed && active == null && Thread.currentThread() !== workerThread)
            Call<T>(id).also { active = it }
        }
        try {
            worker.execute {
                try {
                    if (id != 0L && ownerCancelled()) throw CancellationException("AUTHORITY_OWNER_CANCELLED")
                    call.value = action()
                } catch (failure: Throwable) { call.failure = failure }
                finally {
                    synchronized(call.condition) { call.done = true; call.condition.notifyAll() }
                }
            }
        } catch (failure: Throwable) {
            synchronized(monitor) { if (active === call) active = null }
            throw failure
        }
        var interrupted = false
        try {
            // No owner monitor is held while waiting. A cancelled Binder call remains
            // retained until the worker actually returns and publishes done.
            val cancelled = synchronized(call.condition) {
                while (!call.done) {
                    try { call.condition.wait() }
                    catch (_: InterruptedException) { interrupted = true; call.cancelled = true }
                }
                call.cancelled
            }
            if (cancelled || (id != 0L && ownerCancelled())) {
                (call.value as? AutoCloseable)?.close()
                if (call.failure is RuntimeAuthorityCleanupUnprovenException) throw checkNotNull(call.failure)
                throw CancellationException("AUTHORITY_CALL_CANCELLED")
            }
            call.failure?.let { throw it }
            @Suppress("UNCHECKED_CAST")
            return call.value as T
        } catch (failure: RuntimeAuthorityCleanupUnprovenException) {
            synchronized(monitor) { closed = true; closeUnproven = true }
            worker.shutdown()
            throw failure
        } finally {
            synchronized(monitor) { if (active === call) active = null }
            if (interrupted) Thread.currentThread().interrupt()
        }
    }

    fun isCancelled(id: Long): Boolean {
        if (ownerCancelled()) return true
        val call = synchronized(monitor) { active?.takeIf { it.id == id } } ?: return true
        return synchronized(call.condition) { call.cancelled }
    }

    fun cancel(id: Long): Boolean {
        if (id == 0L) return false
        val call = synchronized(monitor) { active?.takeIf { it.id == id } } ?: return false
        synchronized(call.condition) { call.cancelled = true; call.condition.notifyAll() }
        return true
    }

    override fun close() {
        val call = synchronized(monitor) {
            closed = true
            if (active != null) closeUnproven = true
            active
        }
        call?.let { cancel(it.id) }
        worker.shutdown()
        if (synchronized(monitor) { closeUnproven }) throw RuntimeAuthorityCleanupUnprovenException()
    }
}

/** Only the actual v3 verifier creates this process-local capture provenance. */
internal fun recordProductionPublicationV1(values: LongArray, offset: Int, phase: Int, category: Int,
    age: Long = -1, predicate: Long = -1, state: Long = -1, completed: Long = 0, failure: Throwable? = null) {
    // Numeric observation only. Neither a failed observation nor its contents govern ownership.
    runCatching {
        synchronized(values) {
            if (values.size != 16 || offset !in listOf(0, 8) || values[offset + 1] > 0) return
            values[offset] = phase.toLong(); values[offset + 1] = category.toLong()
            values[offset + 2] = if (age in 0..60000) age else -1
            values[offset + 3] = predicate; values[offset + 4] = state; values[offset + 5] = completed
            values[offset + 6] = when (failure) {
                null -> 0L
                is java.util.concurrent.CancellationException -> 1L
                is RuntimeAuthorityCleanupUnprovenException -> 2L
                is IllegalArgumentException -> 3L
                is IllegalStateException -> 4L
                is java.io.IOException -> 5L
                else -> 6L
            }
        }
    }
}

internal class RuntimeProductionInitialLeaseV1(private val publicationDiagnostic: LongArray = LongArray(16) { -1 }) {
    private var deadline = 0L
    private var installed = false
    private var releaseStarted = false
    private var released = false
    private var unproven = false
    @Synchronized fun install(deadline: Long) {
        check(!installed && !releaseStarted && !unproven && deadline > 0)
        this.deadline = deadline; installed = true
    }
    @Synchronized fun installIfCurrent(deadline: Long, now: Long): Boolean {
        check(!installed && !releaseStarted && !unproven)
        require(deadline > 0 && now >= 0)
        if (now >= deadline) return false
        install(deadline)
        return true
    }
    @Synchronized fun wasInstalled(): Boolean = installed
    @Synchronized fun isCurrent(now: Long): Boolean = installed && !releaseStarted && !unproven && now < deadline
    @Synchronized fun isReleased(): Boolean = released && !unproven
    @Synchronized private fun observationPhase(): Int = when {
        unproven || (releaseStarted && (!released || !installed)) -> -1
        !installed -> 0
        released -> 2
        else -> 1
    }
    /** Read-only stage selection; no monitor spans either broker observation. */
    fun observeCurrent(now: () -> Long, beforePublication: () -> Boolean, afterRelease: () -> Boolean): Boolean {
        val phase = observationPhase()
        val current = when (phase) {
            0 -> beforePublication()
            1 -> isCurrent(now())
            2 -> afterRelease()
            else -> false
        }
        return current && phase == observationPhase() && (phase != 1 || isCurrent(now()))
    }
    fun release(action: () -> Boolean): Boolean {
        synchronized(this) {
            if (released && !unproven) return true
            if (!installed || releaseStarted || unproven) {
                recordProductionPublicationV1(publicationDiagnostic, 8, 2, 3, state = if (installed) 1 else 0)
                throw RuntimeAuthorityCleanupUnprovenException()
            }
            releaseStarted = true
        }
        val result = try { action().also {
            recordProductionPublicationV1(publicationDiagnostic, 8, 3, if (it) 0 else 1,
                predicate = if (it) 1 else 0, state = 1)
        } } catch (failure: Throwable) {
            recordProductionPublicationV1(publicationDiagnostic, 8, 3, 2, state = 1, failure = failure)
            false
        }
        return synchronized(this) {
            if (!result) unproven = true
            if (unproven) throw RuntimeAuthorityCleanupUnprovenException()
            released = true
            recordProductionPublicationV1(publicationDiagnostic, 8, 4, 0, predicate = 1, state = 1, completed = 1)
            true
        }
    }

    /** Failed opening owns cleanup even when it never installed a local publication lease. */
    fun cancelBeforeInstall(cancel: () -> Int): Boolean {
        synchronized(this) {
            if (!installed && released && !unproven) return true
            if (installed || releaseStarted || unproven) {
                unproven = true
                throw RuntimeAuthorityCleanupUnprovenException()
            }
            releaseStarted = true
        }
        val clean = try {
            val status = cancel()
            recordProductionPublicationV1(publicationDiagnostic, 8, 3, if (status == 1) 0 else 1,
                predicate = if (status == 1) 1 else 0, state = 0)
            status == 1
        } catch (failure: Throwable) {
            recordProductionPublicationV1(publicationDiagnostic, 8, 3, 2, state = 0, failure = failure)
            false
        }
        return synchronized(this) {
            if (!clean) unproven = true
            if (unproven) throw RuntimeAuthorityCleanupUnprovenException()
            released = true
            recordProductionPublicationV1(publicationDiagnostic, 8, 4, 0, predicate = 1, state = 0, completed = 1)
            true
        }
    }
}

/** The real call owner's post-action checks must finish before diagnostic returned-success. */
internal fun runProductionPublicationCallV1(lease: RuntimeProductionInitialLeaseV1, diagnostic: LongArray,
    age: () -> Long, call: () -> Boolean): Boolean {
    try {
        return call().also { if (it) {
            runCatching { recordProductionPublicationV1(diagnostic, 0, 7, 0, age(), state = 1, completed = 1) }
        } }
    } catch (failure: Throwable) {
        if (lease.wasInstalled()) runCatching {
            recordProductionPublicationV1(diagnostic, 0, 6, 2, age(), state = 1, failure = failure)
        }
        throw failure
    }
}

/** Pending cleanup consumes the existing call deadline, not an unrelated poll quota. */
internal fun awaitProductionResponseReadyV1(isLive: () -> Boolean, readStatus: () -> Int,
    waitPending: () -> Unit = { java.util.concurrent.locks.LockSupport.parkNanos(1_000_000) }) {
    while (true) {
        check(isLive())
        when (readStatus()) {
            1 -> { check(isLive()); return }
            2 -> waitPending()
            else -> error("AUTHORITY_RESPONSE_REJECTED")
        }
    }
}

internal class RuntimeProductionClientCaptureV1(val offer: RuntimeProductionAuthorityOfferV1,
    val capture: RuntimeCaptureSnapshotV1) : Closeable {
    override fun close() = capture.close()
    override fun toString() = "RuntimeProductionClientCaptureV1(redacted)"
}

internal fun retireProductionProviderV1(providerDead: Boolean, publicationReleased: Boolean,
    cancel: () -> Boolean): Boolean = if (providerDead && publicationReleased) true else cancel()

/** Sole v3 broker connection of a service-owned attempt; never enters the legacy controller. */
internal class RuntimeProductionAuthorityClientV1(private val context: Context,
    private val component: ComponentName, private val consumerEpoch: String,
    private val primitives: DurableFilePrimitives, ownerCancelled: () -> Boolean = { false },
    private val publicationDiagnostic: LongArray = LongArray(16) { -1 },
    private val onProviderDeathSettled: () -> Unit = {},
    private val onInvalidated: (pendingPublication: Boolean) -> Unit) : Closeable {
    @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
    private val state = Object()
    private val calls = RuntimeProductionCallOwnerV1(ownerCancelled)
    private val timer = Executors.newSingleThreadScheduledExecutor { job ->
        Thread(job, "production-authority-expiry").apply { isDaemon = true }
    }
    private var bound = false
    private var remote: IBinder? = null
    private var providerEpoch: String? = null
    private var providerPid = 0
    private var offered: RuntimeProductionAuthorityOfferV1? = null
    private var terminal = false
    private var invalidating = false
    private var invalidationFinished = false
    private var publicationPending = false
    private var pendingInvalidation = false
    private var authorityRejected = false
    private var providerDeathStarted = false
    private var providerDeathSettled = false
    private var unproven = false
    private val initialLease = RuntimeProductionInitialLeaseV1(publicationDiagnostic)
    private var cleanupStarted = false
    private var cleanupComplete = false
    private val death = IBinder.DeathRecipient { providerDied() }
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            synchronized(state) {
                if (terminal || name != component || service == null || remote != null) terminal = true
                else remote = service
                state.notifyAll()
            }
        }
        override fun onServiceDisconnected(name: ComponentName?) {
            if (synchronized(state) { remote?.isBinderAlive == false }) providerDied() else invalidate()
        }
        override fun onBindingDied(name: ComponentName?) = invalidate()
        override fun onNullBinding(name: ComponentName?) = invalidate()
    }
    private val lifetime = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != RuntimeProductionReissueWireV1.INVALIDATED) return super.onTransact(code, data, reply, flags)
            if (reply == null || flags and IBinder.FLAG_ONEWAY != 0 || data.dataSize() > 4096 ||
                getCallingUid() != context.applicationInfo.uid) return false
            return try {
                data.enforceInterface(RuntimeProductionReissueWireV1.CALLBACK)
                require(data.readInt() == 3)
                val provider = RuntimeAuthorityReissueWire.id(data)
                val consumer = RuntimeAuthorityReissueWire.id(data)
                require(data.dataAvail() == 0)
                synchronized(state) {
                    require(provider == providerEpoch && consumer == consumerEpoch && getCallingPid() == providerPid)
                }
                val pending = synchronized(state) { publicationPending }
                synchronized(state) { authorityRejected = true }
                invalidate(pending)
                synchronized(state) { check(!unproven) }
                reply.writeNoException(); reply.writeInt(synchronized(state) { if (pendingInvalidation) 2 else 1 }); true
            } catch (_: Throwable) {
                synchronized(state) { unproven = true }
                reply.setDataSize(0); reply.writeNoException(); reply.writeInt(0); true
            }
        }
    }

    init { require(RuntimeAuthorityLimits.validId(consumerEpoch) && component.packageName == context.packageName) }

    fun capture(call: Long, start: RuntimeReissueStart): RuntimeProductionClientCaptureV1 =
        execute(call, start.deadlineElapsedMillis) {
            require(start.consumerEpoch == consumerEpoch && start.isLiveAt(SystemClock.elapsedRealtime()))
            synchronized(state) { check(offered == null && !terminal) }
            connect(call, start.deadlineElapsedMillis)
            val offer = rpc(RuntimeProductionReissueWireV1.OFFER, { RuntimeAuthorityReissueWire.writeStart(it, start) }) {
                check(it.readInt() == 1)
                val offer = RuntimeAuthorityReissueWire.readOffer(it)
                require(it.readInt() == 1)
                RuntimeProductionAuthorityOfferV1(offer.copy(presentation = RuntimeProductionReissueWireV1.readPresentation(it)))
            }
            synchronized(state) {
                check(!terminal && offer.offer.start == start && offer.offer.providerEpoch == providerEpoch)
                offered = offer
            }
            val verified = exchange(call, offer, RuntimeAuthorityPurpose.FULL_AUTHORITY)
            verified.use { RuntimeProductionClientCaptureV1(offer, checkNotNull(it.takeCapture())) }
        }

    /** Acquires one real protected lease and installs invalidation before native publication. */
    fun acquireInitialPublication(call: Long): Boolean {
        synchronized(state) { publicationPending = true }
        var phase = 1
        var started = -1L
        var predicate = -1L
        var installed = -1L
        try {
        val offer = synchronized(state) { check(!initialLease.wasInstalled() && !terminal); checkNotNull(offered) }
        installed = 0
        val acquired = runProductionPublicationCallV1(initialLease, publicationDiagnostic,
            { if (started < 0) -1 else SystemClock.elapsedRealtime() - started }) {
          execute(call, offer.offer.start.deadlineElapsedMillis) {
            // This sample is diagnostic only. The protected owner supplies the immutable deadline.
            started = SystemClock.elapsedRealtime()
            phase = 2
            exchange(call, offer, RuntimeAuthorityPurpose.PRE_TUN).close()
            phase = 3
            exchange(call, offer, RuntimeAuthorityPurpose.PRE_ACTIVE).close()
            phase = 4
            val providerDeadline = rpc(RuntimeProductionReissueWireV1.COMPLETE,
                { it.writeString(offer.offer.start.requestId) }) {
                val bytes = it.dataAvail()
                require(bytes == 12)
                RuntimeProductionReissueWireV1.readCompletionReply(bytes, it.readInt(), it.readLong(), offer.offer.start.deadlineElapsedMillis)
            }
            val complete = providerDeadline != null
            predicate = if (complete) 1 else 0
            check(complete)
            phase = 5; predicate = -1
            synchronized(state) {
                check(!terminal)
                val now = SystemClock.elapsedRealtime()
                val deadline = checkNotNull(providerDeadline)
                predicate = if (now < deadline) 1 else 0
                if (predicate == 0L) {
                    recordProductionPublicationV1(publicationDiagnostic, 0, 5, 1, now - started, predicate, 0)
                    return@execute false
                }
                predicate = -1
                phase = 6
                check(initialLease.installIfCurrent(deadline, now))
                installed = 1
            }
            true
          }
        }
        return acquired
        } catch (failure: Throwable) {
            recordProductionPublicationV1(publicationDiagnostic, 0, phase, if (predicate == 0L) 1 else 2,
                if (started < 0) -1 else SystemClock.elapsedRealtime() - started,
                predicate, installed, failure = failure)
            // The known publication fence cancels this call. Its returned lease is
            // still retired by publicationClose; cancellation is not failed cleanup.
            if (failure is CancellationException && hasFencedPendingCleanup()) return false
            throw failure
        }
    }

    fun initialPublicationCurrent(): Boolean {
        val snapshot = synchronized(state) {
            if (terminal || unproven || !initialLease.isCurrent(SystemClock.elapsedRealtime())) return false
            remote
        }
        val current = snapshot?.isBinderAlive == true
        return current && synchronized(state) { !terminal && !unproven && initialLease.isCurrent(SystemClock.elapsedRealtime()) && remote === snapshot }
    }

    fun releaseInitialPublication(): Boolean {
        var phase = 1
        try {
        val offer = synchronized(state) { checkNotNull(offered) }
        // Retirement has no borrowed native context and remains required after expiry/invalidation.
        val released = calls.runCleanup {
            phase = 2
            if (initialLease.wasInstalled()) {
                initialLease.release {
                    phase = 3
                    val status = rpc(RuntimeProductionReissueWireV1.RELEASE_LEASE,
                        { it.writeString(offer.offer.start.requestId) }) { it.readInt().also { value -> require(value in 0..2) } }
                    status == 1 || status == 2 && hasFencedPendingCleanup()
                }
            } else {
                initialLease.cancelBeforeInstall {
                    phase = 3
                    val status = rpc(RuntimeProductionReissueWireV1.CANCEL,
                        { RuntimeAuthorityReissueWire.writeStart(it, offer.offer.start) }) { it.readInt() }
                    if (status == 2 && hasFencedPendingCleanup()) {
                        // CANCEL alone says pending, not clean. Separately require
                        // proof that all ordinary provider resources, including the
                        // lease, closed. Its registration remains held until close().
                        val leaseStatus = rpc(RuntimeProductionReissueWireV1.RELEASE_LEASE,
                            { it.writeString(offer.offer.start.requestId) }) { it.readInt() }
                        if (leaseStatus == 2) 1 else status
                    } else status
                }.also {
                    // Native failed-opening teardown owns the containing callback. Do not
                    // recursively invalidate it; prevent any later local acquisition instead.
                    synchronized(state) { terminal = true; state.notifyAll() }
                }
            }.also { phase = 4 }
        }
        recordProductionPublicationV1(publicationDiagnostic, 8, 5, 0, completed = 1, state = if (initialLease.wasInstalled()) 1 else 0)
        return released
        } catch (failure: Throwable) {
            recordProductionPublicationV1(publicationDiagnostic, 8, phase, 2, failure = failure)
            throw failure
        } finally { synchronized(state) { publicationPending = false } }
    }

    fun revalidateCurrent(call: Long, deadline: Long): Boolean = execute(call, deadline) {
        val offer = synchronized(state) { check(!terminal); checkNotNull(offered) }
        fun observe(code: Int): Boolean = rpc(code, {
            RuntimeAuthorityReissueWire.writeOffer(it, offer.offer); it.writeInt(1); it.writeLong(deadline)
        }) { val value = it.readInt(); require(value in 0..1); value == 1 }
        val current = initialLease.observeCurrent(SystemClock::elapsedRealtime,
            { observe(RuntimeProductionReissueWireV1.PREPUBLICATION_CURRENT) },
            { observe(RuntimeProductionReissueWireV1.REGISTERED_CURRENT) })
        if (!current) {
            synchronized(state) { authorityRejected = true }
            invalidate()
        }
        current && synchronized(state) { !terminal }
    }

    fun captureCurrent(): Boolean {
        val snapshot = synchronized(state) {
            if (terminal || unproven || offered == null) return false
            Triple(remote, checkNotNull(offered), initialLease.wasInstalled())
        }
        val current = snapshot.first?.isBinderAlive == true &&
            (snapshot.third || snapshot.second.offer.start.isLiveAt(SystemClock.elapsedRealtime()))
        return current && synchronized(state) { !terminal && !unproven && remote === snapshot.first && offered === snapshot.second }
    }

    /** Death is availability loss, never permission to reuse the old capture. */
    fun providerDeathCanRetry(): Boolean = synchronized(state) {
        providerDeathSettled && !authorityRejected && !unproven && !publicationPending && initialLease.isReleased() &&
            remote?.isBinderAlive == false
    }

    fun providerDeathInProgress(): Boolean = synchronized(state) { providerDeathStarted && !providerDeathSettled }

    private fun providerDied() {
        synchronized(state) {
            if (providerDeathStarted) return
            providerDeathStarted = true
        }
        // Fence first. The service worker owns joined native retirement, not Binder's
        // death callback. Duplicate framework notifications share this one fence.
        invalidate(pendingPublication = true)
        synchronized(state) { providerDeathSettled = true }
        onProviderDeathSettled()
    }

    fun cancelCall(call: Long): Boolean {
        val cancelled = calls.cancel(call)
        synchronized(state) { state.notifyAll() }
        return cancelled
    }

    private fun <T> execute(call: Long, deadline: Long, action: () -> T): T = calls.run(call) {
        require(RuntimeProductionReissueWireV1.validObservationDeadline(SystemClock.elapsedRealtime(), deadline))
        val expiry = timer.schedule({ cancelCall(call) }, deadline - SystemClock.elapsedRealtime(), TimeUnit.MILLISECONDS)
        try {
            check(live(call, deadline))
            val result = action()
            if (!live(call, deadline)) {
                (result as? AutoCloseable)?.close()
                throw CancellationException("AUTHORITY_CALL_CANCELLED")
            }
            result
        } finally { expiry.cancel(false) }
    }

    private fun live(call: Long, deadline: Long): Boolean = !calls.isCancelled(call) &&
        synchronized(state) { !terminal && !unproven } && SystemClock.elapsedRealtime() < deadline

    private fun connect(call: Long, deadline: Long) {
        val info = context.packageManager.getServiceInfo(component, 0)
        require(info.name == component.className && info.applicationInfo.uid == context.applicationInfo.uid &&
            !info.exported && !info.directBootAware && info.processName == context.applicationInfo.processName)
        synchronized(state) { check(!bound && !terminal); bound = true }
        if (!context.bindService(Intent(RuntimeAuthorityReissueWire.ACTION).setComponent(component), connection, Context.BIND_AUTO_CREATE)) {
            synchronized(state) { bound = false; terminal = true }
            error("AUTHORITY_BIND_REJECTED")
        }
        val service = synchronized(state) {
            while (remote == null && live(call, deadline)) state.wait(minOf(100, deadline - SystemClock.elapsedRealtime()).coerceAtLeast(1))
            check(live(call, deadline)); checkNotNull(remote)
        }
        service.linkToDeath(death, 0)
        rpc(RuntimeProductionReissueWireV1.HELLO, { it.writeString(consumerEpoch); it.writeInt(1) }) {
            check(it.readInt() == 1)
            val epoch = RuntimeAuthorityReissueWire.id(it); val pid = it.readInt(); val uid = it.readInt()
            require(epoch != consumerEpoch && pid > 0 && pid != Process.myPid() && uid == context.applicationInfo.uid)
            require(it.readInt() == 3 && it.readInt() == 1)
            synchronized(state) { check(!terminal); providerEpoch = epoch; providerPid = pid }
        }
    }

    private fun exchange(call: Long, offer: RuntimeProductionAuthorityOfferV1,
        purpose: RuntimeAuthorityPurpose): RuntimeVerifiedProductionCaptureV1 {
        val resources = arrayOfNulls<Closeable>(5)
        var count = 0
        fun <T : Closeable> own(value: T): T { check(count < resources.size); resources[count++] = value; return value }
        val deadline = offer.offer.start.deadlineElapsedMillis
        fun pipe(): Pair<RuntimeAuthorityPipeOwner, RuntimeAuthorityPipeOwner> {
            val raw = ParcelFileDescriptor.createReliablePipe()
            var input: ParcelFileDescriptor? = raw[0]; var output: ParcelFileDescriptor? = raw[1]
            try {
                val reader = checkNotNull(input).also { input = null }
                val read = own(RuntimeAuthorityPipeOwner.take(reader, primitives, context.applicationInfo.uid.toLong(), 0, deadline) { live(call, deadline) })
                val writer = checkNotNull(output).also { output = null }
                val write = own(RuntimeAuthorityPipeOwner.take(writer, primitives, context.applicationInfo.uid.toLong(), 1, deadline) { live(call, deadline) })
                return read to write
            } finally {
                var clean = true
                try { input?.close() } catch (_: Throwable) { clean = false }
                try { output?.close() } catch (_: Throwable) { clean = false }
                if (!clean) throw RuntimeAuthorityCleanupUnprovenException()
            }
        }
        val key = ByteArray(32)
        var frame: ByteArray? = null
        var verified: RuntimeVerifiedProductionCaptureV1? = null
        var cleanup: Throwable? = null
        try {
            val cap = pipe(); val output = pipe()
            val id = UUID.randomUUID().toString().replace("-", "")
            val length = RuntimeProductionAuthorityFrameCodecV1.encodedLength(if (purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY) offer.offer.payloadLength else 0)
            val descriptor = output.first.identity.descriptor(id, length)
            val request = offer.request(purpose, descriptor)
            SecureRandom().nextBytes(key)
            val verifier = own(RuntimeProductionAuthorityFrameCodecV1.verifier(key.copyOf(), request))
            RuntimeReissuePipeIo.writeExact(cap.second, key) { live(call, deadline) }; cap.second.close()
            check(rpc(RuntimeProductionReissueWireV1.RESPONSE, {
                it.writeString(offer.offer.start.requestId); it.writeInt(purpose.wire); it.writeString(id); it.writeLong(deadline)
                // Ownership transfer must silently close the sender PFD; normal close
                // can consume the receiver's reliable-pipe status (AOSP API26 PFD).
                cap.first.withDescriptor { fd -> it.writeTypedObject(fd, android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE) }
                output.second.withDescriptor { fd -> it.writeTypedObject(fd, android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE) }
            }) { it.readInt() == 1 })
            cap.first.close(); output.second.close(); key.fill(0)
            frame = RuntimeReissuePipeIo.readExact(output.first, length) { live(call, deadline) }
            awaitProductionResponseReadyV1({ live(call, deadline) }, {
                rpc(RuntimeProductionReissueWireV1.RESPONSE_READY, {
                    it.writeString(offer.offer.start.requestId); it.writeInt(purpose.wire)
                }) { it.readInt() }
            })
            val result = verifier.verifyAndConsume(checkNotNull(frame), descriptor, SystemClock.elapsedRealtime())
            check(result is RuntimeProductionFrameVerificationV1.Verified)
            verified = result.authority
        } finally {
            key.fill(0); frame?.fill(0)
            for (index in count - 1 downTo 0) try { resources[index]?.close() } catch (failure: Throwable) { cleanup = failure }
            if (cleanup != null) {
                verified?.close()
                synchronized(state) { terminal = true; unproven = true }
                throw RuntimeAuthorityCleanupUnprovenException()
            }
        }
        return checkNotNull(verified)
    }

    private fun <T> rpc(code: Int, write: (Parcel) -> Unit, read: (Parcel) -> T): T {
        val service = synchronized(state) { checkNotNull(remote) }
        val data = Parcel.obtain(); val reply = Parcel.obtain()
        return try {
            data.writeInterfaceToken(RuntimeProductionReissueWireV1.DESCRIPTOR); data.writeInt(3); data.writeStrongBinder(lifetime)
            write(data); require(data.dataSize() <= 4096)
            check(service.transact(code, data, reply, 0)); reply.readException(); require(reply.dataSize() <= 4096)
            read(reply).also { require(reply.dataAvail() == 0) }
        } finally { reply.recycle(); data.recycle() }
    }
    private fun simple(code: Int, id: String): Boolean = rpc(code, { it.writeString(id) }) {
        val status = it.readInt(); require(status in 0..1); status == 1
    }

    private fun hasFencedPendingCleanup(): Boolean = synchronized(state) {
        terminal && pendingInvalidation && invalidationFinished && !unproven
    }

    private fun invalidate(pendingPublication: Boolean = false) {
        synchronized(state) {
            terminal = true; state.notifyAll()
            if (invalidationFinished) return
            if (invalidating) { unproven = true; return }
            invalidating = true
            pendingInvalidation = pendingPublication
        }
        try { onInvalidated(pendingPublication) }
        catch (_: Throwable) { synchronized(state) { unproven = true } }
        finally { synchronized(state) { invalidating = false; invalidationFinished = true } }
    }

    override fun close() {
        synchronized(state) {
            if (cleanupComplete && !unproven) return
            terminal = true; state.notifyAll()
            if (invalidating || cleanupStarted) { unproven = true; throw RuntimeAuthorityCleanupUnprovenException() }
            cleanupStarted = true
        }
        // External native teardown must finish ordinary callbacks first. Cleanup uses
        // the same bounded worker, never the invalidation handler or a replacement.
        try {
            calls.runCleanup {
                val service = synchronized(state) { remote }
                val offer = synchronized(state) { offered }
                var clean = true
                if (service != null && offer != null) try {
                    // The containing owner calls close only after actual native and
                    // registration retirement. Pending fencing alone never sends this proof.
                    val opcode = synchronized(state) { if (pendingInvalidation) RuntimeProductionReissueWireV1.CANCEL_RETIRED else RuntimeProductionReissueWireV1.CANCEL }
                    // The caller already proved native/registration retirement. A dead
                    // remote process cannot retain its in-memory registration or ACK CANCEL.
                    // Interrupted publication and every local cleanup failure remain terminal.
                    if (!retireProductionProviderV1(!service.isBinderAlive, initialLease.isReleased()) {
                        rpc(opcode, { RuntimeAuthorityReissueWire.writeStart(it, offer.offer.start) }) { it.readInt() } == 1
                    }) clean = false
                } catch (_: Throwable) { clean = false }
                if (service != null) try { service.unlinkToDeath(death, 0) } catch (_: Throwable) { clean = false }
                val unbind = synchronized(state) { bound.also { bound = false } }
                if (unbind) try { context.unbindService(connection) } catch (_: Throwable) { clean = false }
                synchronized(state) {
                    if (!clean) unproven = true
                    if (unproven) throw RuntimeAuthorityCleanupUnprovenException()
                    remote = null
                }
            }
        } catch (_: Throwable) {
            synchronized(state) { unproven = true }
            throw RuntimeAuthorityCleanupUnprovenException()
        } finally { timer.shutdown(); calls.close() }
        synchronized(state) { cleanupComplete = true }
    }
}
