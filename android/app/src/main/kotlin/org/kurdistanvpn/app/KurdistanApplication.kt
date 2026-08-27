// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.app.Application
import android.app.ActivityManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.os.Looper
import android.os.Parcel
import android.os.Process
import android.os.SystemClock
import android.os.UserManager
import java.io.Closeable
import java.io.OutputStream
import java.util.UUID
import java.util.concurrent.ExecutorService
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import org.kurdistanvpn.data.protectedstate.ProtectedAuthorityEnvironment
import org.kurdistanvpn.data.protectedstate.AuthorityReadFailure
import org.kurdistanvpn.data.protectedstate.AuthorityReadResult
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.kurdistanvpn.data.protectedstate.ProtectedStateProcessOwner
import org.kurdistanvpn.data.protectedstate.ProtectedRuntimeRevisionLease
import org.kurdistanvpn.data.protectedstate.ProtectedRuntimeRevisionRegistration
import org.kurdistanvpn.core.nativeapi.DurableFilePrimitives
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.runtime.api.RuntimeAuthorityLimits
import org.kurdistanvpn.runtime.api.RuntimeAuthorityRequest
import org.kurdistanvpn.runtime.android.RuntimeAuthorityCleanupUnprovenException
import org.kurdistanvpn.runtime.android.KurdVpnService
import org.kurdistanvpn.runtime.android.RuntimeReissueStart
import org.kurdistanvpn.runtime.android.RuntimeMutationQuiescenceWire

class KurdistanApplication : Application(), RuntimeAuthorityReissueOwner {
    private val nativeCore by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { NativeBridge() }
    private val mutationQuiescence by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        VpnMutationQuiescenceClient(this)
    }
    internal val protectedStateProcessOwner by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        requireDefaultProcess()
        ProtectedStateProcessOwner({ mutationQuiescence.acquire() }, SystemClock::elapsedRealtime)
    }
    val compositionRoot: Phase9CompositionRoot by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        requireDefaultProcess()
        Phase9CompositionRoot.create(this, protectedStateProcessOwner)
    }
    override val runtimeAuthorityPipePrimitives: DurableFilePrimitives get() = nativeCore.durableFiles()
    override val runtimeAuthorityReissue: RuntimeAuthorityReissueIpcAdapter by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        requireDefaultProcess()
        val backend = DefaultProcessAuthorityBackend(::isUnlocked, ::isPrepared, SystemClock::elapsedRealtime,
            ::openAuthorityReadOwner, ::acquireRevisionLease)
        RuntimeAuthorityReissueIpcAdapter(Process.myUid().toLong(), java.util.UUID.randomUUID().toString().replace("-", ""),
            backend, SystemClock::elapsedRealtime)
    }

    private fun isUnlocked(): Boolean = getSystemService(UserManager::class.java).isUserUnlocked
    private fun isPrepared(): Boolean = VpnService.prepare(this) == null

    private fun requireDefaultProcess() {
        val current = getSystemService(ActivityManager::class.java).runningAppProcesses
            ?.singleOrNull { it.pid == Process.myPid() && it.uid == Process.myUid() }
        check(current?.processName == applicationInfo.processName) { "DEFAULT_PROCESS_REQUIRED" }
    }

    private fun existingFacade(): ProtectedStateApplicationFacade? {
        if (!isUnlocked() || !isPrepared()) return null
        return when (val opened = ProtectedStateApplicationFacade.openExistingReadOnly(this,
            runtimeAuthorityPipePrimitives, nativeCore, protectedStateProcessOwner)) {
            is ProtectedStateApplicationFacade.OpenResult.Ready -> opened.facade
            else -> null
        }
    }

    private fun openAuthorityReadOwner(environment: ProtectedAuthorityEnvironment): ExistingRestorationReadOwner? {
        val facade = existingFacade() ?: return null
        return object : ExistingRestorationReadOwner {
            override fun prepare(): RuntimeReissueMaterial? = when (val result = facade.reconstructAuthority(environment)) {
                is AuthorityReadResult.Rejected -> {
                    if (result.category == AuthorityReadFailure.CLEANUP_UNPROVEN) throw RuntimeAuthorityCleanupUnprovenException()
                    null
                }
                is AuthorityReadResult.Ready -> object : RuntimeReissueMaterial {
                    private val authority = result.authority
                    override val revision = authority.revision
                    override val signedRetryBudget = authority.signedRetryBudget
                    override val payloadLength = authority.length
                    override fun writeTo(output: OutputStream) = authority.writeTo(output)
                    override fun close() = authority.close()
                }
            }
            override fun close() = facade.close()
        }
    }

    private fun acquireRevisionLease(request: RuntimeAuthorityRequest, environment: ProtectedAuthorityEnvironment): RuntimeProviderRevisionLease? {
        val facade = existingFacade() ?: return null
        var registration: ProtectedRuntimeRevisionRegistration? = null
        var acquired: ProtectedRuntimeRevisionLease? = null
        var transferred = false
        try {
            if (facade.snapshot()?.revision != request.revision) return null
            registration = protectedStateProcessOwner.registerRuntimeRevision(request.consumerEpoch, request.generation, request.revision)
                ?: return null
            val deadline = minOf(request.deadlineElapsedMillis, Math.addExact(SystemClock.elapsedRealtime(), 2000L))
            acquired = registration.acquireFinalLease(deadline) ?: return null
            val ownedRegistration = registration
            val ownedLease = acquired
            val result = object : RuntimeProviderRevisionLease {
                private var released = false
                private var activeRegistered = false
                private var cleanupUnproven = false
                override val revision = request.revision
                @Synchronized override fun isCurrent(): Boolean {
                    if (released || cleanupUnproven || !ownedLease.isCurrent()) return false
                    if (!environment.isUserUnlocked() || !environment.isConsentPrepared() || environment.isCancelled()) return false
                    // The immutable snapshot and physical witnesses are reread under the
                    // same mutation exclusion used by the broker. External trust/expiry
                    // and native key bindings are revalidated, never cached from OFFER.
                    val fresh = facade.reconstructAuthority(environment)
                    if (fresh !is AuthorityReadResult.Ready) return false
                    return try {
                        fresh.authority.revision == revision && fresh.authority.signedRetryBudget == request.signedRetryBudget && ownedLease.isCurrent()
                    } finally { fresh.authority.close() }
                }
                @Synchronized override fun registerActive(onInvalidated: () -> Unit): Closeable {
                    check(!activeRegistered && isCurrent()) { "FINAL_REVISION_LEASE_INVALID" }
                    val owner = ownedLease.registerActive(onInvalidated)
                    activeRegistered = true
                    return owner
                }
                @Synchronized override fun close() {
                    if (released) {
                        if (cleanupUnproven) throw RuntimeAuthorityCleanupUnprovenException()
                        return
                    }
                    released = true
                    var clean = true
                    try { ownedLease.close() } catch (_: Throwable) { clean = false }
                    try { facade.close() } catch (_: Throwable) { clean = false }
                    if (!activeRegistered) try { ownedRegistration.close() } catch (_: Throwable) { clean = false }
                    cleanupUnproven = !clean
                    if (!clean) throw RuntimeAuthorityCleanupUnprovenException()
                }
            }
            transferred = true
            return result
        } finally {
            if (!transferred) {
                var clean = true
                try { acquired?.close() } catch (_: Throwable) { clean = false }
                try { registration?.close() } catch (_: Throwable) { clean = false }
                try { facade.close() } catch (_: Throwable) { clean = false }
                if (!clean) throw RuntimeAuthorityCleanupUnprovenException()
            }
        }
    }
}

/** The default-process reader owns only existing CE descriptors and an existing key lookup.
 * Its implementation must close internally acquired resources if construction throws. */
internal interface ExistingRestorationReadOwner : Closeable {
    fun prepare(): RuntimeReissueMaterial?
}

/** Shared manual/system provider path. It cannot initialize storage, normalize preferences,
 * manufacture authority, or retain a wire between requests. Android binding supplies only
 * lifecycle metadata; all material is reconstructed through the committed read facade. */
internal class DefaultProcessAuthorityBackend(
    private val unlocked: () -> Boolean,
    private val prepared: () -> Boolean,
    private val now: () -> Long,
    private val openExisting: (ProtectedAuthorityEnvironment) -> ExistingRestorationReadOwner?,
    private val lease: (RuntimeAuthorityRequest, ProtectedAuthorityEnvironment) -> RuntimeProviderRevisionLease?,
) : RuntimeAuthorityReissueBackend {
    private fun admitted(start: RuntimeReissueStart): Boolean =
        try { unlocked() && prepared() && start.isLiveAt(now()) } catch (_: Throwable) { false }

    private fun environment(start: RuntimeReissueStart) = object : ProtectedAuthorityEnvironment {
        override fun isUserUnlocked() = unlocked()
        override fun isConsentPrepared() = prepared()
        override fun isCancelled() = !start.isLiveAt(now())
        override fun elapsedRealtimeMillis() = now()
    }

    override fun observe(start: RuntimeReissueStart): RuntimeAuthorityProviderState? {
        val current = prepare(start) ?: return null
        return current.use {
            if (!admitted(start)) null else RuntimeAuthorityProviderState(true, true, true, it.revision, it.signedRetryBudget)
        }
    }

    override fun prepare(start: RuntimeReissueStart): RuntimeReissueMaterial? {
        if (!admitted(start)) return null // before even opening credential-protected state
        var reader: ExistingRestorationReadOwner? = null
        var material: RuntimeReissueMaterial? = null
        var transferred = false
        try {
            reader = openExisting(environment(start)) ?: return null
            material = reader.prepare() ?: return null
            require(RuntimeAuthorityLimits.validRevision(material.revision) &&
                material.signedRetryBudget in 0..RuntimeAuthorityLimits.MAX_RETRIES &&
                start.retryAttempt <= material.signedRetryBudget &&
                material.payloadLength in 1..RuntimeAuthorityLimits.MAX_PAYLOAD_BYTES)
            if (!admitted(start)) return null
            return OwnedMaterial(reader, material) { admitted(start) }.also { transferred = true }
        } catch (failure: RuntimeAuthorityCleanupUnprovenException) { throw failure }
        catch (_: Exception) { return null }
        finally {
            if (!transferred) {
                var clean = true
                try { material?.close() } catch (_: Throwable) { clean = false }
                try { reader?.close() } catch (_: Throwable) { clean = false }
                if (!clean) throw RuntimeAuthorityCleanupUnprovenException()
            }
        }
    }

    override fun acquireRevisionLease(request: RuntimeAuthorityRequest): RuntimeProviderRevisionLease? {
        val start = RuntimeReissueStart(request.consumerEpoch, request.requestId, request.generation,
            request.trigger, request.retryAttempt, request.deadlineElapsedMillis)
        if (!admitted(start)) return null
        return lease(request, environment(start))
    }

    private class OwnedMaterial(private val reader: ExistingRestorationReadOwner,
        private val authority: RuntimeReissueMaterial, private val admitted: () -> Boolean) : RuntimeReissueMaterial {
        private enum class State { OPEN, CLEANUP_REQUIRED, CLEAN, UNPROVEN }
        private var state = State.OPEN
        override val revision = authority.revision
        override val signedRetryBudget = authority.signedRetryBudget
        override val payloadLength = authority.payloadLength
        @Synchronized override fun writeTo(output: OutputStream) {
            check(state == State.OPEN && admitted()) { "AUTHORITY_NOT_LIVE" }
            authority.writeTo(output)
            check(admitted()) { "AUTHORITY_NO_LONGER_LIVE" }
        }
        @Synchronized override fun close() {
            if (state == State.CLEAN) return
            if (state != State.OPEN) throw RuntimeAuthorityCleanupUnprovenException()
            state = State.CLEANUP_REQUIRED
            var clean = true
            try { authority.close() } catch (_: Throwable) { clean = false }
            try { reader.close() } catch (_: Throwable) { clean = false }
            state = if (clean) State.CLEAN else State.UNPROVEN
            if (!clean) throw RuntimeAuthorityCleanupUnprovenException()
        }
    }
}

/** Default-process holder for the VPN process's in-memory quiescence proof.
 * A missing, dead, malformed, or indeterminate peer is never treated as clean. */
private class VpnMutationQuiescenceClient(private val context: Context) {
    private val monitor = Any()
    private val lifetime = Binder()
    private val ipc = Executors.newSingleThreadExecutor { task ->
        Thread(task, "kurd-vpn-quiescence").apply { isDaemon = true }
    }
    private var remote: IBinder? = null
    private var binding = false
    private var poisoned = false
    private val admission = BoundedMutationQuiescenceAdmission(
        now = SystemClock::elapsedRealtime,
        executor = ipc,
        poison = ::poison,
    )
    private val remoteDeath = IBinder.DeathRecipient { poison() }
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            if (name != component || service == null) return poison()
            try {
                service.linkToDeath(remoteDeath, 0)
                val retained = synchronized(monitor) {
                    if (!poisoned) {
                        remote = service
                        binding = false
                        true
                    } else {
                        false
                    }
                }
                if (!retained) try { service.unlinkToDeath(remoteDeath, 0) } catch (_: Throwable) { }
            } catch (_: Throwable) { poison() }
        }
        override fun onServiceDisconnected(name: ComponentName?) = poison()
        override fun onBindingDied(name: ComponentName?) = poison()
        override fun onNullBinding(name: ComponentName?) = poison()
    }
    private val component = ComponentName(context, KurdVpnService::class.java)

    init { bindIfNeeded() }

    fun acquire(): AutoCloseable? {
        check(Looper.myLooper() != Looper.getMainLooper()) { "MUTATION_QUIESCENCE_MAIN_THREAD" }
        val service = synchronized(monitor) { if (poisoned) null else remote }
        if (service == null || !service.isBinderAlive) {
            if (service != null) poison()
            bindIfNeeded()
            return null
        }
        return admission.acquire { code, id, deadline -> transact(service, code, id, deadline) }
    }

    private fun bindIfNeeded() {
        val bind = synchronized(monitor) {
            if (poisoned || remote != null || binding) false else { binding = true; true }
        }
        if (!bind) return
        val accepted = try {
            context.bindService(Intent(RuntimeMutationQuiescenceWire.ACTION).setComponent(component), connection,
                Context.BIND_AUTO_CREATE)
        } catch (_: Throwable) { false }
        if (!accepted) poison()
    }

    private fun transact(service: IBinder, code: Int, id: String, deadline: Long): Boolean {
        val data = Parcel.obtain(); val reply = Parcel.obtain()
        return try {
            data.writeInterfaceToken(RuntimeMutationQuiescenceWire.DESCRIPTOR)
            data.writeInt(RuntimeMutationQuiescenceWire.VERSION); data.writeStrongBinder(lifetime); data.writeString(id); data.writeLong(deadline)
            require(data.dataSize() <= RuntimeMutationQuiescenceWire.MAX_PARCEL_BYTES)
            if (!service.transact(code, data, reply, 0)) return false
            reply.readException()
            reply.readInt() == 1 && reply.dataAvail() == 0
        } catch (_: Throwable) {
            poison()
            throw IllegalStateException("MUTATION_QUIESCENCE_TRANSPORT_UNPROVEN")
        } finally { reply.recycle(); data.recycle() }
    }

    private fun poison() {
        val prior = synchronized(monitor) {
            val current = remote
            remote = null
            binding = false
            poisoned = true
            current
        }
        try { prior?.unlinkToDeath(remoteDeath, 0) } catch (_: Throwable) { }
    }
}

/**
 * Runs an individual same-UID Binder admission away from the main thread.  A timeout does not
 * cancel a possibly already-sent Binder transaction: its worker is retained solely to release a
 * late accepted lease, while the owning process is poisoned so that no mutation can follow it.
 */
internal class BoundedMutationQuiescenceAdmission(
    private val now: () -> Long,
    private val executor: ExecutorService,
    private val poison: () -> Unit,
    private val timeoutMillis: Long = RuntimeMutationQuiescenceWire.MAX_ADMISSION_MILLIS,
    private val newId: () -> String = { UUID.randomUUID().toString().replace("-", "") },
) {
    init { require(timeoutMillis in 1..RuntimeMutationQuiescenceWire.MAX_ADMISSION_MILLIS) }

    fun acquire(call: (code: Int, id: String, deadline: Long) -> Boolean): AutoCloseable? {
        val id = newId().also { require(RuntimeAuthorityLimits.validId(it)) }
        val deadline = Math.addExact(now(), timeoutMillis)
        val cancelled = AtomicBoolean(false)
        val future = executor.submit<AutoCloseable?> {
            val accepted = call(RuntimeMutationQuiescenceWire.ACQUIRE, id, deadline)
            if (!accepted) return@submit null
            if (cancelled.get() || now() >= deadline) {
                if (!call(RuntimeMutationQuiescenceWire.RELEASE, id, deadline)) poison()
                return@submit null
            }
            lease(call, id, deadline)
        }
        return try {
            future.get(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            cancelled.set(true)
            poison()
            null
        } catch (failure: ExecutionException) {
            poison()
            throw IllegalStateException("MUTATION_QUIESCENCE_TRANSPORT_UNPROVEN", failure.cause)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            cancelled.set(true)
            poison()
            null
        }
    }

    private fun lease(call: (Int, String, Long) -> Boolean, id: String, deadline: Long): AutoCloseable = object : AutoCloseable {
        private var closed = false
        override fun close() {
            synchronized(this) {
                if (closed) return
                closed = true
            }
            val released = executor.submit<Boolean> { call(RuntimeMutationQuiescenceWire.RELEASE, id, deadline) }
            val proven = try {
                released.get(timeoutMillis, TimeUnit.MILLISECONDS)
            } catch (failure: Throwable) {
                poison()
                throw IllegalStateException("MUTATION_QUIESCENCE_RELEASE_UNPROVEN", failure)
            }
            if (!proven) {
                poison()
                throw IllegalStateException("MUTATION_QUIESCENCE_RELEASE_UNPROVEN")
            }
        }
    }
}
