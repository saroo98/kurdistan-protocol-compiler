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
import android.os.Build
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
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.first
import org.kurdistanvpn.data.protectedstate.ProtectedAuthorityEnvironment
import org.kurdistanvpn.data.protectedstate.AuthorityReadFailure
import org.kurdistanvpn.data.protectedstate.AuthorityReadResult
import org.kurdistanvpn.data.protectedstate.ProductionCaptureReadResult
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

class KurdistanApplication : Application(), RuntimeAuthorityReissueOwner,
    org.kurdistanvpn.runtime.android.RuntimeDependencyProvider {
    private var runtimeDependencies: RuntimeProcessDependencies? = null
    override val runtimeProcessGraph: org.kurdistanvpn.runtime.android.RuntimeProcessGraph
        get() = checkNotNull(runtimeDependencies) { "VPN_PROCESS_REQUIRED" }.runtimeProcessGraph

    override fun onCreate() {
        super.onCreate()
        if (currentProcessRole() == ProcessRole.VPN) runtimeDependencies = RuntimeProcessDependencies()
    }

    private var sessionController: VpnRuntimeController? = null
    private val observedController = kotlinx.coroutines.flow.MutableStateFlow<VpnRuntimeController?>(null)
    @Volatile private var settingsController: VpnRuntimeController? = null
    internal val settingsRuntimePort: org.kurdistanvpn.data.settings.SettingsRuntimePort by lazy {
        requireDefaultProcess()
        RuntimeSettingsApplyPort(
            { operation, token -> checkNotNull(settingsController).settingsTransition(operation, token) },
            { checkNotNull(settingsController).querySettingsStatus() },
            retainOwner = {
                val owner = runtimeController
                owner.retainSettingsOwner()
                settingsController = owner
                kotlinx.coroutines.withTimeout(10_000) { owner.controlReady.first { it } }
            },
            releaseOwner = {
                val owner = settingsController
                settingsController = null
                owner?.releaseSettingsOwner()
            },
        )
    }
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    internal val runtimeSnapshots: kotlinx.coroutines.flow.Flow<org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot>
        get() = observedController.flatMapLatest { it?.snapshot ?: flowOf(org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot()) }
    internal val activityEffects by lazy { requireDefaultProcess(); ProductActivityEffects() }
    internal val exportDestination by lazy { requireDefaultProcess(); ProductExportDestination(activityEffects) }
    internal val runtimeController: VpnRuntimeController
        @Synchronized get() {
            requireDefaultProcess()
            return sessionController?.takeUnless { it.isClosed }
                ?: VpnRuntimeController(this).also { sessionController = it; observedController.value = it }
        }
    private val nativeCore by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { NativeBridge() }
    private val mutationQuiescence by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        VpnMutationQuiescenceClient(this)
    }
    internal val protectedStateProcessOwner by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        requireDefaultProcess()
        ProtectedStateProcessOwner({ mutationQuiescence.acquire() }, SystemClock::elapsedRealtime)
    }
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    val compositionRoot: ProductCompositionRoot by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        requireDefaultProcess()
        ProductCompositionRoot.create(this, protectedStateProcessOwner, observedController.flatMapLatest { controller ->
            controller?.snapshot?.map { org.kurdistanvpn.domain.SystemPolicyState(it.alwaysOn, it.lockdown, null) }
                ?: flowOf(org.kurdistanvpn.domain.SystemPolicyState(null, null, null))
        })
    }
    override val runtimeAuthorityPipePrimitives: DurableFilePrimitives get() = nativeCore.durableFiles()
    override val runtimeAuthorityReissue: RuntimeAuthorityReissueIpcAdapter by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        requireDefaultProcess()
        val backend = DefaultProcessAuthorityBackend(::isUnlocked, ::isPrepared, SystemClock::elapsedRealtime,
            ::openAuthorityReadOwner, ::acquireRevisionLease)
        val productionBackend = DefaultProcessAuthorityBackend(::isUnlocked, ::isPrepared, SystemClock::elapsedRealtime,
            ::openProductionReadOwner) { request, environment -> acquireLease(request, environment, true) }
        RuntimeAuthorityReissueIpcAdapter(Process.myUid().toLong(), java.util.UUID.randomUUID().toString().replace("-", ""),
            backend, SystemClock::elapsedRealtime, productionBackend)
    }

    private fun isUnlocked(): Boolean = getSystemService(UserManager::class.java).isUserUnlocked
    private fun isPrepared(): Boolean = VpnService.prepare(this) == null

    private fun requireDefaultProcess() {
        check(currentProcessRole() == ProcessRole.MAIN) { "DEFAULT_PROCESS_REQUIRED" }
    }

    private fun currentProcessRole(): ProcessRole {
        val currentName = if (Build.VERSION.SDK_INT >= 28) {
            Application.getProcessName()
        } else {
            getSystemService(ActivityManager::class.java).runningAppProcesses
                ?.singleOrNull { it.pid == Process.myPid() && it.uid == Process.myUid() }?.processName
        }
        return processRole(packageName, currentName)
    }

    private fun existingFacade(rejection: LongArray? = null): ProtectedStateApplicationFacade? {
        if (!isUnlocked() || !isPrepared()) { recordAuthorityReadRejection(rejection, 2); return null }
        return when (val opened = ProtectedStateApplicationFacade.openExistingReadOnly(this,
            runtimeAuthorityPipePrimitives, nativeCore, protectedStateProcessOwner)) {
            is ProtectedStateApplicationFacade.OpenResult.Ready -> opened.facade
            else -> {
                val category = when (opened) {
                    ProtectedStateApplicationFacade.OpenResult.Locked -> 1L
                    ProtectedStateApplicationFacade.OpenResult.Missing -> 2L
                    ProtectedStateApplicationFacade.OpenResult.MigrationRequired -> 3L
                    ProtectedStateApplicationFacade.OpenResult.KeyInvalidated -> 4L
                    else -> 5L
                }
                recordAuthorityReadRejection(rejection, 3, category)
                null
            }
        }
    }

    private fun openAuthorityReadOwner(environment: ProtectedAuthorityEnvironment, rejection: LongArray?): ExistingRestorationReadOwner? {
        val facade = existingFacade(rejection) ?: return null
        return object : ExistingRestorationReadOwner {
            override fun prepare(): RuntimeReissueMaterial? = when (val result = facade.reconstructAuthority(environment)) {
                is AuthorityReadResult.Rejected -> {
                    recordAuthorityReadRejection(rejection, 4, result.category.ordinal.toLong(), result.error?.ordinal?.toLong() ?: -1)
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

    private fun openProductionReadOwner(environment: ProtectedAuthorityEnvironment, rejection: LongArray?): ExistingRestorationReadOwner? {
        val facade = existingFacade(rejection) ?: return null
        return object : ExistingRestorationReadOwner {
            override fun prepare(): RuntimeReissueMaterial? = when (val result = facade.reconstructProductionCapture(environment)) {
                is ProductionCaptureReadResult.Rejected -> {
                    recordAuthorityReadRejection(rejection, 4, result.category.ordinal.toLong(), result.error?.ordinal?.toLong() ?: -1)
                    if (result.category == AuthorityReadFailure.CLEANUP_UNPROVEN) throw RuntimeAuthorityCleanupUnprovenException()
                    null
                }
                is ProductionCaptureReadResult.Ready -> object : RuntimeReissueMaterial {
                    private val capture = result.capture
                    override val presentation = capture.presentation
                    override val revision = capture.revision
                    override val signedRetryBudget = capture.signedRetryBudget
                    override val payloadLength = capture.length
                    override fun writeTo(output: OutputStream) = capture.writeTo(output)
                    override fun close() = capture.close()
                }
            }
            override fun close() = facade.close()
        }
    }

    private fun acquireRevisionLease(request: RuntimeAuthorityRequest, environment: ProtectedAuthorityEnvironment): RuntimeProviderRevisionLease? =
        acquireLease(request, environment, false)

    private fun acquireLease(request: RuntimeAuthorityRequest, environment: ProtectedAuthorityEnvironment,
        production: Boolean): RuntimeProviderRevisionLease? {
        val facade = existingFacade() ?: return null
        var registration: ProtectedRuntimeRevisionRegistration? = null
        var acquired: ProtectedRuntimeRevisionLease? = null
        var transferred = false
        try {
            if (facade.snapshot()?.revision != request.revision) return null
            registration = protectedStateProcessOwner.registerRuntimeRevision(request.consumerEpoch, request.generation, request.revision)
                ?: return null
            val deadline = minOf(request.deadlineElapsedMillis,
                Math.addExact(SystemClock.elapsedRealtime(), RuntimeAuthorityLimits.MAX_FINAL_LEASE_MILLIS))
            acquired = registration.acquireFinalLease(deadline) ?: return null
            val ownedRegistration = registration
            val ownedLease = acquired
            val result = ApplicationRevisionLease(ownedRegistration, ownedLease, facade,
                if (production) { deadline -> observeRegisteredProduction(request, deadline) } else null,
                publicationDeadlineElapsedMillis = deadline) {
                if (!environment.isUserUnlocked() || !environment.isConsentPrepared() || environment.isCancelled()) return@ApplicationRevisionLease false
                // The immutable snapshot and physical witnesses are reread under the
                // same mutation exclusion used by the broker. External trust/expiry
                // and native key bindings are revalidated, never cached from OFFER.
                if (production) {
                    val fresh = facade.reconstructProductionCapture(environment).readyForFinalValidation()
                        ?: return@ApplicationRevisionLease false
                    return@ApplicationRevisionLease try {
                        fresh.capture.revision == request.revision && fresh.capture.signedRetryBudget == request.signedRetryBudget && ownedLease.isCurrent()
                    } finally {
                        fresh.capture.close()
                    }
                }
                val fresh = facade.reconstructAuthority(environment).readyForFinalValidation()
                    ?: return@ApplicationRevisionLease false
                try {
                    fresh.authority.revision == request.revision && fresh.authority.signedRetryBudget == request.signedRetryBudget && ownedLease.isCurrent()
                } finally { fresh.authority.close() }
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

    private fun observeRegisteredProduction(request: RuntimeAuthorityRequest, deadline: Long): Boolean {
        val environment = object : ProtectedAuthorityEnvironment {
            override fun isUserUnlocked() = isUnlocked()
            override fun isConsentPrepared() = isPrepared()
            override fun elapsedRealtimeMillis() = SystemClock.elapsedRealtime()
            override fun isCancelled(): Boolean {
                val now = elapsedRealtimeMillis()
                return now < 0 || deadline <= now || deadline - now > 60_000
            }
        }
        if (!environment.isUserUnlocked() || !environment.isConsentPrepared() || environment.isCancelled()) return false
        val fresh = existingFacade() ?: return false
        return fresh.use {
            when (val result = fresh.reconstructProductionCapture(environment)) {
                is ProductionCaptureReadResult.Ready -> result.capture.use {
                    it.revision == request.revision && it.signedRetryBudget == request.signedRetryBudget &&
                        environment.isUserUnlocked() && environment.isConsentPrepared() && !environment.isCancelled()
                }
                is ProductionCaptureReadResult.Rejected -> {
                    if (result.category == AuthorityReadFailure.CLEANUP_UNPROVEN) throw RuntimeAuthorityCleanupUnprovenException()
                    false
                }
            }
        }
    }
}

// A rejected reconstruction can still own unproven cleanup; it is not a definite policy refusal.
internal fun ProductionCaptureReadResult.readyForFinalValidation(): ProductionCaptureReadResult.Ready? = when (this) {
    is ProductionCaptureReadResult.Ready -> this
    is ProductionCaptureReadResult.Rejected -> {
        if (category == AuthorityReadFailure.CLEANUP_UNPROVEN) throw RuntimeAuthorityCleanupUnprovenException()
        null
    }
}

internal fun AuthorityReadResult.readyForFinalValidation(): AuthorityReadResult.Ready? = when (this) {
    is AuthorityReadResult.Ready -> this
    is AuthorityReadResult.Rejected -> {
        if (category == AuthorityReadFailure.CLEANUP_UNPROVEN) throw RuntimeAuthorityCleanupUnprovenException()
        null
    }
}

private class RegistrationNotStarted(val owner: ApplicationRevisionLease) :
    IllegalStateException("FINAL_REVISION_LEASE_INVALID")

internal fun isDefiniteRegistrationNotStarted(lease: RuntimeProviderRevisionLease, failure: Throwable): Boolean =
    failure is RegistrationNotStarted && failure.owner === lease

/** Manual default-process ownership transfer. Installation may invalidate synchronously. */
internal class ApplicationRevisionLease(
    private val registration: ProtectedRuntimeRevisionRegistration,
    private val lease: ProtectedRuntimeRevisionLease,
    private val facade: AutoCloseable,
    private val validateRegisteredAuthority: ((Long) -> Boolean)? = null,
    override val publicationDeadlineElapsedMillis: Long? = null,
    private val validateAuthority: () -> Boolean,
) : RuntimeProviderRegisteredRevisionLease {
    private enum class Transfer { AVAILABLE, INSTALLING, REGISTERED, FAILED }
    private enum class Release { OPEN, RUNNING, CLEAN, UNPROVEN }
    private val monitor = Any()
    private var transfer = Transfer.AVAILABLE
    private var release = Release.OPEN
    override val revision = lease.revision

    override fun isCurrent(): Boolean = synchronized(monitor) {
        release == Release.OPEN && transfer != Transfer.FAILED && lease.isCurrent() && validateAuthority()
    }

    override fun isCurrentAfterFreshObservation(): Boolean = synchronized(monitor) {
        release == Release.OPEN && transfer != Transfer.FAILED && lease.isCurrent()
    }

    override fun isRegisteredCurrent(observationDeadlineElapsedMillis: Long): Boolean {
        fun admitted() = synchronized(monitor) { transfer == Transfer.REGISTERED && release == Release.CLEAN }
        if (!admitted()) return false
        val fresh = registration.isRegisteredCurrent {
            admitted() && validateRegisteredAuthority?.invoke(observationDeadlineElapsedMillis) == true
        }
        return fresh && admitted()
    }

    override fun registerActive(onInvalidated: () -> Unit, onRetired: (Boolean) -> Unit): Closeable =
        registerActiveOwned(false, onInvalidated, onRetired)

    override fun registerActiveAfterFreshObservation(onInvalidated: () -> Unit, onRetired: (Boolean) -> Unit): Closeable =
        registerActiveOwned(true, onInvalidated, onRetired)

    private fun registerActiveOwned(freshObservation: Boolean, onInvalidated: () -> Unit,
        onRetired: (Boolean) -> Unit): Closeable {
        synchronized(monitor) {
            check(transfer == Transfer.AVAILABLE) { "FINAL_REVISION_LEASE_INVALID" }
            // Only the same production PRE_ACTIVE response may reuse its fresh observation.
            // Temporary registration is not publication; COMPLETE and RELEASE remain fresh.
            val current = try {
                (if (freshObservation) isCurrentAfterFreshObservation() else isCurrent()) && lease.isCurrent()
            }
            catch (failure: RegistrationNotStarted) {
                // A replay from validation is not this invocation's explicit rejection.
                throw RuntimeAuthorityCleanupUnprovenException().also { it.initCause(failure) }
            }
            if (!current) throw RegistrationNotStarted(this)
            transfer = Transfer.INSTALLING
        }
        try {
            val active = lease.registerActive(onInvalidated, onRetired)
            synchronized(monitor) { transfer = Transfer.REGISTERED }
            // The caller owns even a terminal late handle; PRE_ACTIVE reconciles it after
            // acquisition returns. Never close it on its own invalidation callback stack.
            return active
        } catch (failure: Throwable) {
            try { registration.close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
            synchronized(monitor) { transfer = Transfer.FAILED }
            try { close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
            if (failure is RegistrationNotStarted) {
                throw RuntimeAuthorityCleanupUnprovenException().also { it.initCause(failure) }
            }
            throw failure
        }
    }

    override fun close() {
        val closeRegistration = synchronized(monitor) {
            when (release) {
                Release.CLEAN -> return
                Release.RUNNING, Release.UNPROVEN -> throw RuntimeAuthorityCleanupUnprovenException()
                Release.OPEN -> release = Release.RUNNING
            }
            transfer == Transfer.AVAILABLE
        }
        var failure: Throwable? = null
        fun clean(action: () -> Unit) {
            try { action() } catch (caught: Throwable) {
                if (failure == null) failure = caught else checkNotNull(failure).addSuppressed(caught)
            }
        }
        clean { lease.close() }; clean { facade.close() }
        if (closeRegistration) clean { registration.close() }
        synchronized(monitor) { release = if (failure == null) Release.CLEAN else Release.UNPROVEN }
        failure?.let {
            throw RuntimeAuthorityCleanupUnprovenException().also { result -> result.addSuppressed(it) }
        }
    }
}

/** The default-process reader owns only existing CE descriptors and an existing key lookup.
 * Its implementation must close internally acquired resources if construction throws. */
internal interface ExistingRestorationReadOwner : Closeable {
    fun prepare(): RuntimeReissueMaterial?
}

// First original rejection wins. No additional admission/storage reads or exception text.
internal fun recordAuthorityReadRejection(receipt: LongArray?, boundary: Long, category: Long = -1, error: Long = -1) {
    if (receipt == null) return
    synchronized(receipt) {
        if (receipt.size == 3 && receipt[0] == -1L) {
            receipt[0] = boundary; receipt[1] = category; receipt[2] = error
        }
    }
}

/** Shared manual/system provider path. It cannot initialize storage, normalize preferences,
 * manufacture authority, or retain a wire between requests. Android binding supplies only
 * lifecycle metadata; all material is reconstructed through the committed read facade. */
internal class DefaultProcessAuthorityBackend(
    private val unlocked: () -> Boolean,
    private val prepared: () -> Boolean,
    private val now: () -> Long,
    private val openExisting: (ProtectedAuthorityEnvironment, LongArray?) -> ExistingRestorationReadOwner?,
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

    override fun observe(start: RuntimeReissueStart): RuntimeAuthorityProviderState? = observeOriginal(start, null)
    override fun observe(start: RuntimeReissueStart, rejection: LongArray): RuntimeAuthorityProviderState? = observeOriginal(start, rejection)
    private fun observeOriginal(start: RuntimeReissueStart, rejection: LongArray?): RuntimeAuthorityProviderState? {
        val current = prepareOriginal(start, rejection) ?: return null
        return current.use {
            if (!admitted(start)) { recordAuthorityReadRejection(rejection, 7); null } else RuntimeAuthorityProviderState(true, true, true, it.revision, it.signedRetryBudget)
        }
    }

    override fun prepare(start: RuntimeReissueStart): RuntimeReissueMaterial? = prepareOriginal(start, null)
    private fun prepareOriginal(start: RuntimeReissueStart, rejection: LongArray?): RuntimeReissueMaterial? {
        if (!admitted(start)) { recordAuthorityReadRejection(rejection, 1); return null } // before even opening credential-protected state
        var reader: ExistingRestorationReadOwner? = null
        var material: RuntimeReissueMaterial? = null
        var transferred = false
        try {
            reader = openExisting(environment(start), rejection)
            if (reader == null) { recordAuthorityReadRejection(rejection, 3); return null }
            material = reader.prepare()
            if (material == null) { recordAuthorityReadRejection(rejection, 4); return null }
            require(RuntimeAuthorityLimits.validRevision(material.revision) &&
                material.signedRetryBudget in 0..RuntimeAuthorityLimits.MAX_RETRIES &&
                start.retryAttempt <= material.signedRetryBudget &&
                material.payloadLength in 1..RuntimeAuthorityLimits.MAX_PAYLOAD_BYTES)
            if (!admitted(start)) { recordAuthorityReadRejection(rejection, 6); return null }
            return OwnedMaterial(reader, material) { admitted(start) }.also { transferred = true }
        } catch (failure: RuntimeAuthorityCleanupUnprovenException) { throw failure }
        catch (failure: Exception) {
            val category = when (failure) { is IllegalArgumentException -> 1L; is IllegalStateException -> 2L; is SecurityException -> 3L; else -> 4L }
            recordAuthorityReadRejection(rejection, 5, category)
            return null
        }
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
        override val presentation = authority.presentation
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
    private var connectionReady = CountDownLatch(1)
    private val lifetime = Binder()
    private val ipc = Executors.newSingleThreadExecutor { task ->
        Thread(task, "kurd-vpn-quiescence").apply { isDaemon = true }
    }
    private var remote: IBinder? = null
    private var binding = false
    private var rebindRequired = false
    private var poisoned = false
    private var activeAdmissions = 0
    private val admission = BoundedMutationQuiescenceAdmission(
        now = SystemClock::elapsedRealtime,
        executor = ipc,
        poison = ::poison,
    )
    private var remoteDeath: IBinder.DeathRecipient? = null
    private var connection: ServiceConnection = newConnection()
    private fun newConnection(): ServiceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            if (synchronized(monitor) { connection !== this || poisoned }) return
            if (name != component || service == null) return poison(this)
            try {
                val death = IBinder.DeathRecipient { disconnected(service, this) }
                service.linkToDeath(death, 0)
                val retained = synchronized(monitor) {
                    if (!poisoned && connection === this && service.isBinderAlive) {
                        remote = service
                        remoteDeath = death
                        binding = true
                        rebindRequired = false
                        connectionReady.countDown()
                        true
                    } else {
                        false
                    }
                }
                if (!retained) try { service.unlinkToDeath(death, 0) } catch (_: Throwable) { }
            } catch (_: Throwable) { poison(this) }
        }
        override fun onServiceDisconnected(name: ComponentName?) = disconnected(null, this)
        override fun onBindingDied(name: ComponentName?) = disconnected(null, this, bindingDied = true)
        override fun onNullBinding(name: ComponentName?) = poison(this)
    }
    private val component = ComponentName(context, KurdVpnService::class.java)

    init { bindIfNeeded() }

    fun acquire(): AutoCloseable? {
        check(Looper.myLooper() != Looper.getMainLooper()) { "MUTATION_QUIESCENCE_MAIN_THREAD" }
        val deadline = Math.addExact(SystemClock.elapsedRealtime(), RuntimeMutationQuiescenceWire.MAX_ADMISSION_MILLIS)
        bindIfNeeded()
        val initial = synchronized(monitor) { if (poisoned) null else remote }
        val service = initial ?: try {
            val remaining = deadline - SystemClock.elapsedRealtime()
            val ready = synchronized(monitor) { connectionReady }
            if (remaining <= 0 || !ready.await(remaining, TimeUnit.MILLISECONDS)) return null
            synchronized(monitor) { if (poisoned) null else remote }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return null
        }
        if (service == null || !service.isBinderAlive) {
            if (service != null) disconnected(service)
            return null
        }
        synchronized(monitor) {
            if (poisoned || remote !== service || !service.isBinderAlive) return null
            activeAdmissions++
        }
        var retained = false
        try {
            val lease = admission.acquireBefore(deadline) { code, id, leaseDeadline ->
                transact(service, code, id, leaseDeadline)
            } ?: return null
            val closed = AtomicBoolean(false)
            retained = true
            return AutoCloseable {
                if (closed.compareAndSet(false, true)) try { lease.close() }
                finally { synchronized(monitor) { activeAdmissions-- } }
            }
        } finally {
            if (!retained) synchronized(monitor) { activeAdmissions-- }
        }
    }

    private fun disconnected(expected: IBinder?, owner: ServiceConnection? = null, bindingDied: Boolean = false) {
        val mustPoison = synchronized(monitor) {
            if (poisoned || (owner != null && connection !== owner) ||
                (expected != null && remote !== expected) ||
                (!bindingDied && expected == null && remote?.isBinderAlive == true)) return
            if (activeAdmissions != 0) true else {
                // No mutation crossed this death. Replace an unrecovered binding only when
                // the next mutation asks for a fresh proof, never as a process watchdog.
                remote = null; remoteDeath = null
                rebindRequired = true
                connectionReady.countDown()
                connectionReady = CountDownLatch(1)
                false
            }
        }
        if (mustPoison) poison()
    }

    private fun bindIfNeeded() {
        val (prior, next) = synchronized(monitor) {
            if (poisoned || remote != null || (binding && !rebindRequired)) return
            val prior = connection.takeIf { binding }
            binding = true; rebindRequired = false
            connectionReady.countDown()
            connectionReady = CountDownLatch(1)
            connection = newConnection()
            prior to connection
        }
        if (prior != null) try { context.unbindService(prior) } catch (_: Exception) { poison(next); return }
        val accepted = try {
            context.bindService(Intent(RuntimeMutationQuiescenceWire.ACTION).setComponent(component), next,
                Context.BIND_AUTO_CREATE)
        } catch (_: Throwable) { false }
        if (!accepted) poison(next)
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

    private fun poison() = poison(null)

    private fun poison(expected: ServiceConnection?) {
        val prior = synchronized(monitor) {
            if (expected != null && connection !== expected) return
            val current = remote to remoteDeath
            remote = null
            remoteDeath = null
            binding = false
            poisoned = true
            connectionReady.countDown()
            current
        }
        try { prior.second?.let { prior.first?.unlinkToDeath(it, 0) } } catch (_: Throwable) { }
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
        val deadline = Math.addExact(now(), timeoutMillis)
        return acquireBefore(deadline, call)
    }

    internal fun acquireBefore(deadline: Long,
        call: (code: Int, id: String, deadline: Long) -> Boolean): AutoCloseable? {
        val remaining = deadline - now()
        if (remaining !in 1..timeoutMillis) return null
        val id = newId().also { require(RuntimeAuthorityLimits.validId(it)) }
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
            future.get(remaining, TimeUnit.MILLISECONDS)
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
