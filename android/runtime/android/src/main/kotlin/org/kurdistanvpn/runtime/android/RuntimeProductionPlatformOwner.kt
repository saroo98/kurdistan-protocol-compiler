// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android
import org.kurdistanvpn.runtime.api.RuntimePresentationEvidence

import java.nio.ByteBuffer
import java.io.Closeable
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.runtime.api.RuntimeCaptureSnapshotV1
import org.kurdistanvpn.core.nativejni.AndroidProductionPlatformDelegateV1
import org.kurdistanvpn.core.nativejni.AndroidProductionCallbacks
import org.kurdistanvpn.core.nativejni.AndroidProductionProbeBindingV1
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.runtime.api.RuntimeAuthorityTrigger
import android.app.ActivityManager
import android.app.Application
import android.content.ComponentName
import android.net.VpnService
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.os.SystemClock
import android.os.UserManager
import android.os.ParcelFileDescriptor
import org.kurdistanvpn.runtime.api.LiveTunConfiguration
import org.kurdistanvpn.runtime.api.PerAppRoutingMode
import org.kurdistanvpn.core.model.ProbePreferences
import org.kurdistanvpn.core.model.ProductFailureCode

/** A single bounded receiving-process borrow; the accepted native helper owns verification. */
internal object RuntimeProductionBootstrapBorrowV1 {
    fun read(capture: RuntimeCaptureSnapshotV1, validator: NativeBootstrapValidator): NativeProductionBootstrapReadV1 {
        val sizes = IntArray(5)
        val spans = arrayOfNulls<ByteBuffer>(5)
        try {
            capture.copySizesInto(sizes)
            for (i in 0..4) spans[i] = ByteBuffer.allocateDirect(sizes[i])
            check(capture.copyVerifyRequestTo(checkNotNull(spans[0])) == sizes[0])
            check(capture.copyActivationRecordTo(checkNotNull(spans[1])) == sizes[1])
            check(capture.copyRecipientRequestTo(checkNotNull(spans[2])) == sizes[2])
            check(capture.copyRecipientPrivateTo(checkNotNull(spans[3])) == sizes[3])
            check(capture.copySettingsTo(checkNotNull(spans[4])) == sizes[4])
            val material = NativeBootstrapMaterialV1(checkNotNull(spans[0]), checkNotNull(spans[1]),
                checkNotNull(spans[2]), checkNotNull(spans[3]))
            return when (val result = validator.readProductionBinding(material, checkNotNull(spans[4]))) {
                is NativeProductResult.Success -> result.value
                is NativeProductResult.Failure -> error("PRODUCTION_BOOTSTRAP_REJECTED")
            }
        } finally {
            spans.forEach { span -> span?.let { for (i in 0 until it.capacity()) it.put(i, 0) } }
            sizes.fill(0)
        }
    }
}

/** Two fixed lifecycle records on the existing guard, not an admission/handle registry. */
internal class RuntimeProductionGuardOwnershipV1(private val guard: RuntimeActivationGuard,
    private val releaseShared: () -> Unit) : Closeable {
    private inner class Slot : Closeable {
        var owner = 0L
        var lease = 0L
        var abandon: (() -> Int)? = null
        var adopted = false
        var callbackClosed = false
        var retired = false
        var reserving = false
        var finalizingOpening = false
        var parent: Closeable? = null
        override fun close() {
            val retained = synchronized(monitor) {
                if (retired) return
                checkNotNull(parent)
            }
            try {
                retained.close()
                synchronized(monitor) { check(callbackClosed); retired = true }
            } catch (failure: Throwable) {
                synchronized(monitor) { unproven = true }
                throw failure
            }
        }
    }
    private val monitor = Any()
    private val production = Slot()
    private val maintenance = Slot()
    private var closing = false
    private var clean = false
    private var unproven = false
    private fun slot(kind: Int): Slot = when (kind) { 1 -> production; 2 -> maintenance; else -> error("OWNER_KIND_REJECTED") }

    fun beginReservation(kind: Int) = synchronized(monitor) {
        val selected = slot(kind)
        check(guard.isAcquisitionCurrent())
        if (kind == 2 && selected.retired && !closing && !unproven) {
            selected.owner = 0; selected.lease = 0; selected.abandon = null
            selected.adopted = false; selected.callbackClosed = false; selected.retired = false
            selected.parent = null
        }
        check(!closing && !unproven && selected.owner == 0L && !selected.reserving)
        selected.reserving = true
    }

    /** Reuses the fixed guard slot only after this exact native parent's completed retirement. */
    fun retireMaintenance() {
        synchronized(monitor) { check(!closing && !unproven && (maintenance.adopted || maintenance.retired)) }
        maintenance.close()
    }

    fun reserve(kind: Int, owner: Long, lease: Long, abandon: () -> Int) {
        val late = synchronized(monitor) {
            val selected = slot(kind)
            check(selected.reserving && selected.owner == 0L && owner != 0L && lease != 0L)
            selected.owner = owner; selected.lease = lease; selected.abandon = abandon
            selected.reserving = false
            closing || unproven
        }
        if (late) {
            // Actual late ownership is retained before attempting its exact abandonment.
            try {
                val result = abandon()
                synchronized(monitor) { if (result == 0 && slot(kind).callbackClosed) slot(kind).retired = true }
            } finally { synchronized(monitor) { unproven = true } }
            throw RuntimeAuthorityCleanupUnprovenException()
        }
    }

    /** The callback precedes C/JNI final retirement. It alone never releases shared ownership. */
    fun nativeOwnerClosed(kind: Int, owner: Long): Boolean = synchronized(monitor) {
        val selected = slot(kind)
        if (owner == 0L || selected.owner != owner || selected.callbackClosed) return false
        selected.callbackClosed = true
        true
    }

    /** Invoke immediately upon native parent return inside the same setup guard.acquire. */
    fun adoptNativeParent(kind: Int, parent: Closeable) {
        val selected = synchronized(monitor) {
            val value = slot(kind)
            check(value.owner != 0L && !value.adopted)
            check(kind != 2 || production.owner == 0L || production.adopted)
            value.parent = parent
            value.adopted = true
            value
        }
        // Late own still invokes actual cleanup. No allocation/decode may precede this handoff.
        if (guard.own(RuntimeResourceKind.NATIVE_SESSION, selected) == null)
            throw RuntimeAuthorityCleanupUnprovenException()
    }

    /** Exact synchronous post-End result, after the receiver callback and C owner release. */
    fun finalizeFailedOpening(kind: Int, owner: Long, lease: Long, finalize: () -> Int) {
        val selected = synchronized(monitor) {
            val value = slot(kind)
            if (owner == 0L || lease == 0L || value.owner != owner || value.lease != lease ||
                value.adopted || value.retired || value.reserving || value.finalizingOpening || closing || unproven)
                throw RuntimeAuthorityCleanupUnprovenException()
            value.finalizingOpening = true
            value
        }
        val result = try { finalize() } catch (_: Throwable) { 25 }
        synchronized(monitor) {
            selected.finalizingOpening = false
            if (result != 0 || !selected.callbackClosed || closing || unproven) {
                unproven = true
                throw RuntimeAuthorityCleanupUnprovenException()
            }
            selected.retired = true
        }
    }

    override fun close() {
        synchronized(monitor) {
            if (closing) { if (!clean || unproven) throw RuntimeAuthorityCleanupUnprovenException(); return }
            closing = true
            if (production.reserving || maintenance.reserving) unproven = true
        }
        fun retireUnclaimed(selected: Slot) {
            val abandon = synchronized(monitor) {
                if (selected.owner == 0L || selected.retired) return
                if (selected.adopted || selected.finalizingOpening) { unproven = true; return }
                selected.abandon
            }
            try {
                val result = checkNotNull(abandon).invoke()
                synchronized(monitor) {
                    if (result == 0 && selected.callbackClosed) selected.retired = true else unproven = true
                }
            } catch (_: Throwable) { synchronized(monitor) { unproven = true } }
        }
        retireUnclaimed(maintenance)
        retireUnclaimed(production)
        synchronized(monitor) {
            if (unproven || (production.owner != 0L && !production.retired) ||
                (maintenance.owner != 0L && !maintenance.retired)) throw RuntimeAuthorityCleanupUnprovenException()
        }
        try { releaseShared() }
        catch (failure: Throwable) { synchronized(monitor) { unproven = true }; throw failure }
        synchronized(monitor) { clean = true }
    }
}

/** One opening's availability. It cannot refresh itself onto another attempt. */
internal class RuntimeCapturedProbeBindingV1(
    private val facts: NativeProductionBootstrapFactsV1,
    private val live: () -> Boolean,
    private val contains: (Int) -> Boolean,
    generation: ULong, digest: ByteArray,
) : AndroidProductionProbeBindingV1 {
    private val monitor=Any()
    private var valid=matches(generation,digest)
    private var connection=0uL
    private fun matches(generation: ULong,digest:ByteArray):Boolean {
        val expected=facts.planDigest
        return try { generation==facts.generation && expected.contentEquals(digest) } finally {expected.fill(0)}
    }
    override fun invalidate() { synchronized(monitor){valid=false} }
    override fun isCurrent():Boolean {
        if(!synchronized(monitor){valid})return false
        val current=try{live()}catch(_:Throwable){false}
        if(!current)invalidate()
        return current && synchronized(monitor){valid}
    }
    override fun permits(target:Int):Boolean {
        if(!isCurrent())return false
        val present=try{contains(target)}catch(_:Throwable){invalidate();false}
        return present && isCurrent()
    }
    override fun observe(event:NativeControlEvent) {
        synchronized(monitor) {
            if(connection!=0uL && connection!=event.connectionGeneration)valid=false
            connection=event.connectionGeneration
            if(event is NativeControlEvent.ReconnectStarted || event is NativeControlEvent.FallbackStarted ||
                event is NativeControlEvent.PathChanged || event is NativeControlEvent.Revoked ||
                event is NativeControlEvent.Failed || event is NativeControlEvent.Stopped)valid=false
        }
        if(event is NativeControlEvent.RoutePlanReady) {
            val digest=event.snapshot.planDigest
            try { if(!matches(event.snapshot.profileGeneration,digest))invalidate() } finally {digest.fill(0)}
        }
    }
}

internal fun readCapturedGenerationV1(live: () -> Boolean, read: () -> ULong): ULong {
    check(live())
    val generation = read()
    check(generation != 0uL && live())
    return generation
}

internal interface RuntimeProductionCallbackAuthorityV1 {
    fun capturedGeneration(): ULong
    fun bindActive(generation: ULong, digest: ByteArray): AndroidProductionProbeBindingV1
    fun bindDisconnected(): AndroidProductionProbeBindingV1
    val capture: RuntimeCaptureSnapshotV1
    val initialAcquired: Boolean
    fun live(): Boolean
    fun acquireInitial(call: Long): Boolean
    fun initialCurrent(): Boolean
    fun releaseInitial(): Boolean
    fun revalidateCurrent(call: Long, deadline: Long): Boolean
    fun cancel(call: Long): Boolean
}

internal object RuntimeProductionServiceIdentityV1 {
    fun accepts(packageName: String, actualProcess: String?, declaredProcess: String?, ownUid: Int,
        declaredUid: Int, permission: String?, exported: Boolean, directBootAware: Boolean): Boolean =
        actualProcess == "$packageName:vpn" && declaredProcess == actualProcess && ownUid == declaredUid &&
            permission == "android.permission.BIND_VPN_SERVICE" && !exported && !directBootAware
}

/** The successor must transfer the returned original FD immediately to its actual native owner. */
class RuntimeProductionEstablishedTunV1 internal constructor(private val owner: DetachableTun,
    private val current: () -> Boolean, private val duplicate: () -> ParcelFileDescriptor) : Closeable {
    fun detachFileDescriptor(): Int { check(current()); return owner.detachFileDescriptor() }
    internal fun acquirePacketEndpoint(endpoint: AndroidTunPacketEndpoint) {
        check(current())
        endpoint.acquire(duplicate)
        check(current())
    }
    override fun close() = owner.close()
}

/** Trusted service-capability composition. This creates no native session or ACTIVE claim. */
internal class RuntimeProductionNetworkUnavailableV1 : IllegalStateException("NETWORK_UNAVAILABLE")
internal class RuntimeProductionNetworkOutcomeV1(val decision: RuntimeStartDecision) : IllegalStateException("NETWORK_OUTCOME")

internal fun runProductionAcquisitionV1(coordinator: RuntimeStartCoordinator,
    admission: RuntimeStartDecision.RequestAuthority, onAdmitted: () -> Unit, acquire: () -> Unit) {
    var acquisitionFailure: Throwable? = null
    if (!admission.guard.acquire {
        try { onAdmitted(); acquire() }
        catch (failure: Throwable) { acquisitionFailure = failure; throw failure }
    }) {
        val reason = if (acquisitionFailure is RuntimeProductionNetworkUnavailableV1)
            RuntimeStartFailure.NETWORK_UNAVAILABLE else RuntimeStartFailure.CLEANUP_UNPROVEN
        val failed = coordinator.failed(admission.token, reason)
        // Scoped stop may already have published STOPPING while this acquisition ran.
        // Both exceptional and successful-but-cancelled acquisition returns reach here.
        val outcome = if (failed == RuntimeStartDecision.Stale) coordinator.cleanupCompleted(admission.token) else failed
        // Preserve retry, exhaustion and uncertain-cleanup outcomes for the existing service owner.
        if (acquisitionFailure is RuntimeProductionNetworkUnavailableV1 && failed != RuntimeStartDecision.Stale)
            throw RuntimeProductionNetworkOutcomeV1(outcome)
        throw RuntimeAuthorityCleanupUnprovenException().also { failure ->
            acquisitionFailure?.let { failure.initCause(it) }
        }
    }
}

class RuntimeProductionPlatformOwner private constructor(private val service: VpnService,
    private val coordinator: RuntimeStartCoordinator, private val decision: RuntimeStartDecision.RequestAuthority,
    private val initialKind: Int) {
    private val monitor = Any()
    private val guard = decision.guard
    private var client: RuntimeProductionAuthorityClientV1? = null
    private val publicationDiagnostic = LongArray(16) { -1 }
    private var captured: RuntimeProductionClientCaptureV1? = null
    private var bootstrap: NativeProductionBootstrapReadV1? = null
    private var production: Binding? = null
    private var maintenance: Binding? = null
    private var proof: RuntimeTunProofOwner? = null
    private var closing = false
    private var initialAcquired = false
    private var stopRequested = false
    internal var onProviderDeathSettled: () -> Unit = {}
    private var activeProbeBinding: AndroidProductionProbeBindingV1? = null
    private var sessionProbe: RuntimeSelectedProbeV1? = null
    private var productSession: ProductionNativeSession? = null
    private var productRoute: NativeOpeningSnapshot? = null
    private val capturedPackageRevision = currentRuntimePackageRevision(service)
    private var appliedTunConfiguration: LiveTunConfiguration? = null
    private val ownership = RuntimeProductionGuardOwnershipV1(guard, ::releaseShared)
    private val registration = RuntimeProductionRegistrationV1(object : RuntimeProductionRevisionSignalsV1 {
        override fun fence(owner: Long, signal: Long): Int = binding(owner).callbacks.fenceRevision(owner, signal)
        override fun invalidate(owner: Long, signal: Long): Int = binding(owner).callbacks.invalidateRevision(owner, signal)
    })
    private val source = object : RuntimeProductionCallbackAuthorityV1 {
        override fun capturedGeneration(): ULong = readCapturedGenerationV1(::live) {
            checkNotNull(bootstrap).facts.generation
        }
        override fun bindActive(generation:ULong,digest:ByteArray):AndroidProductionProbeBindingV1 {
            check(live())
            val same=checkNotNull(bootstrap)
            return RuntimeCapturedProbeBindingV1(same.facts,{live() && bootstrap===same},
                same.activeSelectors::containsProbe,generation,digest).also {
                synchronized(monitor) { check(activeProbeBinding == null); activeProbeBinding = it }
            }
        }
        override fun bindDisconnected():AndroidProductionProbeBindingV1 {
            check(live())
            val same=checkNotNull(bootstrap)
            val digest=same.facts.planDigest
            return try { RuntimeCapturedProbeBindingV1(same.facts,
                {live() && bootstrap===same && initialKind==2 && production==null && proof==null},
                same.disconnectedSelectors::containsProbe,same.facts.generation,digest)
            } finally {digest.fill(0)}
        }
        override val capture: RuntimeCaptureSnapshotV1 get() = checkNotNull(captured).capture
        override val initialAcquired: Boolean get() = synchronized(monitor) { this@RuntimeProductionPlatformOwner.initialAcquired }
        override fun live(): Boolean = current() && client?.captureCurrent() == true
        override fun acquireInitial(call: Long): Boolean {
            check(current())
            val acquired = checkNotNull(client).acquireInitialPublication(call)
            synchronized(monitor) { if (acquired) this@RuntimeProductionPlatformOwner.initialAcquired = true }
            return acquired && current()
        }
        override fun initialCurrent(): Boolean = current() && client?.initialPublicationCurrent() == true
        override fun releaseInitial(): Boolean = checkNotNull(client).releaseInitialPublication()
        override fun revalidateCurrent(call: Long, deadline: Long): Boolean = current() &&
            checkNotNull(client).revalidateCurrent(call, deadline) && current()
        override fun cancel(call: Long): Boolean = client?.cancelCall(call) == true
    }
    private inner class Binding(val kind: Int) {
        val values = LongArray(2)
        val delegate: RuntimeProductionCallbackDelegateV1 = RuntimeProductionCallbackDelegateV1(kind, source, registration,
            object : RuntimeProductionCallbackSignalsV1 {
                override fun cancelled(owner: Long, call: Long) = callbacks.isCallCancelled(owner, call)
                override fun remainingMillis(owner: Long, call: Long) = callbacks.remainingMillis(owner, call)
                override fun socketLost(owner: Long, signal: Long) = callbacks.signalSocketLoss(owner, signal)
                override fun networkLost(owner: Long, signal: Long) = callbacks.signalNetworkLoss(owner, signal)
            }, ownership::nativeOwnerClosed,
            { _, lost -> RuntimeProductionSocketOwner.forService(service, capturedPlatformSettings().meteredPolicy, ::current, lost) },
            { lost -> VpnMaintenanceNetworkLease.forService(service, if (initialKind == 1) 2 else 1,
                ::current, proof, { initialKind == 2 && production == null && proof == null }, lost) },
            SystemClock::elapsedRealtime)
        val callbacks: AndroidProductionCallbacks = AndroidProductionCallbacks(delegate)
        fun acquire() {
            ownership.beginReservation(kind)
            check(callbacks.reserve(kind, values) == 0)
            delegate.adoptOwner(values[0])
            ownership.reserve(kind, values[0], values[1]) { callbacks.abandon(values[1]) }
            check(current())
        }
    }
    private fun binding(owner: Long): Binding = synchronized(monitor) {
        production?.takeIf { it.values[0] == owner } ?: maintenance?.takeIf { it.values[0] == owner }
            ?: error("PLATFORM_OWNER_REJECTED")
    }
    private fun current(): Boolean {
        if (synchronized(monitor) { closing } || !guard.isAcquisitionCurrent() || coordinator.currentToken() != decision.token) return false
        return service.getSystemService(UserManager::class.java)?.isUserUnlocked == true &&
            VpnService.prepare(service) == null && guard.isAcquisitionCurrent() && coordinator.currentToken() == decision.token
    }
    private fun acquire() {
        check(current())
        val native = NativeBridge()
        val acquiringClient = RuntimeProductionAuthorityClientV1(service,
            ComponentName(service.packageName, "org.kurdistanvpn.app.RuntimeAuthorityReissueService"),
            coordinator.epoch, native.durableFiles(), { !guard.isAcquisitionCurrent() }, publicationDiagnostic,
            { onProviderDeathSettled() }) { pending ->
            guard.markCancellation()
            check(if (pending) registration.fencePendingPublication() else registration.invalidate())
        }
        val cancelled = synchronized(monitor) { client = acquiringClient; stopRequested }
        if (cancelled) acquiringClient.cancelCall(1)
        check(current())
        val token = decision.token
        val start = RuntimeReissueStart(token.epoch, token.requestId, token.generation, token.trigger,
            token.retryAttempt, Math.addExact(SystemClock.elapsedRealtime(), 60_000))
        // Local bootstrap worker ownership, before any native call identity exists.
        captured = checkNotNull(client).capture(1, start)
        check(current())
        bootstrap = RuntimeProductionBootstrapBorrowV1.read(checkNotNull(captured).capture, native)
        check(current())
        val selected = Binding(initialKind)
        synchronized(monitor) { if (initialKind == 1) production = selected else maintenance = selected }
        selected.acquire()
    }
    private fun releaseShared() {
        synchronized(monitor) { closing = true }
        check(registration.isRetired())
        // Capture cannot disappear merely because guard traversal continued after failed native close.
        client?.close()
        if (initialKind == 1 && proof != null) {
            service.setUnderlyingNetworks(null)
            ActiveVpnUnderlyingNetwork.publish(null)
        }
        proof?.close()
        bootstrap?.close()
        captured?.close()
        synchronized(monitor) {
            client = null; proof = null; bootstrap = null; captured = null
            productSession = null; productRoute = null
        }
    }
    /** Scalar platform lease only. The successor's native opening owns claim/preflight outcomes. */
    fun platformLease(kind: Int): Long {
        check(current())
        return synchronized(monitor) {
            when (kind) { 1 -> checkNotNull(production).values[1]; 2 -> checkNotNull(maintenance).values[1]; else -> error("OWNER_KIND_REJECTED") }
        }
    }
    /** Facts/catalogues are process-local availability only, not authorization to open or execute. */
    fun bootstrapAvailability(): NativeProductionBootstrapReadV1 { check(current()); return checkNotNull(bootstrap) }
    fun startToken(): RuntimeStartToken = decision.token
    internal fun providerDeathCanRetry(): Boolean = client?.providerDeathCanRetry() == true
    internal fun providerDeathInProgress(): Boolean = client?.providerDeathInProgress() == true
    fun adoptNativeParent(kind: Int, parent: Closeable) = ownership.adoptNativeParent(kind, parent)
    /** Opens only this service's captured production reservation under its existing guard. */
    fun openProductionSession(): NativeProductResult<ProductionNativeSession> {
        check(initialKind == 1 && current())
        val selected = synchronized(monitor) { checkNotNull(production) }
        var result: NativeProductResult<ProductionNativeSession>? = null
        if (!guard.acquire {
            check(current())
            result = selected.callbacks.openProduction(
                { parent -> ownership.adoptNativeParent(1, parent) },
                { finalizeFailedOpening(1) })
            check(current())
            val opened = result
            if (opened is NativeProductResult.Success) {
                synchronized(monitor) { check(productSession == null); productSession = opened.value }
                val same = checkNotNull(bootstrap)
                val binding = checkNotNull(activeProbeBinding)
                val probe = OwnedSessionSelectedProbeV1(opened.value, same, binding)
                synchronized(monitor) { check(sessionProbe == null); sessionProbe = probe }
            }
        }) throw RuntimeAuthorityCleanupUnprovenException()
        return checkNotNull(result)
    }

    /** The product consumes control through its owner so a caller cannot invent RoutePlanReady. */
    internal fun nextProductControl(output: ByteBuffer): NativeProductResult<NativeControlEvent> {
        check(current())
        val session = synchronized(monitor) { checkNotNull(productSession) }
        val result = session.nextControl(output)
        if (result is NativeProductResult.Success && result.value is NativeControlEvent.RoutePlanReady) {
            val snapshot = (result.value as NativeControlEvent.RoutePlanReady).snapshot
            val opening = session.openingSnapshot
            check(snapshot.profileGeneration == opening.profileGeneration &&
                snapshot.planDigest.contentEquals(opening.planDigest) &&
                snapshot.profileFingerprint.contentEquals(opening.profileFingerprint) &&
                snapshot.strategyFingerprint.contentEquals(opening.strategyFingerprint) &&
                snapshot.relayFingerprint.contentEquals(opening.relayFingerprint) &&
                snapshot.effectiveMode == opening.effectiveMode && snapshot.effectiveDnsMode == opening.effectiveDnsMode &&
                snapshot.packetLimits == opening.packetLimits)
            if (snapshot.effectiveMode != org.kurdistanvpn.core.model.TunnelMode.PROXY_ONLY) {
                val routing = capturedRouting()
                check(productionTunConfigurationV1(snapshot, routing, service.packageName) ==
                    productionTunConfigurationV1(opening, routing, service.packageName))
            }
            check(current())
            synchronized(monitor) { check(!closing && productRoute == null); productRoute = snapshot }
        }
        return result
    }

    private fun capturedRouting() = capturedPlatformSettings().routing

    internal fun capturedRevision(): Long {
        check(current())
        return checkNotNull(captured).offer.offer.revision
    }

    internal fun capturedProfileId(): String? {
        check(current())
        return captured?.offer?.offer?.presentation?.profileId
    }

    /** Independent native-route and actual TUN-owner observations, scoped to this attempt only. */
    internal fun presentationEvidence(): RuntimePresentationEvidence? {
        if (!current()) return null
        val profile = captured?.offer?.offer?.presentation ?: return null
        val packages = capturedPackageRevision ?: return null
        val route = synchronized(monitor) { productRoute } ?: return null
        if (route.profileGeneration != profile.profileGeneration) return null
        val nativeReady = synchronized(monitor) { productSession != null && !closing && !stopRequested }
        val applied = synchronized(monitor) { appliedTunConfiguration }
        val tunOwned = proof?.interfaceName() != null
        val id = decision.token.requestId
        if (!current()) return null
        return RuntimePresentationEvidence(id, profile.withPackageRevision(packages),
            id.takeIf { nativeReady }, id.takeIf { tunOwned },
            profile.settingsRevision.takeIf { tunOwned && applied != null && applied.routes.isNotEmpty() },
            profile.settingsRevision.takeIf { tunOwned && applied != null && applied.dnsServers.isNotEmpty() })
    }

    internal fun boundNetworkHandle(): Long = checkNotNull(production).delegate.boundNetworkHandle()

    internal fun capturedPlatformSettings(): RuntimeCapturedPlatformSettingsV1 {
        check(current())
        val capture = checkNotNull(captured).capture
        val sizes = IntArray(5)
        capture.copySizesInto(sizes)
        val bytes = ByteBuffer.allocateDirect(sizes[4])
        try {
            check(capture.copySettingsTo(bytes) == sizes[4] && current())
            return readCapturedPlatformSettingsV1(bytes)
        } finally {
            for (i in 0 until bytes.capacity()) bytes.put(i, 0)
            sizes.fill(0)
        }
    }

    internal fun establishProductTun(): RuntimeProductionEstablishedTunV1 {
        val ready = synchronized(monitor) { checkNotNull(productRoute) }
        return establishTun(productionTunConfigurationV1(ready, capturedRouting(), service.packageName), blocking = false)
    }

    internal fun startProductPackets(onFailure: () -> Unit): TunPacketPump {
        check(current())
        val session = synchronized(monitor) { checkNotNull(productSession) }
        val ready = synchronized(monitor) { checkNotNull(productRoute) }
        val tun = establishProductTun()
        val endpoint = AndroidTunPacketEndpoint()
        check(guard.own(RuntimeResourceKind.TUN, endpoint) != null)
        check(guard.acquire { tun.acquirePacketEndpoint(endpoint) })
        val pump = TunPacketPump(session, endpoint, ready.packetLimits.packetMax, onFailure)
        check(guard.own(RuntimeResourceKind.HEALTH_MONITOR, pump) != null)
        check(guard.acquire { pump.start() })
        return pump
    }

    internal fun admitProductRetryPolicy(): Boolean {
        check(current())
        val facts = checkNotNull(bootstrap).facts
        return coordinator.acceptProductionAuthority(decision.token, facts.effectiveAutomaticReconnectMaximum)
    }

    internal fun activateProduct(notification: RuntimeActivationResource, health: RuntimeActivationResource,
        publish: (NativeOpeningSnapshot) -> Unit): RuntimeStartDecision {
        val ready = synchronized(monitor) { checkNotNull(productRoute) }
        val requiresTun = ready.effectiveMode != org.kurdistanvpn.core.model.TunnelMode.PROXY_ONLY
        if (!guard.activateNativeOwned(requiresTun, notification, health,
                { current() && source.live() && initialAcquired && (!requiresTun || proof?.interfaceName() != null) },
                { publish(ready) }))
            return coordinator.failed(decision.token, RuntimeStartFailure.CANCELLED)
        return coordinator.activationCompleted(decision.token)
    }
    /** Non-owning port for this exact successful opening, never a way to open another session. */
    fun selectedSessionProbe(): RuntimeSelectedProbeV1? =
        if (current()) synchronized(monitor) { sessionProbe } else null

    private inner class OwnedSessionSelectedProbeV1(
        private val session: ProductionNativeSession,
        private val capturedBootstrap: NativeProductionBootstrapReadV1,
        private val binding: AndroidProductionProbeBindingV1,
    ) : RuntimeSelectedProbeV1 {
        private fun live(): Boolean {
            val valid = try {
                current() && client?.captureCurrent() == true &&
                    bootstrap === capturedBootstrap && binding.isCurrent()
            } catch (_: Exception) { false }
            if (!valid) binding.invalidate()
            return valid
        }
        override fun runSelected(preferences: ProbePreferences): NativeProductResult<NativeProbeResult> {
            val unavailable = NativeProductResult.Failure(ProductFailureCode.PROFILE_INCOMPATIBLE)
            if (!live()) return unavailable
            val selected = selectedProbeRequestV1(preferences)
            if (selected is NativeProductResult.Failure) return selected
            val request = (selected as NativeProductResult.Success).value
            if (!binding.permits(request.targetId) || !live()) return unavailable
            // Native rechecks signed method/mode/limits/rates. Never clamp a rejected request.
            val result = session.runProbe(request)
            if (!live()) return unavailable
            if (result is NativeProductResult.Success && result.value.path != NativeProbePath.ACTIVE_RELAY_END_TO_END)
                return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
            return result
        }
        override fun toString() = "OwnedSessionSelectedProbeV1(redacted)"
    }
    /** Uses the same authenticated capture and guard, including an associated owner. */
    fun openMaintenanceSession(): NativeProductResult<ProductionNativeMaintenance> {
        check(current())
        val selected = synchronized(monitor) { checkNotNull(maintenance) }
        var result: NativeProductResult<ProductionNativeMaintenance>? = null
        if (!guard.acquire {
            check(current())
            result = selected.callbacks.openMaintenance(
                { parent -> ownership.adoptNativeParent(2, parent) },
                { finalizeFailedOpening(2) })
            check(current())
        }) throw RuntimeAuthorityCleanupUnprovenException()
        return checkNotNull(result)
    }
    /** Trusted opening failure only; never infers retirement from a P1 error. */
    fun finalizeFailedOpening(kind: Int) {
        val selected = synchronized(monitor) {
            when (kind) { 1 -> checkNotNull(production); 2 -> checkNotNull(maintenance); else -> error("OWNER_KIND_REJECTED") }
        }
        ownership.finalizeFailedOpening(kind, selected.values[0], selected.values[1]) {
            selected.callbacks.finishFailedOpening(kind, selected.values[1])
        }
    }
    fun acquireAssociatedMaintenance(setup: (RuntimeProductionPlatformOwner) -> Unit) {
        check(initialKind == 1 && current() && initialAcquired)
        check(guard.acquire {
            val selected = Binding(2)
            synchronized(monitor) { check(maintenance == null && !closing); maintenance = selected }
            selected.acquire()
            setup(this)
            check(current())
        })
    }
    fun retireAssociatedMaintenance() {
        check(initialKind == 1)
        ownership.retireMaintenance()
        check(registration.rearmMaintenanceAfterRetirement())
        synchronized(monitor) { maintenance = null }
    }
    /** Additive service-owned TUN path. Configuration must come from the same admitted native session. */
    fun establishTun(configuration: LiveTunConfiguration, blocking: Boolean = true): RuntimeProductionEstablishedTunV1 {
        check(initialKind == 1 && current() && initialAcquired)
        val retainedProof = RuntimeTunProofOwner(::current)
        synchronized(monitor) { check(proof == null && !closing); proof = retainedProof }
        check(guard.own(RuntimeResourceKind.TUN, retainedProof) != null)
        var builder: VpnService.Builder? = null
        var establishedDescriptor: ParcelFileDescriptor? = null
        val platform = PlatformTunOwner(acquire = { checkNotNull(builder).establish() },
            validate = { original: ParcelFileDescriptor ->
                establishedDescriptor = original
                retainedProof.adoptEstablished(original); check(current())
            },
            detach = ParcelFileDescriptor::detachFd)
        val result = RuntimeProductionEstablishedTunV1(platform, ::current) {
            ParcelFileDescriptor.dup(checkNotNull(establishedDescriptor).fileDescriptor)
        }
        check(guard.own(RuntimeResourceKind.TUN, result) != null)
        check(guard.acquire {
            check(current() && configuration.mtu == checkNotNull(bootstrap).facts.effectiveMtu)
            val configured = service.Builder().setSession("Kurdistan VPN").setMtu(configuration.mtu).setBlocking(blocking)
            val networkHandle = checkNotNull(production).delegate.boundNetworkHandle()
            check(networkHandle != 0L) { "BOUND_NETWORK_UNAVAILABLE" }
            @Suppress("DEPRECATION") // API26-compatible lookup of the actually bound native socket network.
            val networks = service.getSystemService(ConnectivityManager::class.java).allNetworks
            check(networks.size <= 64)
            val underlying = checkNotNull(networks.singleOrNull { it.networkHandle == networkHandle })
            configured.setUnderlyingNetworks(arrayOf(underlying))
            configuration.addresses.forEach { configured.addAddress(it.address, it.prefixLength) }
            configuration.routes.forEach { configured.addRoute(it.address, it.prefixLength) }
            configuration.dnsServers.forEach(configured::addDnsServer)
            if (Build.VERSION.SDK_INT >= 29) configured.setMetered(configuration.metered)
            when (configuration.routingPolicy.perAppMode) {
                PerAppRoutingMode.ALL_APPS -> Unit
                PerAppRoutingMode.INCLUDE_ONLY -> configuration.routingPolicy.packages.forEach(configured::addAllowedApplication)
                PerAppRoutingMode.EXCLUDE_SELECTED -> configuration.routingPolicy.packages.forEach(configured::addDisallowedApplication)
            }
            builder = configured
            check(current())
            checkNotNull(platform.establish())
            check(service.setUnderlyingNetworks(arrayOf(underlying))) { "UNDERLYING_NETWORK_REJECTED" }
            ActiveVpnUnderlyingNetwork.publish(underlying)
            check(current())
            synchronized(monitor) { appliedTunConfiguration = configuration }
        })
        return result
    }
    /** External lifecycle entry, never invoked recursively from an owned resource's release. */
    fun stop(reason: RuntimeStopReason): RuntimeStartDecision {
        val activeClient = synchronized(monitor) { stopRequested = true; client }
        guard.markCancellation()
        activeClient?.cancelCall(1)
        val result = coordinator.stopIfCurrent(decision.token, reason)
        // The acquisition failure path may have retired this exact owner already.
        // CLEAN is actual old-guard proof; a missing/stale token alone proves nothing.
        return if (guard.cleanupState() == RuntimeCleanupState.CLEAN) RuntimeStartDecision.Idle else result
    }

    companion object {
        /** Continues the service coordinator's admitted attempt, without creating a second start. */
        internal fun acquireAdmitted(service: VpnService, admission: RuntimeStartDecision.RequestAuthority,
            onAdmitted: (RuntimeProductionPlatformOwner) -> Unit,
            setup: (RuntimeProductionPlatformOwner) -> Unit): RuntimeProductionPlatformOwner =
            acquireWithAdmission(service, admission.token.trigger, 1, true, onAdmitted, setup, admission)

        /** setup must immediately adopt each returned native parent before decoding or allocation. */
        fun acquire(service: VpnService, trigger: RuntimeAuthorityTrigger, kind: Int,
            setup: (RuntimeProductionPlatformOwner) -> Unit): RuntimeProductionPlatformOwner =
            acquireWithAdmission(service, trigger, kind, false, null, setup)

        /** Refuses another service's ownership atomically, without superseding it. */
        fun acquireIfIdle(service: VpnService, trigger: RuntimeAuthorityTrigger, kind: Int,
            onAdmitted: (RuntimeProductionPlatformOwner) -> Unit = {},
            setup: (RuntimeProductionPlatformOwner) -> Unit): RuntimeProductionPlatformOwner =
            acquireWithAdmission(service, trigger, kind, true, onAdmitted, setup)

        private fun acquireWithAdmission(service: VpnService, trigger: RuntimeAuthorityTrigger, kind: Int,
            idleOnly: Boolean, onAdmitted: ((RuntimeProductionPlatformOwner) -> Unit)?,
            setup: (RuntimeProductionPlatformOwner) -> Unit,
            admitted: RuntimeStartDecision.RequestAuthority? = null): RuntimeProductionPlatformOwner {
            require(kind in 1..2)
            val component = ComponentName(service, service.javaClass)
            val declared = service.packageManager.getServiceInfo(component, 0)
            val actualProcess = if (Build.VERSION.SDK_INT >= 28) Application.getProcessName()
                else service.getSystemService(ActivityManager::class.java)?.runningAppProcesses
                    ?.firstOrNull { it.pid == Process.myPid() }?.processName
            check(declared.name == component.className && RuntimeProductionServiceIdentityV1.accepts(
                service.packageName, actualProcess, declared.processName, Process.myUid(),
                declared.applicationInfo.uid, declared.permission, declared.exported, declared.directBootAware))
            val coordinator = RuntimeStartCoordinator.processOwner()
            val unlocked = service.getSystemService(UserManager::class.java)?.isUserUnlocked == true
            val prepared = VpnService.prepare(service) == null
            val admission = admitted ?: if (idleOnly) coordinator.beginIfIdle(trigger, unlocked, prepared)
                else coordinator.begin(trigger, unlocked, prepared)
            check(admission is RuntimeStartDecision.RequestAuthority)
            check(unlocked && prepared && coordinator.ownsAdmission(admission))
            val owner = RuntimeProductionPlatformOwner(service, coordinator, admission, kind)
            check(admission.guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, owner.ownership) != null)
            runProductionAcquisitionV1(coordinator, admission, { onAdmitted?.invoke(owner) }) {
                owner.acquire(); setup(owner); check(owner.current())
            }
            return owner
        }
    }
}
internal interface RuntimeProductionCallbackSignalsV1 {
    fun cancelled(owner: Long, call: Long): Boolean
    fun remainingMillis(owner: Long, call: Long): Long?
    fun socketLost(owner: Long, signal: Long): Int
    fun networkLost(owner: Long, signal: Long): Int
}

/** One delegate per fixed C owner; framework acquisitions use the actual service-owned factories. */
internal class RuntimeProductionCallbackDelegateV1(private val kind: Int,
    private val authority: RuntimeProductionCallbackAuthorityV1,
    private val registration: RuntimeProductionRegistrationV1,
    private val signals: RuntimeProductionCallbackSignalsV1,
    private val ownerRetired: (Int, Long) -> Boolean,
    private val newSocket: (RuntimeSocketIdentityV1, () -> Unit) -> RuntimeProductionSocketOwner,
    private val newNetwork: (() -> Unit) -> VpnMaintenanceNetworkLease,
    private val now: () -> Long,
) : AndroidProductionPlatformDelegateV1 {
    private val monitor = Any()
    private var owner = 0L
    private var nextId = 0L
    private var revision = 0L
    private var revisionSignal = 0L
    private var epoch = 0L
    private var publication = 0L
    private var publicationInitial = false
    private var publicationDeadline = 0L
    private val publicationDiagnostic = LongArray(16) { -1 }
    private var transport = 0L
    private var socket: RuntimeProductionSocketOwner? = null
    private var network: VpnMaintenanceNetworkLease? = null
    private var closed = false
    private var unproven = false
    private var selectorsBound = false
    @Volatile private var firstSocketRejection = 0

    private fun recordSocketRejection(phase: Int, failure: Throwable? = null) {
        // Fixed own-source scalars only; observation cannot replace the real outcome.
        runCatching {
            if (firstSocketRejection != 0) return
            val category = when (failure) {
                null -> 0
                is RuntimeAuthorityCleanupUnprovenException -> 1
                is java.util.concurrent.CancellationException -> 2
                is IllegalArgumentException -> 3
                is IllegalStateException -> 4
                is java.io.IOException -> 5
                else -> 6
            }
            var origin = 0
            var line = 0
            var cause = failure
            for (depth in 0 until 4) {
                val actual = cause ?: break
                for (frame in actual.stackTrace.take(16)) {
                    val found = when {
                        frame.className == "org.kurdistanvpn.runtime.android.RuntimeProductionCallbackDelegateV1" &&
                            frame.fileName == "RuntimeProductionPlatformOwner.kt" -> 1
                        frame.className == "org.kurdistanvpn.runtime.android.RuntimeProductionSocketOwner" &&
                            frame.fileName == "RuntimeProductionSocketOwner.kt" -> 2
                        frame.className == "org.kurdistanvpn.runtime.android.AndroidSocketPlatformV1" &&
                            frame.fileName == "RuntimeProductionSocketOwner.kt" -> 3
                        else -> 0
                    }
                    if (found != 0) {
                        origin = found
                        line = frame.lineNumber.takeIf { it in 1..1023 } ?: 0
                        break
                    }
                }
                if (origin != 0) break
                cause = actual.cause
            }
            val encoded = phase or (category shl 4) or (origin shl 7) or (line shl 9)
            synchronized(monitor) { if (firstSocketRejection == 0) firstSocketRejection = encoded }
        }
    }

    fun adoptOwner(value: Long) = synchronized(monitor) { check(owner == 0L && value != 0L && !closed); owner = value }
    override fun capturedGeneration(owner: Long): Long = readCapturedGenerationV1(
        { owns(owner) && authority.live() }, authority::capturedGeneration).toLong()
    private fun bindSelectors(owner:Long,expectedKind:Int,bind:()->AndroidProductionProbeBindingV1):AndroidProductionProbeBindingV1 {
        check(kind==expectedKind && owns(owner) && current())
        synchronized(monitor){check(!selectorsBound);selectorsBound=true}
        val bound=bind()
        return object:AndroidProductionProbeBindingV1 {
            override fun isCurrent():Boolean {
                val sameNetwork=synchronized(monitor){network}
                val live=try { owns(owner) && current() && (kind!=2 || sameNetwork?.isCurrent()==true) }
                    catch(_:Throwable){false}
                if(!live)bound.invalidate()
                return bound.isCurrent()
            }
            override fun permits(target:Int)=isCurrent() && bound.permits(target) && isCurrent()
            override fun observe(event:NativeControlEvent)=bound.observe(event)
            override fun invalidate()=bound.invalidate()
        }
    }
    override fun bindActiveSelectors(owner:Long,generation:Long,digest:ByteArray)=
        bindSelectors(owner,1){authority.bindActive(generation.toULong(),digest)}
    override fun bindDisconnectedSelectors(owner:Long)=bindSelectors(owner,2){authority.bindDisconnected()}
    override fun owns(owner: Long): Boolean = synchronized(monitor) { owner != 0L && this.owner == owner && !closed && !unproven }
    private fun id(): Long { check(nextId != Long.MAX_VALUE); return ++nextId }
    private fun live(call: Long): Boolean = owns(owner) && call != 0L && !signals.cancelled(owner, call) && authority.live()
    private fun deadline(call: Long): Long = Math.addExact(now(), minOf(60_000, signals.remainingMillis(owner, call) ?: 60_000))
    private fun exact(owner: Long, revision: Long): Boolean = owns(owner) && revision != 0L && synchronized(monitor) { this.revision == revision }
    private fun current(): Boolean = owns(owner) && authority.live() && registration.isCurrent(kind, owner, revisionSignal)
    private inline fun bridge(action: () -> Int): Int = try { action() } catch (_: Throwable) {
        synchronized(monitor) { unproven = true }; 25
    }

    override fun captureSizes(owner: Long, sizes: IntArray): Int = bridge {
        if (sizes.size != 5 || !owns(owner) || !authority.live()) return 1
        authority.capture.copySizesInto(sizes)
        if (!authority.live()) { sizes.fill(0); return 6 }
        0
    }
    override fun captureCopyInto(owner: Long, verify: ByteBuffer, activation: ByteBuffer, recipient: ByteBuffer,
        privateRecipient: ByteBuffer, settings: ByteBuffer, written: IntArray): Int {
        val spans = arrayOf(verify, activation, recipient, privateRecipient, settings)
        written.fill(0)
        var status = 25
        try {
            if (written.size != 5 || !owns(owner) || !authority.live()) return 1
            val sizes = IntArray(5)
            authority.capture.copySizesInto(sizes)
            for (i in 0..4) if (!spans[i].isDirect || spans[i].isReadOnly || spans[i].position() != 0 ||
                spans[i].capacity() != sizes[i] || spans[i].limit() != sizes[i]) return 1
            written[0] = authority.capture.copyVerifyRequestTo(verify)
            written[1] = authority.capture.copyActivationRecordTo(activation)
            written[2] = authority.capture.copyRecipientRequestTo(recipient)
            written[3] = authority.capture.copyRecipientPrivateTo(privateRecipient)
            written[4] = authority.capture.copySettingsTo(settings)
            if (!written.contentEquals(sizes) || !authority.live()) return 6
            status = 0
            return 0
        } catch (_: Throwable) { synchronized(monitor) { unproven = true }; return 25 }
        finally {
            if (status != 0) {
                written.fill(0)
                spans.forEach { span -> if (!span.isReadOnly) { val limit = span.limit(); span.limit(span.capacity());
                    for (i in 0 until span.capacity()) span.put(i, 0); span.limit(limit) } }
            }
        }
    }
    private fun register(requestKind: Int, owner: Long, epoch: Long, signal: Long, out: LongArray): Int = bridge {
        if (out.size != 1) return 1
        out[0] = 0
        if (requestKind != kind || !owns(owner) || epoch == 0L || signal == 0L || !authority.live()) return 1
        synchronized(monitor) {
            if (revision != 0L) return 25
            revision = id(); this.epoch = epoch; revisionSignal = signal; out[0] = revision
        }
        if (!registration.register(kind, owner, signal) || !authority.live()) return 6
        0
    }
    override fun productionCurrentRegister(owner: Long, epoch: Long, signal: Long, out: LongArray) = register(1, owner, epoch, signal, out)
    override fun maintenanceCurrentRegister(owner: Long, epoch: Long, signal: Long, out: LongArray) = register(2, owner, epoch, signal, out)
    @Volatile private var firstRevalidationRejection = 0
    override fun revisionRevalidate(owner: Long, registration: Long, call: Long): Int {
        var phase = 1
        fun rejected(status: Int, category: Int = 0): Int {
            synchronized(monitor) {
                if (firstRevalidationRejection == 0) firstRevalidationRejection = phase or (category shl 4)
            }
            return status
        }
        return try {
            if (!exact(owner, registration) || !live(call)) rejected(8)
            else {
                phase = 2
                if (!current()) rejected(3)
                else {
                    phase = 3
                    if (!authority.revalidateCurrent(call, deadline(call))) rejected(3)
                    else {
                        phase = 4
                        if (!live(call)) rejected(3)
                        else { phase = 5; if (!current()) rejected(3) else 0 }
                    }
                }
            }
        } catch (failure: Throwable) {
            val category = when (failure) {
                is RuntimeAuthorityCleanupUnprovenException -> 1
                is java.util.concurrent.CancellationException -> 2
                is IllegalArgumentException -> 3
                is IllegalStateException -> 4
                is java.io.IOException -> 5
                else -> 6
            }
            synchronized(monitor) { unproven = true }
            rejected(3, category)
        }
    }
    override fun publicationAcquire(owner: Long, registration: Long, call: Long, out: LongArray): Int {
        var phase = 1
        var initialState = -1L
        var predicate = -1L
        fun rejected(code: Int): Int {
            recordProductionPublicationV1(publicationDiagnostic, 0, phase, 1, predicate = predicate, state = initialState)
            return code
        }
        return try {
        if (out.size != 1) return rejected(1)
        out[0] = 0
        if (!exact(owner, registration) || !live(call) || !current()) return rejected(8)
        val initial = !authority.initialAcquired
        initialState = if (initial) 1 else 0
        if (!initial && kind != 2) return rejected(3)
        phase = 2
        val until = deadline(call)
        phase = 3
        synchronized(monitor) {
            if (publication != 0L) return rejected(3)
            publication = id(); publicationInitial = initial; publicationDeadline = until; out[0] = publication
        }
        phase = 4
        val acquired = if (initial) authority.acquireInitial(call) else authority.revalidateCurrent(call, until)
        predicate = if (acquired) 1 else 0
        phase = 5
        if (!acquired || !live(call) || !current()) rejected(3) else {
            recordProductionPublicationV1(publicationDiagnostic, 0, 6, 0, predicate = 1, state = initialState, completed = 1)
            0
        }
        } catch (failure: Throwable) {
            recordProductionPublicationV1(publicationDiagnostic, 0, phase, 2, predicate = predicate, state = initialState, failure = failure)
            synchronized(monitor) { unproven = true }; 3
        }
    }
    override fun publicationIsCurrent(owner: Long, registration: Long, publication: Long, out: IntArray): Int = bridge {
        if (out.size != 1) return 1
        out[0] = 0
        if (!exact(owner, registration) || publication == 0L || synchronized(monitor) { this.publication != publication }) return 25
        if (current() && now() < publicationDeadline && (!publicationInitial || authority.initialCurrent())) out[0] = 1
        0
    }
    override fun publicationClose(owner: Long, registration: Long, publication: Long): Int {
        var phase = 1
        var predicate = -1L
        var initialState = -1L
        fun rejected(code: Int, category: Int = 1): Int {
            recordProductionPublicationV1(publicationDiagnostic, 8, phase, category, predicate = predicate, state = initialState)
            return code
        }
        return bridge {
        try {
        synchronized(monitor) {
            if (this.owner != owner || owner == 0L || this.revision != registration || this.publication != publication || publication == 0L) return rejected(25)
        }
        initialState = if (publicationInitial) 1 else 0
        phase = 2
        if (publicationInitial) {
            val released = authority.releaseInitial()
            predicate = if (released) 1 else 0
            phase = 3
            if (!released) return rejected(25)
        }
        phase = 4
        synchronized(monitor) { this.publication = 0; publicationInitial = false; publicationDeadline = 0 }
        if (unproven) rejected(25, 4) else {
            recordProductionPublicationV1(publicationDiagnostic, 8, 5, 0, predicate = predicate, state = initialState, completed = 1)
            0
        }
        } catch (failure: Throwable) {
            recordProductionPublicationV1(publicationDiagnostic, 8, phase, 2, predicate = predicate, state = initialState, failure = failure)
            throw failure
        }
        }
    }
    override fun revisionClose(owner: Long, registration: Long): Int = bridge {
        synchronized(monitor) {
            if (owner == 0L || this.owner != owner || this.revision != registration || registration == 0L || publication != 0L) return 25
        }
        if (!this.registration.retire(kind, owner, revisionSignal)) return 25
        synchronized(monitor) { revision = 0; revisionSignal = 0 }
        if (unproven) 25 else 0
    }
    override fun socketRegister(owner: Long, call: Long, epoch: Long, attempt: Long, token: Long, fd: Int,
        explicit: Int, hasNetwork: Int, network: Long, signal: Long, out: LongArray, binding: IntArray): Int = try {
        if (out.size != 1 || binding.size != 1) return 2
        out[0] = 0; binding[0] = 0
        if (kind != 1 || !owns(owner) || !live(call) || this.epoch != epoch || signal == 0L) return 14
        val identity = RuntimeSocketIdentityV1(epoch, attempt, token, fd, explicit, hasNetwork, network)
        synchronized(monitor) { if (transport != 0L) return 18; transport = id(); out[0] = transport }
        socket = newSocket(identity) { check(signals.socketLost(owner, signal) == 0) }
        if (!live(call)) return 14
        if (!checkNotNull(socket).acquire(identity)) return 9
        binding[0] = 1
        if (!live(call)) 14 else 0
    } catch (failure: Throwable) { recordSocketRejection(1, failure); synchronized(monitor) { unproven = true }; 18 }
    override fun socketConfirm(owner: Long, socket: Long, protected: Int, hasNetwork: Int, network: Long): Int = try {
        if (!owns(owner) || kind != 1 || socket == 0L || socket != transport || !current()) 14
        else checkNotNull(this.socket).confirm(protected, hasNetwork, network)
    } catch (failure: Throwable) { recordSocketRejection(2, failure); synchronized(monitor) { unproven = true }; 18 }
    internal fun boundNetworkHandle(): Long = if (current()) socket?.boundNetworkHandle() ?: 0 else 0
    override fun socketClose(owner: Long, socket: Long): Int = try {
        if (owner == 0L || this.owner != owner || socket == 0L || transport != socket || network != null) {
            recordSocketRejection(3); return 25
        }
        this.socket?.close()
        synchronized(monitor) { this.socket = null; transport = 0 }
        if (unproven) { recordSocketRejection(4); 25 } else 0
    } catch (failure: Throwable) { recordSocketRejection(5, failure); synchronized(monitor) { unproven = true }; 25 }
    override fun maintenanceNetworkAcquire(owner: Long, call: Long, signal: Long, out: LongArray): Int = try {
        if (out.size != 1) return 1
        out[0] = 0
        if (kind != 2 || !owns(owner) || !live(call) || signal == 0L || !current()) return 8
        synchronized(monitor) { if (transport != 0L) return 6; transport = id(); out[0] = transport }
        network = newNetwork { check(signals.networkLost(owner, signal) == 0) }
        if (!live(call)) return 8
        val result = checkNotNull(network).acquire()
        if (result == 0 && !live(call)) 8 else result
    } catch (_: Throwable) { synchronized(monitor) { unproven = true }; 10 }
    override fun maintenanceNetworkSnapshot(owner: Long, network: Long, dns: ByteBuffer, metadata: IntArray): Int = try {
        if (!owns(owner) || network == 0L || transport != network || kind != 2) 1
        else checkNotNull(this.network).copySnapshot(dns, metadata)
    } catch (_: Throwable) { synchronized(monitor) { unproven = true }; 10 }
    override fun maintenanceNetworkIsCurrent(owner: Long, network: Long, out: IntArray): Int = try {
        if (out.size != 1) return 1
        out[0] = 0
        if (!owns(owner) || network == 0L || transport != network || kind != 2) return 1
        if (current() && checkNotNull(this.network).isCurrent()) out[0] = 1
        0
    } catch (_: Throwable) { synchronized(monitor) { unproven = true }; 10 }
    override fun maintenanceNetworkBindSocket(owner: Long, network: Long, fd: Int): Int = try {
        if (!owns(owner) || network == 0L || transport != network || kind != 2 || !current()) 10
        else checkNotNull(this.network).bindSocket(fd)
    } catch (_: Throwable) { synchronized(monitor) { unproven = true }; 10 }
    override fun maintenanceNetworkClose(owner: Long, network: Long): Int = bridge {
        if (owner == 0L || this.owner != owner || network == 0L || transport != network || socket != null) return 25
        this.network?.close()
        synchronized(monitor) { this.network = null; transport = 0 }
        if (unproven) 25 else 0
    }
    override fun cancelCall(owner: Long, call: Long): Int = bridge {
        if (!owns(owner) || call == 0L) return 25
        // No Binder wait currently owned is distinct from callback failure or cleanup proof.
        if (authority.cancel(call)) 0 else if (signals.cancelled(owner, call)) 0 else 25
    }
    override fun ownerClose(owner: Long): Int = bridge {
        synchronized(monitor) {
            if (this.owner != owner || owner == 0L || closed || unproven || revision != 0L || publication != 0L || transport != 0L) return 25
            closed = true
        }
        if (ownerRetired(kind, owner)) 0 else 25
    }
}
