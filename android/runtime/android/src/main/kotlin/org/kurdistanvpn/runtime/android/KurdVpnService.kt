// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Binder
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Parcel
import android.os.SystemClock
import android.os.UserManager
import java.io.Closeable
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.nio.ByteBuffer
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.model.TunnelMode
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.model.ResolverPolicy
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.runtime.api.*

internal fun providerDeathFailureV1(failure: RuntimeStartFailure, inProgress: Boolean,
    canRetry: Boolean): RuntimeStartFailure? {
    val providerLoss = failure == RuntimeStartFailure.AUTHORITY_REJECTED ||
        failure == RuntimeStartFailure.ENDPOINT_UNAVAILABLE
    // Only consequences of the death fence wait for settlement. Independent
    // terminal failures retain precedence through the existing coordinator.
    if (providerLoss && inProgress) return null
    return if (providerLoss && canRetry)
        RuntimeStartFailure.AUTHORITY_PROVIDER_LOST else failure
}

/** One VPN-process coordinator, one TUN owner. A lifecycle Intent never conveys authority. */
class KurdVpnService : VpnService() {
    private val coordinator = RuntimeStartCoordinator.processOwner()
    private val executor = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(32),
        { task -> Thread(task, "kurd-vpn-tun").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
    private val mainHandler = Handler(Looper.getMainLooper())
    @Volatile private var attempt: Attempt? = null
    @Volatile private var destroyed = false
    @Volatile private var latestSnapshot = PublishedSnapshot()
    private val settingsContinuation = RuntimeSettingsContinuation(SystemClock::elapsedRealtime)
    private var settingsExpiry: Runnable? = null // guarded by settingsContinuation
    private val maintenance = RuntimeServiceMaintenance(this,
        { attempt?.takeIf { current(it) && it.guard.isActive() }?.production },
        { attempt == null }, { !destroyed })
    private val controlProbe = RuntimeControlProbe { profileId ->
        val owner = attempt
        if (owner == null || !current(owner) || !owner.guard.isActive() ||
            owner.production?.presentationEvidence()?.binding?.profileId != profileId.value) null
        else owner.production?.selectedSessionProbe()
    }
    private val controlBinder by lazy {
        RuntimeControlBinder(applicationInfo.uid, { controlSnapshot() }, proxyCredentials = {
            val owner = attempt
            if (owner != null && current(owner) && owner.guard.isActive()) owner.proxy?.credentials?.copyForReveal() else null
        }, settingsTransition = ::settingsTransition, observerLost = {
            controlProbe.cancel(null, it)
            maintenance.cancel(null, it)
            settingsContinuation.invalidate(it)
            dispatch { if (attempt == null) finishService() }
        }, probe = { id, profile, target, timeout, peer ->
            val profileId = org.kurdistanvpn.core.model.CatalogId(profile)
            val preferences = org.kurdistanvpn.core.model.ProbePreferences(org.kurdistanvpn.core.model.ProbeMethod.TCP_CONNECT,
                signedTargetId = org.kurdistanvpn.core.model.CatalogId("probe-$target"), timeoutSeconds = timeout)
            RuntimeProbeWire.encode(if (attempt == null) maintenance.run(id, profileId, peer) { parent ->
                when (val request = selectedProbeRequestV1(preferences)) {
                    is NativeProductResult.Failure -> request
                    is NativeProductResult.Success -> parent.runProbe(request.value)
                }
            } else controlProbe.run(id, profileId, preferences, peer))
        }, cancelProbe = { id, peer ->
            val probeCancelled = controlProbe.cancel(id, peer)
            maintenance.cancel(id, peer) || probeCancelled
        }, update = { id, profile, output, peer ->
            val result = maintenance.run(id, org.kurdistanvpn.core.model.CatalogId(profile), peer, ::materializeRuntimeUpdate)
            val artifact = (result as? NativeProductResult.Success)?.value
            try {
                if (artifact != null) {
                    RuntimeAuthorityPipeOwner.take(output, org.kurdistanvpn.core.nativejni.NativeBridge().durableFiles(),
                        applicationInfo.uid.toLong(), 1, SystemClock.elapsedRealtime() + 5_000,
                        { !destroyed && peer.isBinderAlive }).use { pipe ->
                        var offset = 0
                        while (offset < artifact.artifact.size) {
                            val written = pipe.write(artifact.artifact, offset, artifact.artifact.size - offset)
                            check(written > 0)
                            offset += written
                        }
                    }
                }
                RuntimeUpdateWire.encode(result)
            } finally { artifact?.close() }
        }) { code ->
            when (RuntimeAction.fromWire(code)) {
                RuntimeAction.STOP -> {
                    settingsContinuation.invalidate()
                    mainHandler.post { requestStop(RuntimeStopReason.STOP, VpnRuntimeState.IDLE) }
                    true
                }
                RuntimeAction.RECOVER_INTERNET -> {
                    settingsContinuation.invalidate()
                    mainHandler.post { requestStop(RuntimeStopReason.RECOVER_INTERNET, VpnRuntimeState.IDLE) }
                    true
                }
                RuntimeAction.QUERY_STATUS -> true
                RuntimeAction.RESTART_PROXY -> {
                    val owner = attempt
                    if (owner == null || !current(owner) || !owner.guard.isActive() ||
                        owner.authority?.effectiveMode != TunnelMode.TUN_PLUS_PROXY) false
                    else { dispatch { restartProxy(owner) }; true }
                }
                RuntimeAction.ROTATE_PROXY_CREDENTIALS -> {
                    val owner = attempt
                    if (owner == null || !current(owner) || !owner.guard.isActive() || owner.proxy == null) false
                    else { owner.proxy?.credentials?.rotate(); true }
                }
                else -> false
            }
        }
    }
    private data class HeldMutationQuiescence(val id: String, val lease: AutoCloseable,
        val death: IBinder.DeathRecipient)
    private val quiescenceMonitor = Any()
    private val mutationQuiescences = linkedMapOf<IBinder, HeldMutationQuiescence>()
    private val mutationQuiescenceBinder = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code !in RuntimeMutationQuiescenceWire.ACQUIRE..RuntimeMutationQuiescenceWire.RELEASE ||
                reply == null || flags and IBinder.FLAG_ONEWAY != 0 || data.dataSize() > RuntimeMutationQuiescenceWire.MAX_PARCEL_BYTES)
                return false
            return try {
                data.enforceInterface(RuntimeMutationQuiescenceWire.DESCRIPTOR)
                require(data.readInt() == RuntimeMutationQuiescenceWire.VERSION && getCallingUid() == applicationInfo.uid)
                val lifetime = checkNotNull(data.readStrongBinder()).also { require(it.isBinderAlive) }
                val id = RuntimeMutationQuiescenceWire.leaseId(data)
                val deadline = data.readLong()
                require(data.dataAvail() == 0)
                val accepted = when (code) {
                    RuntimeMutationQuiescenceWire.ACQUIRE -> acquireMutationQuiescence(lifetime, id, deadline)
                    RuntimeMutationQuiescenceWire.RELEASE -> releaseMutationQuiescence(lifetime, id)
                    else -> false
                }
                reply.writeNoException(); reply.writeInt(if (accepted) 1 else 0)
                true
            } catch (_: Throwable) {
                reply.setDataSize(0); reply.writeNoException(); reply.writeInt(0); true
            }
        }
    }
    private inner class Attempt(val admission: RuntimeStartDecision.RequestAuthority) {
        val token = admission.token
        val guard = admission.guard
        val cancelled = AtomicBoolean(false)
        val health = RuntimeSessionHealth()
        var production: RuntimeProductionPlatformOwner? = null
        var session: ProductionNativeSession? = null
        var pump: TunPacketPump? = null
        @Volatile var proxy: LocalProxySupervisor? = null
        var authority: NativeOpeningSnapshot? = null
        @Volatile var platformSettings: RuntimeCapturedPlatformSettingsV1? = null
        @Volatile var appliedRevision: Long = 0
        val cleanupQueued = AtomicBoolean(false)
        var cleanupDeadline = 0L
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val command = sanitizedCommand(intent)
        if (command !is RuntimeServiceCommand.Rejected) settingsContinuation.invalidate()
        when (command) {
            is RuntimeServiceCommand.Rejected -> {
                // An invalid start cannot tear down or replace a separately admitted session.
                if (attempt?.let { !it.cancelled.get() && it.guard.isActive() } == true)
                    return Service.START_STICKY
                if (attempt == null) {
                    try { promote(notification(getString(R.string.runtime_notification_blocked))) }
                    finally {
                        publish(PublishedSnapshot(state = VpnRuntimeState.BLOCKED, failure = command.reason))
                        finishService()
                    }
                }
            }
            RuntimeServiceCommand.Stop -> {
                requestStop(RuntimeStopReason.STOP, VpnRuntimeState.IDLE, promoteStopNotification = true)
            }
            RuntimeServiceCommand.Recover -> {
                requestStop(RuntimeStopReason.RECOVER_INTERNET, VpnRuntimeState.IDLE, promoteStopNotification = true)
            }
            is RuntimeServiceCommand.Manual, RuntimeServiceCommand.AutomaticTrigger -> {
                if (attempt?.guard?.isActive() != true) {
                    try { promote(notification(getString(R.string.runtime_notification_connecting))) }
                    catch (failure: Throwable) {
                        requestStop(RuntimeStopReason.CANCEL, VpnRuntimeState.BLOCKED,
                            finalFailure = runtimeStartFailure(this, failure))
                        return Service.START_NOT_STICKY
                    }
                }
                if (!isUnlocked()) {
                    publish(PublishedSnapshot(state = VpnRuntimeState.BLOCKED, failure = "FIRST_UNLOCK_REQUIRED"))
                    finishService()
                } else if (!isPrepared()) {
                    requestStop(RuntimeStopReason.REVOKE, VpnRuntimeState.REVOKED)
                } else {
                    val trigger = if (command is RuntimeServiceCommand.Manual) RuntimeAuthorityTrigger.MANUAL else RuntimeAuthorityTrigger.AUTOMATIC
                    if (trigger == RuntimeAuthorityTrigger.MANUAL && attempt?.token?.trigger != RuntimeAuthorityTrigger.MANUAL) {
                        attempt?.let { it.cancelled.set(true); it.guard.markCancellation() }
                    }
                    dispatch {
                        handle(coordinator.begin(trigger, isUnlocked(), isPrepared(),
                            (command as? RuntimeServiceCommand.Manual)?.requestId))
                    }
                    // Recreate an interrupted started service with a null intent, never replay
                    // manual authority. The automatic path reopens current protected bootstrap.
                    return Service.START_STICKY
                }
            }
        }
        return Service.START_NOT_STICKY
    }

    override fun onRevoke() {
        requestStop(RuntimeStopReason.REVOKE, VpnRuntimeState.REVOKED)
        super.onRevoke()
    }

    override fun onDestroy() {
        destroyed = true
        val standaloneMaintenance = maintenance.markCancelled()
        settingsContinuation.invalidate()
        synchronized(settingsContinuation) {
            settingsExpiry?.let(mainHandler::removeCallbacks); settingsExpiry = null
        }
        controlBinder.close()
        releaseAllMutationQuiescences()
        attempt?.let { it.cancelled.set(true); it.guard.markCancellation() }
        dispatch {
            // A query-only binding owns no session. Its destruction must not cancel
            // another service's admitted owner in the shared VPN process.
            attempt?.let { handle(coordinator.stopIfCurrent(it.token, RuntimeStopReason.CANCEL), VpnRuntimeState.IDLE) }
            standaloneMaintenance?.stop(RuntimeStopReason.CANCEL)
        }
        executor.shutdown()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? {
        if (intent?.action == RuntimeControlBinder.ACTION_BIND) {
            val expected = ComponentName(this, KurdVpnService::class.java)
            return if (intent.component == expected && intent.data == null && intent.clipData == null &&
                intent.selector == null && intent.categories.isNullOrEmpty() && intent.flags == 0 &&
                intent.extras?.isEmpty != false) controlBinder else null
        }
        if (intent?.action == RuntimeMutationQuiescenceWire.ACTION) {
            val expected = ComponentName(this, KurdVpnService::class.java)
            return if (intent.component == expected && intent.data == null && intent.clipData == null &&
                intent.selector == null && intent.categories.isNullOrEmpty() && intent.flags == 0 &&
                intent.extras?.isEmpty != false) mutationQuiescenceBinder else null
        }
        // Preserve the platform VpnService binding contract for SERVICE_INTERFACE.
        return super.onBind(intent)
    }

    private fun acquireMutationQuiescence(lifetime: IBinder, id: String, deadline: Long): Boolean {
        val now = SystemClock.elapsedRealtime()
        if (!RuntimeMutationQuiescenceWire.acceptsAdmissionDeadline(now, deadline)) return false
        val lease = coordinator.acquireMutationQuiescenceLease() ?: return false
        val held = HeldMutationQuiescence(id, lease, IBinder.DeathRecipient { releaseMutationQuiescence(lifetime, id) })
        val installed = synchronized(quiescenceMonitor) {
            if (SystemClock.elapsedRealtime() >= deadline || mutationQuiescences.isNotEmpty() ||
                mutationQuiescences.containsKey(lifetime)) false
            else {
                mutationQuiescences[lifetime] = held
                true
            }
        }
        if (!installed) return try { lease.close(); false } catch (_: Throwable) { false }
        return try {
            lifetime.linkToDeath(held.death, 0)
            synchronized(quiescenceMonitor) { mutationQuiescences[lifetime] === held }
        } catch (_: Throwable) {
            releaseMutationQuiescence(lifetime, id)
            false
        }
    }

    private fun releaseMutationQuiescence(lifetime: IBinder, id: String): Boolean {
        val held = synchronized(quiescenceMonitor) {
            val current = mutationQuiescences[lifetime]
            if (current == null || current.id != id) null else {
                mutationQuiescences.remove(lifetime)
                current
            }
        } ?: return false
        var clean = true
        try { held.lease.close() } catch (_: Throwable) { clean = false }
        try { lifetime.unlinkToDeath(held.death, 0) } catch (_: Throwable) { clean = false }
        return clean
    }

    private fun releaseAllMutationQuiescences() {
        val held = synchronized(quiescenceMonitor) { mutationQuiescences.toMap().also { mutationQuiescences.clear() } }
        held.forEach { (lifetime, value) ->
            try { value.lease.close() } catch (_: Throwable) { }
            try { lifetime.unlinkToDeath(value.death, 0) } catch (_: Throwable) { }
        }
    }

    private fun sanitizedCommand(intent: Intent?): RuntimeServiceCommand = try {
        val extras = intent?.extras
        if (extras == null) RuntimeServiceCommand.fromScalars(intent?.action, emptyMap())
        else if (extras.size() > 2) RuntimeServiceCommand.Rejected("FORBIDDEN_START_EXTRA")
        else {
            val scalars = LinkedHashMap<String, Any?>()
            for (key in extras.keySet()) {
                if (key != RuntimeServiceCommand.MARKER_KEY && key != RuntimeServiceCommand.REQUEST_KEY)
                    return RuntimeServiceCommand.Rejected("FORBIDDEN_START_EXTRA")
                @Suppress("DEPRECATION")
                val value = extras.get(key)
                if (value !is Int && value !is String) return RuntimeServiceCommand.Rejected("MALFORMED_START_EXTRA")
                scalars[key] = value
            }
            RuntimeServiceCommand.fromScalars(intent.action, scalars)
        }
    } catch (_: Throwable) { RuntimeServiceCommand.Rejected("MALFORMED_START_PARCEL") }

    private fun handle(decision: RuntimeStartDecision, finalState: VpnRuntimeState = VpnRuntimeState.FAILED,
        finalFailure: String? = null) {
        when (decision) {
            is RuntimeStartDecision.RequestAuthority -> {
                val next = Attempt(decision)
                attempt = next
                publish(PublishedSnapshot(state = if (decision.delayMillis == 0L) VpnRuntimeState.CONNECTING else VpnRuntimeState.RECONNECTING,
                    requestId = next.token.requestId))
                if (decision.delayMillis == 0L) acquireAuthority(next)
                else {
                    val retry = Runnable { dispatch { if (current(next)) acquireAuthority(next) } }
                    if (next.guard.own(RuntimeResourceKind.HEALTH_MONITOR, Closeable { mainHandler.removeCallbacks(retry) }) == null ||
                        !mainHandler.postDelayed(retry, decision.delayMillis)) fail(next, RuntimeStartFailure.INTERNAL_FAILURE)
                }
            }
            is RuntimeStartDecision.Ready -> {
                decision.authority.close()
                attempt?.takeIf { it.token == decision.token }?.let { fail(it, RuntimeStartFailure.AUTHORITY_REJECTED) }
            }
            is RuntimeStartDecision.Active, is RuntimeStartDecision.Coalesced, RuntimeStartDecision.Stale -> Unit
            is RuntimeStartDecision.CleanupPending -> {
                publish(PublishedSnapshot(state = VpnRuntimeState.BLOCKED, failure = "CLEANUP_" + decision.state.name,
                    requestId = decision.token.requestId))
                // No retry/replacement or success can cross incomplete cleanup.
                if (decision.state == RuntimeCleanupState.CLEANUP_REQUIRED) scheduleCleanupDrain(decision.token, finalState, finalFailure)
            }
            is RuntimeStartDecision.Rejected -> {
                attempt = null
                publish(PublishedSnapshot(state = VpnRuntimeState.BLOCKED, failure = decision.failure.name))
                finishService()
            }
            RuntimeStartDecision.Idle -> {
                attempt = null
                publish(PublishedSnapshot(state = finalState, failure = finalFailure))
                finishService()
            }
        }
    }

    private fun scheduleCleanupDrain(token: RuntimeStartToken, finalState: VpnRuntimeState, finalFailure: String?) {
        val value = attempt?.takeIf { it.token == token } ?: return
        val now = SystemClock.elapsedRealtime()
        if (value.cleanupDeadline == 0L) value.cleanupDeadline = now + 5_000
        if (destroyed || now >= value.cleanupDeadline || !value.cleanupQueued.compareAndSet(false, true)) return
        val drain = Runnable {
            value.cleanupQueued.set(false)
            dispatch {
                if (coordinator.currentToken() == token)
                    handle(coordinator.cleanupCompleted(token), finalState, finalFailure)
            }
        }
        if (!mainHandler.postDelayed(drain, 25)) value.cleanupQueued.set(false)
    }

    private fun acquireAuthority(value: Attempt) {
        if (!current(value) || !isUnlocked() || !isPrepared()) { fail(value, RuntimeStartFailure.CONSENT_REVOKED); return }
        var acquisitionFailure = RuntimeStartFailure.AUTHORITY_REJECTED
        try {
            val dependencies = (application as? RuntimeDependencyProvider)?.runtimeProcessGraph
                ?: error("VPN_DEPENDENCIES_UNAVAILABLE")
            val owner = dependencies.acquireAdmitted(this, value.admission,
                onAdmitted = {
                    value.production = it
                    it.onProviderDeathSettled = { dispatch { fail(value, RuntimeStartFailure.AUTHORITY_REJECTED) } }
                }) { production ->
                publish(PublishedSnapshot(state = VpnRuntimeState.CONNECTING, disposition = "CAPTURE_VERIFIED", requestId = value.token.requestId))
                value.platformSettings = production.capturedPlatformSettings()
                publish(PublishedSnapshot(state = VpnRuntimeState.CONNECTING, disposition = "SETTINGS_VERIFIED", requestId = value.token.requestId))
                if (!checkNotNull(value.platformSettings).pausePolicy.permitsAutoConnect) {
                    acquisitionFailure = RuntimeStartFailure.PAUSED
                    error("PERSISTED_PAUSE")
                }
                check(production.admitProductRetryPolicy())
                publish(PublishedSnapshot(state = VpnRuntimeState.CONNECTING, disposition = "NATIVE_OPENING", requestId = value.token.requestId))
                val opened = production.openProductionSession()
                if (opened !is NativeProductResult.Success) {
                    publish(PublishedSnapshot(state = VpnRuntimeState.CONNECTING,
                        disposition = "NATIVE_OPEN_" + (opened as NativeProductResult.Failure).code.name,
                        requestId = value.token.requestId))
                    if (opened.code == ProductFailureCode.NETWORK_UNAVAILABLE) throw RuntimeProductionNetworkUnavailableV1()
                    error("PRODUCTION_OPEN_REJECTED")
                }
                val session = opened.value
                value.session = session
                value.appliedRevision = production.capturedRevision()
                publish(PublishedSnapshot(state = VpnRuntimeState.CONNECTING, disposition = "SESSION_OPEN", requestId = value.token.requestId))
                val buffer = ByteBuffer.allocateDirect(32768)
                try {
                    val deadline = SystemClock.elapsedRealtime() + 30_000
                    while (value.authority == null) {
                        check(current(value) && SystemClock.elapsedRealtime() < deadline)
                        buffer.clear()
                        when (val result = production.nextProductControl(buffer)) {
                            is NativeProductResult.Failure -> {
                                // An empty bounded native poll is not the overall startup deadline.
                                if (result.code == ProductFailureCode.OPERATION_TIMED_OUT) continue
                                publish(PublishedSnapshot(state = VpnRuntimeState.CONNECTING,
                                    disposition = "CONTROL_" + result.code.name, requestId = value.token.requestId))
                                error("PRODUCTION_CONTROL_REJECTED")
                            }
                            is NativeProductResult.Success -> when (val event = result.value) {
                                is NativeControlEvent.SocketProtectionRequired ->
                                    check(session.confirmSocketProtection(event.token, true, null) is NativeProductResult.Success)
                                is NativeControlEvent.RoutePlanReady -> value.authority = event.snapshot
                                is NativeControlEvent.TransportConnecting, is NativeControlEvent.TransportReady -> Unit
                                is NativeControlEvent.Failed -> {
                                    publish(PublishedSnapshot(state = VpnRuntimeState.CONNECTING,
                                        disposition = "NATIVE_" + event.code.name, requestId = value.token.requestId))
                                    if (event.code == ProductFailureCode.NETWORK_UNAVAILABLE) throw RuntimeProductionNetworkUnavailableV1()
                                    error("PRODUCTION_OPEN_TERMINATED")
                                }
                                else -> error("PRODUCTION_OPEN_TERMINATED")
                            }
                        }
                    }
                } finally { for (i in 0 until buffer.capacity()) buffer.put(i, 0) }
                publish(PublishedSnapshot(state = VpnRuntimeState.CONNECTING, disposition = "TRANSPORT_READY", requestId = value.token.requestId))
                if (session.openingSnapshot.effectiveMode != TunnelMode.PROXY_ONLY) {
                    value.pump = production.startProductPackets {
                        value.cancelled.set(true); value.guard.markCancellation()
                        dispatch { fail(value, RuntimeStartFailure.ENDPOINT_UNAVAILABLE) }
                    }
                }
                if (session.openingSnapshot.effectiveMode != TunnelMode.TUN_ONLY) {
                    publish(PublishedSnapshot(state = VpnRuntimeState.CONNECTING, disposition = "PROXY_BINDING", requestId = value.token.requestId))
                    value.proxy = newProxy(value)
                    // One stable ownership slot covers replacements without growing the guard.
                    check(value.guard.own(RuntimeResourceKind.LOCAL_PROXY, Closeable { value.proxy?.close() }) != null)
                }
            }
            publish(PublishedSnapshot(state = VpnRuntimeState.CONNECTING, disposition = "ACTIVATION_COMMIT", requestId = value.token.requestId))
            check(current(value))
            val notification = ActiveNotification(value)
            val health = HealthMonitor(value)
            val activated = owner.activateProduct(notification, health) { snapshot ->
                check(current(value) && isPrepared() && isUnlocked())
                notification.publish()
                latestSnapshot = PublishedSnapshot(state = VpnRuntimeState.CONNECTING,
                    authority = snapshot, requestId = value.token.requestId,
                    startedAtElapsedRealtime = SystemClock.elapsedRealtime())
            }
            handle(activated)
            if (activated is RuntimeStartDecision.Active) {
                acquisitionFailure = RuntimeStartFailure.PROXY_BIND_FAILED
                check(value.guard.acquire { value.proxy?.start { current(value) && value.guard.isActive() } })
                value.health.ready = true
                publish(safeSnapshot().copy(state = value.health.state, failure = value.health.failure))
                acquisitionFailure = RuntimeStartFailure.INTERNAL_FAILURE
                notification.publishOptionalActiveLabel()
                controlBinder.publish()
            }
        } catch (failure: Throwable) {
            if (failure is RuntimeProductionNetworkOutcomeV1) { handle(failure.decision); return }
            // Acquisition can retire its own coordinator entry before throwing. A stale
            // token must not leave the last CONNECTING display behind, or stop a successor.
            if (attempt === value && coordinator.currentToken() == null && !destroyed) {
                val cleanup = value.guard.cleanupState()
                val stopped = latestSnapshot.state == VpnRuntimeState.STOPPING
                attempt = null
                publish(PublishedSnapshot(
                    state = if (stopped && cleanup == RuntimeCleanupState.CLEAN) VpnRuntimeState.IDLE else VpnRuntimeState.BLOCKED,
                    disposition = latestSnapshot.disposition,
                    failure = if (cleanup != RuntimeCleanupState.CLEAN) "CLEANUP_" + cleanup.name
                        else if (stopped) null else acquisitionFailure.name))
                if (cleanup == RuntimeCleanupState.CLEAN) finishService()
            } else {
                // The scoped acquisition may already have moved this token to STOPPING.
                // Drain/publish that outcome instead of losing it through failed()'s stale guard.
                val drained = coordinator.cleanupCompleted(value.token)
                if (drained == RuntimeStartDecision.Stale) fail(value, acquisitionFailure) else handle(drained)
            }
        }
    }

    private inner class ActiveNotification(private val owner: Attempt) : RuntimeActivationResource() {
        private var prepared: Notification? = null
        override fun acquire() {
            check(current(owner))
            prepared = notification(getString(R.string.runtime_notification_connecting))
        }
        fun publish() { promote(checkNotNull(prepared)) }
        fun publishOptionalActiveLabel() {
            owner.guard.publishOptionalActiveStatus {
                if (current(owner)) getSystemService(NotificationManager::class.java)
                    ?.notify(NOTIFICATION_ID, notification(getString(R.string.runtime_notification_connected),
                        safeSnapshot().startedAtElapsedRealtime))
            }
        }
        override fun release() {
            prepared = null
            // Foreground visibility ends only after the coordinator proves complete teardown.
        }
    }
    private inner class HealthMonitor(private val owner: Attempt) : RuntimeActivationResource() {
        private val stopped = AtomicBoolean(false)
        private val rate = RuntimeTrafficRate()
        private val networkMonitor = UnderlyingNetworkMonitor(getSystemService(android.net.ConnectivityManager::class.java)) { state ->
            // Default VPN appearance is not physical loss. The socket owner observes actual loss.
            if (state.handle != 0L && !state.vpn && state.permits(checkNotNull(owner.platformSettings).meteredPolicy)) {
                dispatch {
                    if (current(owner) && owner.guard.isActive() &&
                        owner.production?.boundNetworkHandle()?.let { it != 0L && it != state.handle } == true)
                        fail(owner, RuntimeStartFailure.NETWORK_CHANGED)
                }
            }
        }
        private val worker = Thread({
            val buffer = ByteBuffer.allocateDirect(32768)
            try {
                while (!stopped.get() && current(owner)) {
                    buffer.clear()
                    when (val result = checkNotNull(owner.production).nextProductControl(buffer)) {
                        is NativeProductResult.Failure -> {
                            if (result.code == ProductFailureCode.OPERATION_TIMED_OUT) continue
                            if (!stopped.get()) dispatch { fail(owner, RuntimeStartFailure.ENDPOINT_UNAVAILABLE) }
                            return@Thread
                        }
                        is NativeProductResult.Success -> when (result.value) {
                            is NativeControlEvent.MetricsUpdated -> Unit
                            is NativeControlEvent.Degraded -> dispatch {
                                if (current(owner)) {
                                    owner.health.nativeDegraded = true
                                    publish(safeSnapshot().copy(state = owner.health.state, failure = owner.health.failure))
                                }
                            }
                            is NativeControlEvent.Revoked -> {
                                dispatch { if (current(owner)) requestStop(RuntimeStopReason.REVOKE, VpnRuntimeState.REVOKED) }
                                return@Thread
                            }
                            else -> {
                                if (!stopped.get()) dispatch { fail(owner, RuntimeStartFailure.ENDPOINT_UNAVAILABLE) }
                                return@Thread
                            }
                        }
                    }
                }
            } catch (_: Throwable) {
                if (!stopped.get()) dispatch { fail(owner, RuntimeStartFailure.AUTHORITY_REJECTED) }
            } finally { for (i in 0 until buffer.capacity()) buffer.put(i, 0) }
        }, "kurd-runtime-control")
        private val sample = object : Runnable {
            override fun run() {
                if (stopped.get() || !current(owner)) return
                owner.guard.publishOptionalActiveStatus {
                    controlBinder.publish()
                    val started = safeSnapshot().startedAtElapsedRealtime
                    if (started > 0) coordinator.recordStableSession(owner.token, SystemClock.elapsedRealtime() - started)
                    val counts = owner.pump?.snapshot()
                    val speed = rate.sample(SystemClock.elapsedRealtime(), counts?.outboundBytes ?: 0, counts?.inboundBytes ?: 0)
                    if (speed != null && owner.platformSettings?.showSpeed == true) {
                        val text = getString(R.string.runtime_notification_speed, speed.first, speed.second)
                        getSystemService(NotificationManager::class.java)?.notify(NOTIFICATION_ID,
                            notification(text, safeSnapshot().startedAtElapsedRealtime))
                    }
                }
                if (!mainHandler.postDelayed(this, RUNTIME_HEALTH_INTERVAL_MILLIS))
                    dispatch { fail(owner, RuntimeStartFailure.INTERNAL_FAILURE) }
            }
        }
        override fun acquire() {
            check(current(owner))
            networkMonitor.start()
            worker.start()
            check(mainHandler.postDelayed(sample, RUNTIME_HEALTH_INTERVAL_MILLIS))
            checkNotNull(startService(Intent(this@KurdVpnService, RuntimeRestartService::class.java)))
        }
        override fun release() {
            stopped.set(true)
            mainHandler.removeCallbacks(sample)
            try { stopService(Intent(this@KurdVpnService, RuntimeRestartService::class.java)) } finally {
                try { networkMonitor.close() } finally {
                    val cancelled = owner.session?.cancel() is NativeProductResult.Success
                    try { owner.proxy?.close() } finally {
                        worker.join(5_000)
                        check(!worker.isAlive && cancelled) { "CONTROL_WORKER_CLEANUP_UNPROVEN" }
                    }
                }
            }
        }
    }

    private fun newProxy(value: Attempt): LocalProxySupervisor {
        val session = checkNotNull(value.session)
        lateinit var proxy: LocalProxySupervisor
        proxy = LocalProxySupervisor(checkNotNull(value.platformSettings).proxy,
            checkNotNull(session.openingSnapshot.proxyLimits), session::openProxyStream) {
            dispatch {
                if (current(value) && value.proxy === proxy) {
                    proxy.close(); value.proxy = null
                    if (value.authority?.effectiveMode == TunnelMode.TUN_PLUS_PROXY && value.guard.isActive()) {
                        value.health.proxyFailed = true
                        publish(safeSnapshot().copy(state = value.health.state, failure = value.health.failure))
                    }
                    else fail(value, RuntimeStartFailure.INTERNAL_FAILURE)
                }
            }
        }
        return proxy
    }

    private fun restartProxy(value: Attempt) {
        if (!current(value) || !value.guard.isActive()) return
        check(value.guard.acquire {
            value.proxy?.close(); value.proxy = null
            if (current(value) && value.guard.isActive()) {
                val replacement = newProxy(value)
                value.proxy = replacement
                try {
                    replacement.start { current(value) && value.guard.isActive() }
                    value.health.proxyFailed = false
                    publish(safeSnapshot().copy(state = value.health.state, failure = value.health.failure))
                } catch (_: Exception) {
                    replacement.close(); value.proxy = null
                    if (current(value) && value.guard.isActive()) {
                        value.health.proxyFailed = true
                        publish(safeSnapshot().copy(state = value.health.state, failure = value.health.failure))
                    }
                }
            }
        })
    }

    private fun settingsTransition(operation: Int, token: String?, observer: IBinder): String? {
        if (destroyed) return null
        return when (operation) {
            RuntimeControlBinder.SETTINGS_PREPARE -> {
                if (attempt?.guard?.isActive() != true) return null
                val lease = settingsContinuation.prepare(observer) ?: return null
                if (!mainHandler.post {
                    synchronized(settingsContinuation) {
                        if (settingsContinuation.matches(observer, lease)) {
                            settingsExpiry?.let(mainHandler::removeCallbacks)
                            val expiry = Runnable {
                                // matches expires only the old lease, never invalidates a newer one.
                                settingsContinuation.matches(observer, lease)
                                dispatch { if (attempt == null) finishService() }
                            }
                            settingsExpiry = expiry
                            if (!mainHandler.postDelayed(expiry, 120_000)) settingsContinuation.invalidate(observer)
                            requestStop(RuntimeStopReason.STOP, VpnRuntimeState.IDLE, managedSettings = true)
                        }
                    }
                }) { settingsContinuation.invalidate(observer); null } else lease
            }
            RuntimeControlBinder.SETTINGS_RESUME -> {
                val lease = token ?: return null
                if (attempt != null || safeSnapshot().state != VpnRuntimeState.IDLE) return null
                val request = settingsContinuation.resume(observer, lease) ?: return null
                if (!mainHandler.post {
                    if (settingsContinuation.ownsRequest(observer, lease, request)) {
                        try {
                            promote(notification(getString(R.string.runtime_notification_connecting)))
                            dispatch {
                                if (settingsContinuation.ownsRequest(observer, lease, request))
                                    handle(coordinator.begin(RuntimeAuthorityTrigger.MANUAL, isUnlocked(), isPrepared(), request))
                            }
                        } catch (failure: Exception) {
                            settingsContinuation.invalidate(observer)
                            requestStop(RuntimeStopReason.CANCEL, VpnRuntimeState.BLOCKED,
                                finalFailure = runtimeStartFailure(this, failure))
                        }
                    }
                }) null else request
            }
            RuntimeControlBinder.SETTINGS_STOP -> {
                val lease = token ?: return null
                if (!settingsContinuation.matches(observer, lease) ||
                    (attempt != null && !settingsContinuation.ownsRequest(observer, lease, attempt?.token?.requestId))) return null
                if (!mainHandler.post {
                    if (settingsContinuation.matches(observer, lease) &&
                        (attempt == null || settingsContinuation.ownsRequest(observer, lease, attempt?.token?.requestId)))
                        requestStop(RuntimeStopReason.STOP, VpnRuntimeState.IDLE, managedSettings = true)
                }) null else lease
            }
            RuntimeControlBinder.SETTINGS_FINISH -> {
                if (token == null || !settingsContinuation.matches(observer, token)) null
                else {
                    settingsContinuation.invalidate(observer)
                    dispatch { if (attempt == null) finishService() }
                    token
                }
            }
            else -> null
        }
    }

    private fun requestStop(reason: RuntimeStopReason, finalState: VpnRuntimeState,
        promoteStopNotification: Boolean = false, managedSettings: Boolean = false, finalFailure: String? = null) {
        if (!managedSettings) settingsContinuation.invalidate()
        maintenance.markCancelled()
        attempt?.let { it.cancelled.set(true); it.guard.markCancellation() }
        publish(PublishedSnapshot(state = VpnRuntimeState.STOPPING))
        if (promoteStopNotification) {
            try { promote(notification(getString(R.string.runtime_notification_stopping))) } catch (_: Throwable) {
                // Cancellation and STOPPING publication precede fallible foreground work.
            }
        }
        // A retained quiescence binding can outlive stopSelf. Finish any promotion
        // before dispatching cleanup so it cannot re-elevate the stopped service.
        dispatch { handle(coordinator.stop(reason), finalState, finalFailure) }
    }
    private fun fail(value: Attempt, failure: RuntimeStartFailure) {
        if (coordinator.currentToken() != value.token) return
        val outcome = providerDeathFailureV1(failure, value.production?.providerDeathInProgress() == true,
            value.production?.providerDeathCanRetry() == true) ?: return
        value.cancelled.set(true)
        value.guard.markCancellation()
        handle(coordinator.failed(value.token, outcome))
    }
    private fun current(value: Attempt): Boolean = !destroyed && attempt === value && !value.cancelled.get() && coordinator.currentToken() == value.token
    private fun isUnlocked(): Boolean = getSystemService(UserManager::class.java)?.isUserUnlocked == true
    private fun isPrepared(): Boolean = try { prepare(this) == null } catch (_: Throwable) { false }
    private fun safeSnapshot(): PublishedSnapshot = synchronized(coordinator) {
        val value = latestSnapshot
        if (value.state == VpnRuntimeState.ACTIVE_KURD_LIVE && attempt?.guard?.isActive() != true)
            value.copy(state = VpnRuntimeState.BLOCKED, failure = "ACTIVE_INVALIDATED", startedAtElapsedRealtime = 0)
        else value
    }
    private fun publish(snapshot: PublishedSnapshot) {
        synchronized(coordinator) { latestSnapshot = snapshot }
        try { controlBinder.publish() } catch (_: Throwable) { /* Best-effort display only. */ }
    }
    private fun promote(notification: Notification) {
        if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(NOTIFICATION_ID, notification)
    }
    private fun finishService() = synchronized(settingsContinuation) {
        stopService(Intent(this, RuntimeRestartService::class.java))
        // A controlled reconnect retains the existing started/foreground lifetime.
        // A notification alone cannot restart that lifetime after stopSelf().
        if (!settingsContinuation.hasPending()) {
            settingsExpiry?.let(mainHandler::removeCallbacks); settingsExpiry = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }
    private fun dispatch(operation: () -> Unit) {
        try { executor.execute {
            try { operation() } catch (_: Throwable) {
                attempt?.let { it.cancelled.set(true); it.guard.markCancellation(); handle(coordinator.failed(it.token, RuntimeStartFailure.INTERNAL_FAILURE)) }
            }
        } } catch (_: Throwable) {
            // Rejected execution cannot strand an already established TUN. The
            // acquisition guard owns partial children and is safe to cancel even
            // while the executor is full or shutting down. It never reports CLEAN
            // until every acquisition/close is accounted for.
            attempt?.let {
                it.cancelled.set(true)
                it.guard.markCancellation()
                val cleanup = it.guard.cancel()
                publish(PublishedSnapshot(state = VpnRuntimeState.BLOCKED,
                    failure = if (cleanup == RuntimeCleanupState.CLEAN) "DISPATCH_REJECTED" else "CLEANUP_" + cleanup.name))
            }
        }
    }

    private fun controlSnapshot(): VpnRuntimeSnapshot {
        val snapshot = safeSnapshot()
        val native = snapshot.authority
        val counts = attempt?.takeIf { it.token.requestId == snapshot.requestId }?.pump?.snapshot()
        val presentation = attempt?.takeIf { native != null && it.token.requestId == snapshot.requestId }?.let { owner ->
            try {
                owner.production?.presentationEvidence()?.let { evidence ->
                    evidence.copy(proxySessionId = evidence.sessionId.takeIf {
                        current(owner) && owner.guard.isActive() && owner.proxy?.isListening() == true
                    })
                }
            } catch (_: Exception) { null }
        }
        return VpnRuntimeSnapshot(
            state = snapshot.state, packetsRead = counts?.outboundPackets ?: 0, packetsWritten = counts?.inboundPackets ?: 0,
            bytesSent = counts?.outboundBytes ?: 0, bytesReceived = counts?.inboundBytes ?: 0,
            alwaysOn = isAlwaysOnCompat(), lockdown = isLockdownCompat(), failure = snapshot.failure,
            packetDisposition = snapshot.disposition,
            perAppRoutingMode = when (native?.perAppMode) {
                PerAppSelectionMode.INCLUDE_ONLY -> PerAppRoutingMode.INCLUDE_ONLY
                PerAppSelectionMode.EXCLUDE_SELECTED -> PerAppRoutingMode.EXCLUDE_SELECTED
                else -> PerAppRoutingMode.ALL_APPS
            },
            startedAtElapsedRealtime = snapshot.startedAtElapsedRealtime,
            dnsMode = native?.effectiveDnsMode ?: ResolverPolicy.INTERNAL,
            ipMode = native?.effectiveIp ?: IpMode.AUTO, mtu = native?.effectiveMtu ?: 1280,
            profileGeneration = native?.profileGeneration ?: 0uL,
            planDigest = native?.planDigest?.toHex(),
            profileFingerprint = native?.profileFingerprint?.toHex(),
            strategyFingerprint = native?.strategyFingerprint?.toHex(),
            relayFingerprint = native?.relayFingerprint?.toHex(),
            maxReconnectAttempts = native?.reconnectLimits?.effectiveAutomaticReconnectMax ?: 0,
            runtimeRequestId = snapshot.requestId,
            appliedRevision = if (native == null) 0 else attempt?.appliedRevision ?: 0,
            routeCount = native?.routes?.size ?: 0,
            perAppCount = native?.effectivePackageCount ?: 0,
            lanBypass = false, // Current native admission rejects bypass rather than approximating it.
            metering = when {
                native == null -> VpnMeteringState.UNAVAILABLE
                Build.VERSION.SDK_INT < 29 -> VpnMeteringState.OS_CONTROLLED
                native.metered -> VpnMeteringState.METERED
                else -> VpnMeteringState.UNMETERED
            },
            diagnostics = VpnRuntimeDiagnostics(tunPacketsRead = counts?.outboundPackets ?: 0,
                outboundPacketsAccepted = counts?.outboundPackets ?: 0, tunPacketsWritten = counts?.inboundPackets ?: 0),
            presentation = presentation,
        ).validatedForDisplay()
    }

    private fun isAlwaysOnCompat(): Boolean? =
        if (Build.VERSION.SDK_INT >= 29) try { isAlwaysOn } catch (_: SecurityException) { null } else null

    private fun isLockdownCompat(): Boolean? =
        if (Build.VERSION.SDK_INT >= 29) try { isLockdownEnabled } catch (_: SecurityException) { null } else null

    private fun notification(text: String, startedAt: Long = 0): Notification {
        val launch = packageManager.getLaunchIntentForPackage(packageName)
        val pending = PendingIntent.getActivity(
            this,
            0,
            launch,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("Kurdistan VPN")
            .setContentText(text)
            .setContentIntent(pending)
            .setOngoing(true)
            .apply {
                if (startedAt > 0) {
                    setWhen(System.currentTimeMillis() - (SystemClock.elapsedRealtime() - startedAt).coerceAtLeast(0))
                    setUsesChronometer(true)
                }
            }
            .build()
    }

    private fun createNotificationChannel() {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                getString(R.string.runtime_notification_channel),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = getString(R.string.runtime_notification_channel)
                setShowBadge(false)
            },
        )
    }

    companion object {
        private const val CHANNEL_ID = "kurdistan-vpn-runtime"
        private const val NOTIFICATION_ID = 1001
        private const val RUNTIME_HEALTH_INTERVAL_MILLIS = 250L

        fun start(context: Context, requestId: String) {
            require(RuntimeAuthorityLimits.validId(requestId))
            context.startForegroundService(Intent(context, KurdVpnService::class.java)
                .setAction(RuntimeServiceCommand.ACTION_START)
                .putExtra(RuntimeServiceCommand.MARKER_KEY, RuntimeServiceCommand.MARKER_VERSION)
                .putExtra(RuntimeServiceCommand.REQUEST_KEY, requestId))
        }
        fun newRequestId(): String = UUID.randomUUID().toString().replace("-", "")
        fun stop(context: Context) {
            context.startService(Intent(context, KurdVpnService::class.java)
                .setAction(RuntimeServiceCommand.ACTION_STOP)
                .putExtra(RuntimeServiceCommand.MARKER_KEY, RuntimeServiceCommand.MARKER_VERSION))
        }
        fun recoverInternet(context: Context) {
            context.startService(Intent(context, KurdVpnService::class.java)
                .setAction(RuntimeServiceCommand.ACTION_RECOVER)
                .putExtra(RuntimeServiceCommand.MARKER_KEY, RuntimeServiceCommand.MARKER_VERSION))
        }
    }
    private data class PublishedSnapshot(
        val state: VpnRuntimeState = VpnRuntimeState.IDLE,
        val failure: String? = null,
        val disposition: String? = null,
        val startedAtElapsedRealtime: Long = 0,
        val authority: NativeOpeningSnapshot? = null,
        val requestId: String? = null,
    )



    private fun ByteArray.toHex(): String = joinToString(separator = "") { value ->
        "%02x".format(value.toInt() and 0xff)
    }
}

/** Independent health on the existing attempt; proxy repair cannot certify native recovery. */
internal class RuntimeSessionHealth {
    var ready = false
    var nativeDegraded = false
    var proxyFailed = false
    val state: VpnRuntimeState get() = when {
        !ready -> VpnRuntimeState.CONNECTING
        nativeDegraded || proxyFailed -> VpnRuntimeState.DEGRADED
        else -> VpnRuntimeState.ACTIVE_KURD_LIVE
    }
    val failure: String? get() = if (proxyFailed) "PROXY_LISTENER_FAILED" else null
}
