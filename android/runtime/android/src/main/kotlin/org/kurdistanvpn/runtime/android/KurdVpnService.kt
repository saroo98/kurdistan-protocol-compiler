// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Binder
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.os.UserManager
import java.io.Closeable
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.nativeapi.NativeLiveRuntimeSession
import org.kurdistanvpn.core.nativeapi.NativeLiveRuntimeSessionSnapshot
import org.kurdistanvpn.core.nativeapi.NativeLiveRuntimeDiagnostics
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.runtime.api.*

/** One VPN-process coordinator, one TUN owner. A lifecycle Intent never conveys authority. */
class KurdVpnService : VpnService() {
    private val coordinator = RuntimeStartCoordinator.installOnce(PROCESS_EPOCH)
    private val executor = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(32),
        { task -> Thread(task, "kurd-vpn-tun").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
    private val mainHandler = Handler(Looper.getMainLooper())
    private val nativeCore by lazy { NativeBridge() }
    @Volatile private var attempt: Attempt? = null
    @Volatile private var destroyed = false
    @Volatile private var latestSnapshot = PublishedSnapshot()
    private var queryRegistered = false
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
    private val statusQueryReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != VpnRuntimeContract.ACTION_QUERY_STATUS) return
            val query = try { intent.getStringExtra(VpnRuntimeContract.EXTRA_STATUS_QUERY) } catch (_: Throwable) { null }
            if (query != null && RuntimeAuthorityLimits.validId(query)) publishTransient(safeSnapshot(), query)
        }
    }

    private inner class Attempt(val token: RuntimeStartToken, val guard: RuntimeActivationGuard) {
        val cancelled = AtomicBoolean(false)
        val network = UnderlyingNetworkAvailability<Network>()
        var client: RuntimeAuthorityReissueClient? = null
        var controller: NativeTunnelController? = null
        var leases: RuntimeRevisionLeaseClient? = null
        var config = VpnRuntimeConfig(VpnRoutingPolicy())
        var authority: NativeLiveRuntimeSessionSnapshot? = null
        var selectedNetwork: Network? = null
        var lastStage: LiveTunnelStage? = null
        var readyNotification: ActiveNotification? = null
        var readyHealth: HealthMonitor? = null
        val cleanupQueued = AtomicBoolean(false)
        var cleanupDeadline = 0L
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        val filter = IntentFilter(VpnRuntimeContract.ACTION_QUERY_STATUS)
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(statusQueryReceiver, filter, RECEIVER_NOT_EXPORTED)
        else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(statusQueryReceiver, filter)
        }
        queryRegistered = true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val command = sanitizedCommand(intent)
        when (command) {
            is RuntimeServiceCommand.Rejected -> {
                // An invalid start cannot tear down or replace a separately admitted session.
                if (attempt == null) {
                    try { promote(notification("Connection blocked: invalid start request")) }
                    finally {
                        publish(PublishedSnapshot(state = VpnRuntimeState.BLOCKED, failure = command.reason))
                        finishService()
                    }
                }
            }
            RuntimeServiceCommand.Stop -> {
                requestStop(RuntimeStopReason.STOP, VpnRuntimeState.IDLE)
                try { promote(notification("Stopping Kurdistan VPN safely")) } catch (_: Throwable) {
                    // Stop precedence is already published before fallible foreground work.
                }
            }
            is RuntimeServiceCommand.Manual, RuntimeServiceCommand.AutomaticTrigger -> {
                if (attempt?.guard?.isActive() != true) {
                    try { promote(notification("Connecting: verifying protected state")) }
                    catch (_: Throwable) {
                        requestStop(RuntimeStopReason.CANCEL, VpnRuntimeState.BLOCKED)
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
        releaseAllMutationQuiescences()
        attempt?.let { it.cancelled.set(true); it.guard.markCancellation() }
        if (queryRegistered) {
            queryRegistered = false
            try { unregisterReceiver(statusQueryReceiver) } catch (_: Throwable) {
                attempt?.guard?.own(RuntimeResourceKind.HEALTH_MONITOR, Closeable { error("QUERY_CLEANUP_UNPROVEN") })
            }
        }
        dispatch { handle(coordinator.stop(RuntimeStopReason.CANCEL), VpnRuntimeState.IDLE) }
        executor.shutdown()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? {
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

    private fun handle(decision: RuntimeStartDecision, finalState: VpnRuntimeState = VpnRuntimeState.FAILED) {
        when (decision) {
            is RuntimeStartDecision.RequestAuthority -> {
                val next = Attempt(decision.token, decision.guard)
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
            is RuntimeStartDecision.Ready -> attempt?.takeIf { it.token == decision.token }?.let { beginNative(it, decision) }
                ?: decision.authority.close()
            is RuntimeStartDecision.Active, is RuntimeStartDecision.Coalesced, RuntimeStartDecision.Stale -> Unit
            is RuntimeStartDecision.CleanupPending -> {
                publish(PublishedSnapshot(state = VpnRuntimeState.BLOCKED, failure = "CLEANUP_" + decision.state.name,
                    requestId = decision.token.requestId))
                // No retry/replacement or success can cross incomplete cleanup.
                if (decision.state == RuntimeCleanupState.CLEANUP_REQUIRED) scheduleCleanupDrain(decision.token, finalState)
            }
            is RuntimeStartDecision.Rejected -> {
                attempt = null
                publish(PublishedSnapshot(state = VpnRuntimeState.BLOCKED, failure = decision.failure.name))
                finishService()
            }
            RuntimeStartDecision.Idle -> {
                attempt = null
                publish(PublishedSnapshot(state = finalState))
                finishService()
            }
        }
    }

    private fun scheduleCleanupDrain(token: RuntimeStartToken, finalState: VpnRuntimeState) {
        val value = attempt?.takeIf { it.token == token } ?: return
        val now = SystemClock.elapsedRealtime()
        if (value.cleanupDeadline == 0L) value.cleanupDeadline = now + 5_000
        if (destroyed || now >= value.cleanupDeadline || !value.cleanupQueued.compareAndSet(false, true)) return
        val drain = Runnable {
            value.cleanupQueued.set(false)
            dispatch {
                if (coordinator.currentToken() == token)
                    handle(coordinator.cleanupCompleted(token), finalState)
            }
        }
        if (!mainHandler.postDelayed(drain, 25)) value.cleanupQueued.set(false)
    }

    private fun acquireAuthority(value: Attempt) {
        if (!current(value) || !isUnlocked() || !isPrepared()) { fail(value, RuntimeStartFailure.CONSENT_REVOKED); return }
        try {
            val monitor = UnderlyingNetworkMonitor(getSystemService(ConnectivityManager::class.java)) { transition ->
                value.network.update(transition.current, transition.current != null)
                if (value.selectedNetwork != null && value.selectedNetwork != transition.current) {
                    value.cancelled.set(true); value.guard.markCancellation()
                    dispatch { fail(value, if (transition.current == null) RuntimeStartFailure.NETWORK_LOST else RuntimeStartFailure.NETWORK_CHANGED) }
                }
            }
            check(value.guard.own(RuntimeResourceKind.SOCKET, Closeable {
                monitor.close()
                setUnderlyingNetworks(null)
                ActiveVpnUnderlyingNetwork.publish(null)
            }) != null)
            check(value.guard.acquire { monitor.start() })
            // Client owns partial pipes/binding before any authority acquisition.
            val client = RuntimeAuthorityReissueClient(this,
                ComponentName(this, "org.kurdistanvpn.app.RuntimeAuthorityReissueService"),
                PROCESS_EPOCH, nativeCore.durableFiles(), value.guard) {
                value.cancelled.set(true)
                dispatch { fail(value, RuntimeStartFailure.AUTHORITY_REJECTED) }
            }
            value.client = client
            check(value.guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, client) != null)
            check(client.bind { bound ->
                if (!bound) { dispatch { fail(value, RuntimeStartFailure.AUTHORITY_REJECTED) }; return@bind }
                val now = SystemClock.elapsedRealtime()
                val request = RuntimeReissueStart(PROCESS_EPOCH, value.token.requestId, value.token.generation,
                    value.token.trigger, value.token.retryAttempt, now + RuntimeAuthorityLimits.MAX_LIFETIME_MILLIS)
                if (!current(value) || !client.request(request) { result ->
                    dispatch {
                        when (result) {
                            is RuntimeFrameVerification.Verified -> handle(coordinator.acceptAuthority(value.token, result.authority, SystemClock.elapsedRealtime()))
                            is RuntimeFrameVerification.Rejected -> fail(value, RuntimeStartFailure.AUTHORITY_REJECTED)
                        }
                    }
                }) dispatch { fail(value, RuntimeStartFailure.AUTHORITY_REJECTED) }
            })
        } catch (_: Throwable) { fail(value, RuntimeStartFailure.INTERNAL_FAILURE) }
    }

    /** Allocated and registered before native open; transfer is one-way into the TUN owner. */
    private class NativeAcquisition : Closeable {
        private var session: NativeLiveRuntimeSession? = null
        private var terminal = false
        private var clean = true
        @Synchronized fun open(native: NativeBridge, bytes: ByteArray): NativeLiveRuntimeSession {
            check(!terminal && session == null)
            val result = try { native.openLiveRuntimeSession(bytes) } catch (error: Throwable) {
                clean = false
                throw error
            }
            check(result is NativeResult.Success)
            session = result.value
            return result.value
        }
        @Synchronized fun transfer(controller: NativeTunnelController): LiveTunnelStartResult {
            check(!terminal)
            val owned = checkNotNull(session)
            session = null
            // NativeTunnelController assumes ownership on entry, including rejected starts.
            return controller.start(owned)
        }
        @Synchronized override fun close() {
            if (!terminal) {
                terminal = true
                val owned = session
                session = null
                if (owned != null) {
                    val stopped = try { owned.stop() is NativeResult.Success } catch (_: Throwable) { false }
                    val closed = try { owned.close(); true } catch (_: Throwable) { false }
                    clean = stopped && closed
                }
            }
            check(clean) { "NATIVE_CLEANUP_UNPROVEN" }
        }
    }

    private fun beginNative(value: Attempt, ready: RuntimeStartDecision.Ready) {
        value.leases = ready.leases
        val nativeOwner = NativeAcquisition()
        var failure = RuntimeStartFailure.INTERNAL_FAILURE
        val acquired = value.guard.acquire { scope ->
            check(scope.own(RuntimeResourceKind.NATIVE_SESSION, nativeOwner) != null)
            val bytes = checkNotNull(ready.authority.takePayload())
            val session = try { nativeOwner.open(nativeCore, bytes) } finally { bytes.fill(0); ready.authority.close() }
            val snapshot = session.snapshot
            value.authority = snapshot
            check(scope.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, Closeable { wipe(snapshot) }) != null)
            value.config = configFrom(snapshot)
            val selected = value.network.awaitUsable(NETWORK_BIND_TIMEOUT_MILLIS)
            if (selected == null) { failure = RuntimeStartFailure.NETWORK_UNAVAILABLE; error("NO_UNDERLYING_NETWORK") }
            value.selectedNetwork = selected
            check(current(value) && isPrepared() && isUnlocked())
            val notification = ActiveNotification(value)
            val health = HealthMonitor(value)
            val controller = NativeTunnelController(
                protector = SocketProtector(::protect),
                networkBinder = SocketNetworkBinder { descriptor ->
                    val duplicate = ParcelFileDescriptor.fromFd(descriptor)
                    try { selected.bindSocket(duplicate.fileDescriptor); true } finally { duplicate.close() }
                },
                tunEstablisher = TunEstablisher { configuration -> establishTun(configuration, selected) },
                detachedCloser = DetachedFileDescriptorCloser { descriptor -> ParcelFileDescriptor.adoptFd(descriptor).close() },
                onStage = { stage ->
                    value.lastStage = stage
                    if (stage != LiveTunnelStage.STOPPED) publish(PublishedSnapshot(state = VpnRuntimeState.CONNECTING,
                        disposition = "LIVE_STAGE_" + stage.name, requestId = value.token.requestId, config = value.config))
                },
                preTunValidation = {
                    ready.leases.beginFinalLease(SystemClock.elapsedRealtime()) &&
                        leaseCheck(value, RuntimeAuthorityPurpose.PRE_TUN) && ready.leases.authorizeTun(checks(value))
                },
                prepareRequiredActivationResources = { it.notification(notification); it.healthMonitor(health) },
                finalPublicationCheck = { leaseCheck(value, RuntimeAuthorityPurpose.PRE_ACTIVE) && current(value) },
                activationOwner = value.guard,
            )
            value.controller = controller
            check(scope.own(RuntimeResourceKind.TUN, Closeable {
                check(controller.stopResult() == LiveTunnelCleanupState.CLEAN) { "TUN_CLEANUP_UNPROVEN" }
            }) != null)
            when (val result = nativeOwner.transfer(controller)) {
                is LiveTunnelStartResult.Failure -> {
                    failure = if (result.cleanup == LiveTunnelCleanupState.UNPROVEN) RuntimeStartFailure.CLEANUP_UNPROVEN else runtimeFailure(result.category)
                    error("TUN_ACTIVATION_FAILED")
                }
                is LiveTunnelStartResult.Running -> Unit
            }
            value.readyNotification = notification
            value.readyHealth = health
        }
        if (!acquired) { fail(value, failure); return }
        // Required IPC acknowledgement is before publication and while both peers hold
        // the same final revision lease. No fallible required work follows the barrier.
        if (!awaitBoolean(value) { callback -> checkNotNull(value.client).prepareActivationCommit(callback) }) {
            fail(value, RuntimeStartFailure.AUTHORITY_REJECTED); return
        }
        val published = value.guard.activate(ready.leases, { checks(value) },
            checkNotNull(value.readyNotification), checkNotNull(value.readyHealth)) {
            check(current(value) && value.controller?.isRunning() == true)
            val snapshot = PublishedSnapshot(state = VpnRuntimeState.ACTIVE_KURD_LIVE,
                config = value.config, authority = value.authority, requestId = value.token.requestId,
                startedAtElapsedRealtime = SystemClock.elapsedRealtime())
            checkNotNull(value.readyNotification).publish()
            check(current(value) && isPrepared() && isUnlocked())
            latestSnapshot = snapshot // No-throw local publication; reader also checks guard ACTIVE.
        }
        if (!published) { fail(value, RuntimeStartFailure.AUTHORITY_REJECTED); return }
        handle(coordinator.activationCompleted(value.token))
        value.readyNotification?.publishOptionalActiveLabel()
        try { publishTransient(safeSnapshot()) } catch (_: Throwable) { /* Optional status delivery cannot authorize ACTIVE. */ }
        // Cleanup of the final lease is separate from the completed activation claim.
        // Failure is a new terminal invalidation, never a retrospective success receipt.
        if (value.client?.releaseActivationLease { released ->
            if (!released) dispatch { fail(value, RuntimeStartFailure.AUTHORITY_REJECTED) }
        } != true) fail(value, RuntimeStartFailure.AUTHORITY_REJECTED)
    }

    private fun leaseCheck(value: Attempt, purpose: RuntimeAuthorityPurpose): Boolean {
        val client = value.client ?: return false
        return awaitBoolean(value) { complete ->
            client.checkLease(purpose) { result ->
                val accepted = when (result) {
                    is RuntimeFrameVerification.Verified -> if (current(value)) value.leases?.accept(result.authority, checks(value)) == true
                        else { result.authority.close(); false }
                    is RuntimeFrameVerification.Rejected -> false
                }
                complete(accepted)
            }
        }
    }
    private fun awaitBoolean(value: Attempt, invoke: ((Boolean) -> Unit) -> Boolean): Boolean {
        val latch = CountDownLatch(1)
        val accepted = AtomicBoolean(false)
        val finished = AtomicBoolean(false)
        if (!invoke { result -> if (finished.compareAndSet(false, true)) { accepted.set(result); latch.countDown() } }) return false
        val received = latch.await(2_000, TimeUnit.MILLISECONDS)
        if (!received) { finished.set(true); value.cancelled.set(true); value.guard.markCancellation() }
        return received && accepted.get() && current(value)
    }
    private fun checks(value: Attempt): RuntimeActivationChecks {
        val lease = checkNotNull(value.leases)
        return RuntimeActivationChecks(PROCESS_EPOCH, value.client?.observedProviderEpoch().orEmpty(),
            coordinator.currentToken()?.generation ?: 0, lease.request.revision,
            isUnlocked(), isPrepared(), !current(value), SystemClock.elapsedRealtime())
    }

    private inner class ActiveNotification(private val owner: Attempt) : RuntimeActivationResource() {
        private var prepared: Notification? = null
        private var activeLabel: Notification? = null
        override fun acquire() {
            check(current(owner))
            prepared = notification("Connecting: completing protected tunnel verification")
            activeLabel = notification("Verified Kurd relay session active")
        }
        fun publish() { promote(checkNotNull(prepared)) }
        fun publishOptionalActiveLabel() {
            owner.guard.publishOptionalActiveStatus {
                if (current(owner)) getSystemService(NotificationManager::class.java)
                    ?.notify(NOTIFICATION_ID, checkNotNull(activeLabel))
            }
        }
        override fun release() {
            prepared = null
            activeLabel = null
            if (attempt === owner) stopForeground(STOP_FOREGROUND_REMOVE)
        }
    }
    private inner class HealthMonitor(private val owner: Attempt) : RuntimeActivationResource() {
        private val stopped = AtomicBoolean(false)
        private val queued = AtomicBoolean(false)
        private val check = object : Runnable {
            override fun run() {
                if (stopped.get() || !current(owner)) return
                if (queued.compareAndSet(false, true)) dispatch {
                    try {
                        if (current(owner)) {
                            val error = owner.controller?.checkHealth()
                            if (error != null) fail(owner, runtimeFailure(error))
                            else if (owner.guard.isActive()) {
                                val diagnostics = owner.controller?.diagnostics()
                                if (diagnostics is NativeResult.Success) {
                                    val current = safeSnapshot()
                                    if (current.state == VpnRuntimeState.ACTIVE_KURD_LIVE)
                                        publish(current.copy(diagnostics = diagnostics.value.toRuntimeDiagnostics()))
                                }
                            }
                        }
                    } finally { queued.set(false) }
                }
                if (!stopped.get() && current(owner) && !mainHandler.postDelayed(this, RUNTIME_HEALTH_INTERVAL_MILLIS)) {
                    owner.cancelled.set(true); owner.guard.markCancellation()
                    dispatch { fail(owner, RuntimeStartFailure.INTERNAL_FAILURE) }
                }
            }
        }
        override fun acquire() {
            check(current(owner) && mainHandler.postDelayed(check, RUNTIME_HEALTH_INTERVAL_MILLIS))
        }
        override fun release() { stopped.set(true); mainHandler.removeCallbacks(check) }
    }

    private fun requestStop(reason: RuntimeStopReason, finalState: VpnRuntimeState) {
        attempt?.let { it.cancelled.set(true); it.guard.markCancellation() }
        publish(PublishedSnapshot(state = VpnRuntimeState.STOPPING))
        dispatch { handle(coordinator.stop(reason), finalState) }
    }
    private fun fail(value: Attempt, failure: RuntimeStartFailure) {
        if (coordinator.currentToken() != value.token) return
        value.cancelled.set(true)
        value.guard.markCancellation()
        handle(coordinator.failed(value.token, failure))
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
        try { publishTransient(safeSnapshot()) } catch (_: Throwable) { /* Best-effort display only. */ }
    }
    private fun promote(notification: Notification) {
        if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(NOTIFICATION_ID, notification)
    }
    private fun finishService() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
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

    private fun publishTransient(
        snapshot: PublishedSnapshot,
        statusQueryId: String? = null,
    ) {
        sendBroadcast(
            Intent(VpnRuntimeContract.ACTION_STATUS)
                .setPackage(packageName)
                .putExtra(VpnRuntimeContract.EXTRA_RUNTIME_REQUEST, snapshot.requestId)
                .putExtra(VpnRuntimeContract.EXTRA_STATUS_QUERY, statusQueryId)
                .putExtra(VpnRuntimeContract.EXTRA_STATE, snapshot.state.name)
                .putExtra(VpnRuntimeContract.EXTRA_PACKETS, snapshot.packets)
                .putExtra(VpnRuntimeContract.EXTRA_PACKETS_WRITTEN, snapshot.replies)
                .putExtra(VpnRuntimeContract.EXTRA_ALWAYS_ON, isAlwaysOnCompat())
                .putExtra(VpnRuntimeContract.EXTRA_LOCKDOWN, isLockdownCompat())
                .putExtra(VpnRuntimeContract.EXTRA_FAILURE, snapshot.failure)
                .putExtra(
                    VpnRuntimeContract.EXTRA_PACKET_DISPOSITION,
                    snapshot.disposition,
                )
                .putExtra(
                    VpnRuntimeContract.EXTRA_PER_APP_MODE,
                    snapshot.config.routingPolicy.perAppMode.name,
                )
                .putExtra(VpnRuntimeContract.EXTRA_STARTED_AT, snapshot.startedAtElapsedRealtime)
                .putExtra(VpnRuntimeContract.EXTRA_DNS_MODE, snapshot.config.dnsMode.name)
                .putExtra(VpnRuntimeContract.EXTRA_IP_MODE, snapshot.config.ipMode.name)
                .putExtra(VpnRuntimeContract.EXTRA_MTU, snapshot.config.mtu)
                .putExtra(
                    VpnRuntimeContract.EXTRA_PROFILE_GENERATION,
                    snapshot.authority?.generation ?: 0,
                )
                .putExtra(
                    VpnRuntimeContract.EXTRA_PLAN_DIGEST,
                    snapshot.authority?.planDigest?.toHex(),
                )
                .putExtra(
                    VpnRuntimeContract.EXTRA_PROFILE_FINGERPRINT,
                    snapshot.authority?.profileFingerprint?.toHex(),
                )
                .putExtra(
                    VpnRuntimeContract.EXTRA_STRATEGY_FINGERPRINT,
                    snapshot.authority?.strategyFingerprint?.toHex(),
                )
                .putExtra(
                    VpnRuntimeContract.EXTRA_RELAY_FINGERPRINT,
                    snapshot.authority?.relayFingerprint?.toHex(),
                )
                .putExtra(
                    VpnRuntimeContract.EXTRA_MAX_RECONNECT_ATTEMPTS,
                    snapshot.authority?.maxReconnectAttempts ?: 0,
                )
                .putExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_TUN_READ, snapshot.diagnostics.tunPacketsRead)
                .putExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_OUTBOUND, snapshot.diagnostics.outboundPacketsAccepted)
                .putExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_CARRIER_WRITE, snapshot.diagnostics.carrierRecordsWritten)
                .putExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_CARRIER_READ, snapshot.diagnostics.carrierRecordsRead)
                .putExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_AUTHENTICATED, snapshot.diagnostics.authenticatedOperations)
                .putExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_INNER_ACCEPTED, snapshot.diagnostics.innerPacketsAccepted)
                .putExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_INNER_REJECTED, snapshot.diagnostics.innerPacketsRejected)
                .putExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_TUN_ATTEMPTS, snapshot.diagnostics.tunWriteAttempts)
                .putExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_TUN_FAILURES, snapshot.diagnostics.tunWriteFailures)
                .putExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_TUN_FAILURE_CODE, snapshot.diagnostics.tunWriteFailureCode)
                .putExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_TUN_ERRNO, snapshot.diagnostics.tunWriteErrno)
                .putExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_TUN_WRITTEN, snapshot.diagnostics.tunPacketsWritten)
                .putExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_REJECTED, snapshot.diagnostics.rejectedTunPackets)
                .putExtra(
                    VpnRuntimeContract.EXTRA_DIAGNOSTIC_REJECTION_CODE,
                    snapshot.diagnostics.rejectedTunPacketCode,
                ),
        )
    }

    private fun configFrom(snapshot: NativeLiveRuntimeSessionSnapshot): VpnRuntimeConfig {
        val mode = when (snapshot.perAppMode) {
            PerAppSelectionMode.ALL_APPS -> PerAppRoutingMode.ALL_APPS
            PerAppSelectionMode.INCLUDE_ONLY -> PerAppRoutingMode.INCLUDE_ONLY
            PerAppSelectionMode.EXCLUDE_SELECTED -> PerAppRoutingMode.EXCLUDE_SELECTED
        }
        return VpnRuntimeConfig(
            routingPolicy = VpnRoutingPolicy(mode, snapshot.packages.toSet()),
            selectionMode = snapshot.selectionMode,
            ipMode = snapshot.ipMode,
            dnsMode = snapshot.dnsMode,
            mtu = snapshot.mtu,
            metered = snapshot.metered,
        ).validatedForLiveTransport()
    }

    private fun establishTun(
        configuration: LiveTunConfiguration,
        underlyingNetwork: Network,
    ): DetachableTun? {
        val builder = Builder()
            .setSession("Kurdistan VPN")
            .setMtu(configuration.mtu)
            .setBlocking(true)
            .setUnderlyingNetworks(arrayOf(underlyingNetwork))
        configuration.addresses.forEach { builder.addAddress(it.address, it.prefixLength) }
        configuration.routes.forEach { builder.addRoute(it.address, it.prefixLength) }
        configuration.dnsServers.forEach(builder::addDnsServer)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(configuration.metered)
        }
        applyPerAppPolicy(builder, configuration.routingPolicy)
        // The wrapper exists before Builder.establish. A returned descriptor cannot be
        // stranded by a later wrapper allocation or descriptor-validation exception.
        return PlatformTunOwner(acquire = {
            val descriptor = builder.establish()
            descriptor
        },
            validate = { descriptor -> check(descriptor.fd >= 0) { "TUN_DESCRIPTOR_INVALID" } },
            detach = ParcelFileDescriptor::detachFd).establish()
    }

    private fun applyPerAppPolicy(builder: Builder, policy: VpnRoutingPolicy) {
        when (policy.perAppMode) {
            PerAppRoutingMode.ALL_APPS -> Unit
            PerAppRoutingMode.INCLUDE_ONLY ->
                policy.packages.forEach(builder::addAllowedApplication)
            PerAppRoutingMode.EXCLUDE_SELECTED ->
                policy.packages.forEach(builder::addDisallowedApplication)
        }
    }

    private fun isAlwaysOnCompat(): Boolean =
        android.os.Build.VERSION.SDK_INT >= 29 && isAlwaysOn

    private fun isLockdownCompat(): Boolean =
        android.os.Build.VERSION.SDK_INT >= 29 && isLockdownEnabled

    private fun notification(text: String): Notification {
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
            .build()
    }

    private fun createNotificationChannel() {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "VPN connection",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Shows the active Kurdistan VPN runtime"
                setShowBadge(false)
            },
        )
    }

    companion object {
        private const val CHANNEL_ID = "kurdistan-vpn-runtime"
        private const val NOTIFICATION_ID = 1001
        private const val NETWORK_BIND_TIMEOUT_MILLIS = 5_000L
        private const val RUNTIME_HEALTH_INTERVAL_MILLIS = 250L
        private val PROCESS_EPOCH = UUID.randomUUID().toString().replace("-", "")

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
        private fun runtimeFailure(failure: LiveTunnelFailure): RuntimeStartFailure = when (failure) {
            LiveTunnelFailure.NETWORK_LOST -> RuntimeStartFailure.NETWORK_LOST
            LiveTunnelFailure.ENDPOINT_UNAVAILABLE -> RuntimeStartFailure.ENDPOINT_UNAVAILABLE
            LiveTunnelFailure.TLS_REJECTED -> RuntimeStartFailure.TLS_REJECTED
            LiveTunnelFailure.AUTHORITY_REJECTED, LiveTunnelFailure.KURD_AUTH_REJECTED -> RuntimeStartFailure.AUTHORITY_REJECTED
            LiveTunnelFailure.CANCELLED -> RuntimeStartFailure.CANCELLED
            LiveTunnelFailure.RECOVERY_REQUIRED -> RuntimeStartFailure.CLEANUP_UNPROVEN
            LiveTunnelFailure.STATE_CORRUPT -> RuntimeStartFailure.STATE_CORRUPT
            else -> RuntimeStartFailure.INTERNAL_FAILURE
        }
        private fun wipe(snapshot: NativeLiveRuntimeSessionSnapshot) {
            snapshot.planDigest.fill(0); snapshot.profileFingerprint.fill(0)
            snapshot.strategyFingerprint.fill(0); snapshot.relayFingerprint.fill(0)
            snapshot.clientIpv4.fill(0); snapshot.clientIpv6.fill(0)
            snapshot.dnsIpv4.fill(0); snapshot.dnsIpv6.fill(0)
            snapshot.routes.forEach { it.address.fill(0) }
        }
    }
    private data class PublishedSnapshot(
        val state: VpnRuntimeState = VpnRuntimeState.IDLE,
        val packets: Long = 0,
        val replies: Long = 0,
        val failure: String? = null,
        val disposition: String? = null,
        val config: VpnRuntimeConfig = VpnRuntimeConfig(VpnRoutingPolicy()),
        val startedAtElapsedRealtime: Long = 0,
        val authority: NativeLiveRuntimeSessionSnapshot? = null,
        val diagnostics: VpnRuntimeDiagnostics = VpnRuntimeDiagnostics(),
        val requestId: String? = null,
    )

    private fun NativeLiveRuntimeDiagnostics.toRuntimeDiagnostics() = VpnRuntimeDiagnostics(
        tunPacketsRead = tunPacketsRead,
        outboundPacketsAccepted = outboundPacketsAccepted,
        carrierRecordsWritten = carrierRecordsWritten,
        carrierRecordsRead = carrierRecordsRead,
        authenticatedOperations = authenticatedOperations,
        innerPacketsAccepted = innerPacketsAccepted,
        innerPacketsRejected = innerPacketsRejected,
        tunWriteAttempts = tunWriteAttempts,
        tunWriteFailures = tunWriteFailures,
        tunWriteFailureCode = tunWriteFailureCode,
        tunWriteErrno = tunWriteErrno,
        tunPacketsWritten = tunPacketsWritten,
        rejectedTunPackets = rejectedTunPackets,
        rejectedTunPacketCode = rejectedTunPacketCode,
    )


    private fun ByteArray.toHex(): String = joinToString(separator = "") { value ->
        "%02x".format(value.toInt() and 0xff)
    }
}
