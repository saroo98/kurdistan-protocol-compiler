// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ComponentName
import android.content.ServiceConnection
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.UUID
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.NativeLiveRuntimeSessionSnapshot
import org.kurdistanvpn.core.nativeapi.NativeLiveRuntimeDiagnostics
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.runtime.api.PerAppRoutingMode
import org.kurdistanvpn.runtime.api.LiveTunConfiguration
import org.kurdistanvpn.runtime.api.LiveTunnelStage
import org.kurdistanvpn.runtime.api.LiveTunnelStartResult
import org.kurdistanvpn.runtime.api.RuntimeStartWire
import org.kurdistanvpn.runtime.api.VpnRuntimeContract
import org.kurdistanvpn.runtime.api.VpnRuntimeState
import org.kurdistanvpn.runtime.api.VpnRuntimeConfig
import org.kurdistanvpn.runtime.api.VpnRuntimeDiagnostics
import org.kurdistanvpn.runtime.api.VpnRoutingPolicy

class KurdVpnService : VpnService() {
    private val executor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "kurd-vpn-tun").apply { isDaemon = true }
    }
    private val starting = AtomicBoolean(false)
    private val mainHandler = Handler(Looper.getMainLooper())
    private var tunnelController: NativeTunnelController? = null
    private var networkMonitor: UnderlyingNetworkMonitor? = null
    private val underlyingNetworkAvailability = UnderlyingNetworkAvailability<Network>()
    private var pendingAuthorityRequest: String? = null
    @Volatile
    private var activeRequestId: String? = null
    private val authorityArrivalTimeout = Runnable {
        val requestId = pendingAuthorityRequest ?: return@Runnable
        pendingAuthorityRequest = null
        RuntimeAuthorityBroker.cancel(requestId)
        publish(VpnRuntimeState.FAILED, failure = "AUTHORITY_HANDOFF_TIMEOUT")
        activeRequestId = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }
    private val runtimeHealthCheck = object : Runnable {
        override fun run() {
            val controller = tunnelController ?: return
            val diagnostics = when (val result = controller.diagnostics()) {
                is NativeResult.Success -> result.value.toRuntimeDiagnostics()
                is NativeResult.Failure -> latestSnapshot.diagnostics
            }
            val failure = controller.checkHealth()
            if (failure != null) {
                val config = activeConfig ?: VpnRuntimeConfig(VpnRoutingPolicy())
                val authority = latestSnapshot.authority
                closeRuntime()
                publish(
                    VpnRuntimeState.FAILED,
                    failure = "LIVE_${failure.name}",
                    disposition = "LIVE_STAGE_RUNTIME_MONITOR",
                    config = config,
                    authority = authority,
                    diagnostics = diagnostics,
                )
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }
            if (diagnostics != latestSnapshot.diagnostics) {
                publish(latestSnapshot.copy(diagnostics = diagnostics))
            }
            mainHandler.postDelayed(this, RUNTIME_HEALTH_INTERVAL_MILLIS)
        }
    }
    private val nativeCore by lazy { NativeBridge() }
    @Volatile
    private var activeConfig: VpnRuntimeConfig? = null
    @Volatile
    private var latestSnapshot = PublishedSnapshot()
    private val pendingTermination = PendingRuntimeTermination()
    private val statusQueryReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == VpnRuntimeContract.ACTION_QUERY_STATUS) {
                val queryId = intent.getStringExtra(
                    VpnRuntimeContract.EXTRA_STATUS_QUERY,
                ).orEmpty()
                if (validRequestId(queryId)) {
                    publishTransient(latestSnapshot, queryId)
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        val filter = IntentFilter(VpnRuntimeContract.ACTION_QUERY_STATUS)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(statusQueryReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(statusQueryReceiver, filter)
        }
        networkMonitor = UnderlyingNetworkMonitor(
            getSystemService(ConnectivityManager::class.java),
            ::onUnderlyingNetworkTransition,
        ).also(UnderlyingNetworkMonitor::start)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            VpnRuntimeContract.ACTION_STOP -> {
                // Android can deliver a stop command while the service record is still
                // covered by a preceding startForegroundService request. Reasserting
                // foreground state before teardown closes that race without leaving a
                // notification or a live service behind.
                startForeground(
                    NOTIFICATION_ID,
                    notification("Stopping Kurdistan VPN safely"),
                )
                stopRuntime(VpnRuntimeState.IDLE)
            }
            VpnRuntimeContract.ACTION_START -> {
                startForeground(
                    NOTIFICATION_ID,
                    notification("Awaiting verified Kurd session authority"),
                )
                val requestId = intent.getStringExtra(
                    VpnRuntimeContract.EXTRA_AUTHORITY_REQUEST,
                ).orEmpty()
                if (!armAuthorityRequest(requestId)) {
                    publishTransient(
                        PublishedSnapshot(
                            state = VpnRuntimeState.FAILED,
                            failure = "MISSING_VERIFIED_AUTHORITY",
                            requestId = requestId.takeIf(::validRequestId),
                        ),
                    )
                    if (activeRequestId == null && tunnelController?.isRunning() != true && !starting.get()) {
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                    return Service.START_NOT_STICKY
                }
            }
            null -> {
                publish(VpnRuntimeState.FAILED, failure = "MISSING_START_COMMAND")
                stopSelf()
            }
        }
        return Service.START_NOT_STICKY
    }

    override fun onRevoke() {
        stopRuntime(VpnRuntimeState.REVOKED)
        super.onRevoke()
    }

    override fun onDestroy() {
        runCatching { unregisterReceiver(statusQueryReceiver) }
        mainHandler.removeCallbacks(authorityArrivalTimeout)
        mainHandler.removeCallbacks(runtimeHealthCheck)
        pendingAuthorityRequest?.let(RuntimeAuthorityBroker::cancel)
        pendingAuthorityRequest = null
        networkMonitor?.close()
        networkMonitor = null
        closeRuntime()
        pendingTermination.take()?.let { outcome ->
            publish(outcome.state, failure = outcome.failure)
        }
        executor.shutdownNow()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    private fun armAuthorityRequest(requestId: String): Boolean {
        if (!validRequestId(requestId) || activeRequestId != null || pendingAuthorityRequest != null || tunnelController?.isRunning() == true || starting.get()) return false
        activeRequestId = requestId
        pendingAuthorityRequest = requestId
        startForeground(NOTIFICATION_ID, notification("Awaiting verified Kurd session authority"))
        publish(VpnRuntimeState.PREPARING)
        val armed = RuntimeAuthorityBroker.arm(requestId) { descriptor, length ->
            if (pendingAuthorityRequest != requestId) {
                descriptor.close()
            } else {
                mainHandler.removeCallbacks(authorityArrivalTimeout)
                pendingAuthorityRequest = null
                startRuntime(descriptor, length)
            }
        }
        if (!armed) {
            pendingAuthorityRequest = null
            activeRequestId = null
        }
        if (armed && pendingAuthorityRequest == requestId) {
            mainHandler.postDelayed(
                authorityArrivalTimeout,
                RuntimeAuthorityTimeoutPolicy.ARRIVAL_MILLIS,
            )
        }
        return armed
    }

    private fun startRuntime(authority: ParcelFileDescriptor, authorityLength: Int) {
        if (tunnelController?.isRunning() == true) {
            authority.close()
            publish(latestSnapshot.copy(failure = "POLICY_CHANGE_REQUIRES_STOP"))
            return
        }
        if (!starting.compareAndSet(false, true)) {
            authority.close()
            publish(VpnRuntimeState.PREPARING)
            return
        }
        startForeground(NOTIFICATION_ID, notification("Verifying Kurd session authority"))
        publish(VpnRuntimeState.PREPARING)
        executor.execute {
            var terminalFailure: String? = null
            var config = VpnRuntimeConfig(VpnRoutingPolicy())
            var authoritySnapshot: NativeLiveRuntimeSessionSnapshot? = null
            var lastStage: LiveTunnelStage? = null
            try {
                val authorityBytes = readAuthority(authority, authorityLength)
                val opened = try {
                    nativeCore.openLiveRuntimeSession(authorityBytes)
                } finally {
                    authorityBytes.fill(0)
                }
                val session = when (opened) {
                    is NativeResult.Failure -> {
                        terminalFailure = "AUTHORITY_${opened.error.name}"
                        null
                    }
                    is NativeResult.Success -> opened.value
                }
                if (session == null) return@execute
                authoritySnapshot = session.snapshot
                config = configFrom(session.snapshot)
                val selectedUnderlyingNetwork =
                    underlyingNetworkAvailability.awaitUsable(NETWORK_BIND_TIMEOUT_MILLIS)
                if (selectedUnderlyingNetwork == null) {
                    session.close()
                    terminalFailure = "LIVE_NETWORK_UNAVAILABLE"
                    return@execute
                }
                if (pendingTermination.peek() != null) return@execute
                val controller = NativeTunnelController(
                    protector = SocketProtector(::protect),
                    tunEstablisher = TunEstablisher { configuration ->
                        establishTun(configuration, selectedUnderlyingNetwork)
                    },
                    detachedCloser = DetachedFileDescriptorCloser { fd ->
                        runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
                    },
                    onStage = { stage ->
                        lastStage = stage
                        publish(
                            VpnRuntimeState.PREPARING,
                            disposition = "LIVE_STAGE_${stage.name}",
                            config = config,
                            authority = authoritySnapshot,
                        )
                    },
                )
                tunnelController = controller
                when (val started = controller.start(session)) {
                    is LiveTunnelStartResult.Failure -> {
                        terminalFailure = "LIVE_${started.category.name}"
                    }
                    is LiveTunnelStartResult.Running -> {
                        activeConfig = config
                        publish(
                            VpnRuntimeState.ACTIVE_KURD_LIVE,
                            config = config,
                            authority = authoritySnapshot,
                        )
                        updateNotification("Verified Kurd relay session active")
                        mainHandler.postDelayed(
                            runtimeHealthCheck,
                            RUNTIME_HEALTH_INTERVAL_MILLIS,
                        )
                    }
                }
            } catch (failure: AuthorityReadFailure) {
                terminalFailure = failure.category
            } catch (_: Throwable) {
                if (starting.get()) {
                    terminalFailure = "VPN_RUNTIME_FAILURE"
                }
            } finally {
                val failure = terminalFailure
                val requestedTermination = pendingTermination.take()
                if (requestedTermination != null) {
                    starting.set(false)
                    closeRuntime()
                    publish(
                        requestedTermination.state,
                        failure = requestedTermination.failure,
                        config = config,
                        authority = authoritySnapshot,
                    )
                    activeRequestId = null
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                } else if (failure != null && starting.compareAndSet(true, false)) {
                    closeRuntime()
                    publish(
                        VpnRuntimeState.FAILED,
                        failure = failure,
                        disposition = "LIVE_STAGE_${lastStage?.name ?: "AUTHORITY_OPEN"}",
                        config = config,
                        authority = authoritySnapshot,
                    )
                    activeRequestId = null
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                } else if (failure == null) {
                    starting.set(false)
                }
            }
        }
    }

    private fun stopRuntime(
        finalState: VpnRuntimeState,
        finalFailure: String? = null,
    ) {
        publish(VpnRuntimeState.STOPPING)
        mainHandler.removeCallbacks(authorityArrivalTimeout)
        mainHandler.removeCallbacks(runtimeHealthCheck)
        pendingAuthorityRequest?.let(RuntimeAuthorityBroker::cancel)
        pendingAuthorityRequest = null
        pendingTermination.request(finalState, finalFailure)
        tunnelController?.stop()
        if (!starting.get()) {
            closeRuntime()
            val outcome = pendingTermination.take() ?: RuntimeTermination(finalState, finalFailure)
            publish(outcome.state, failure = outcome.failure)
            activeRequestId = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun closeRuntime() {
        mainHandler.removeCallbacks(runtimeHealthCheck)
        starting.set(false)
        runCatching { tunnelController?.close() }
        tunnelController = null
        activeConfig = null
    }

    private fun publish(
        state: VpnRuntimeState,
        packets: Long = 0,
        replies: Long = 0,
        failure: String? = null,
        disposition: String? = null,
        config: VpnRuntimeConfig = VpnRuntimeConfig(VpnRoutingPolicy()),
        authority: NativeLiveRuntimeSessionSnapshot? = null,
        diagnostics: VpnRuntimeDiagnostics = VpnRuntimeDiagnostics(),
    ) {
        publish(
            PublishedSnapshot(
                state = state,
                packets = packets,
                replies = replies,
                failure = failure,
                disposition = disposition,
                config = config,
                authority = authority,
                diagnostics = diagnostics,
                requestId = activeRequestId,
                startedAtElapsedRealtime = if (
                    state == VpnRuntimeState.ACTIVE_KURD_LOOPBACK ||
                    state == VpnRuntimeState.ACTIVE_KURD_LIVE ||
                    state == VpnRuntimeState.ACTIVE_LOCAL_ONLY
                ) {
                    latestSnapshot.startedAtElapsedRealtime.takeIf { it > 0 }
                        ?: SystemClock.elapsedRealtime()
                } else 0,
            ),
        )
    }

    private fun publish(snapshot: PublishedSnapshot) {
        latestSnapshot = snapshot
        publishTransient(snapshot)
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
        val descriptor = builder.establish() ?: return null
        return object : DetachableTun {
            override fun detachFileDescriptor(): Int = descriptor.detachFd()
            override fun close() = descriptor.close()
        }
    }

    private fun onUnderlyingNetworkTransition(transition: NetworkTransition<Network>) {
        val bound = when {
            transition.current == null -> false
            tunnelController?.isRunning() == true -> runCatching {
                setUnderlyingNetworks(arrayOf(transition.current))
            }.getOrDefault(false)
            else -> true
        }
        underlyingNetworkAvailability.update(transition.current, bound)
        if (transition.current == null) {
            runCatching { setUnderlyingNetworks(null) }
        }
        if (transition.previous == null || transition.previous == transition.current) return
        if (tunnelController?.isRunning() == true) {
            val failure = if (transition.current == null) {
                "NETWORK_UNAVAILABLE"
            } else {
                "NETWORK_CHANGED"
            }
            publish(
                VpnRuntimeState.BLOCKED,
                failure = failure,
                config = activeConfig ?: VpnRuntimeConfig(VpnRoutingPolicy()),
                authority = latestSnapshot.authority,
            )
            stopRuntime(VpnRuntimeState.BLOCKED, failure)
        }
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

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, notification(text))
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
        private const val MAX_RUNTIME_OPEN_BYTES = RuntimeStartWire.MAX_RUNTIME_OPEN_BYTES
        private const val NETWORK_BIND_TIMEOUT_MILLIS = 5_000L
        private const val RUNTIME_HEALTH_INTERVAL_MILLIS = 250L

        fun start(
            context: Context,
            requestId: String,
            authority: ByteArray,
            handoffExecutor: Executor,
            onFailure: (String) -> Unit,
        ) {
            require(authority.size in 1..MAX_RUNTIME_OPEN_BYTES) {
                "INVALID_VERIFIED_AUTHORITY"
            }
            require(validRequestId(requestId)) { "INVALID_AUTHORITY_REQUEST" }
            val pipe = ParcelFileDescriptor.createReliablePipe()
            val readSide = pipe[0]
            val writeSide = pipe[1]
            val intent = Intent(context, KurdVpnService::class.java)
                .setAction(VpnRuntimeContract.ACTION_START)
                .putExtra(VpnRuntimeContract.EXTRA_AUTHORITY_REQUEST, requestId)
            try {
                context.startForegroundService(intent)
            } catch (failure: Throwable) {
                readSide.close()
                writeSide.closeWithError("service start failed")
                authority.fill(0)
                throw failure
            }
            val bindIntent = Intent(context, RuntimeAuthorityHandoffService::class.java)
                .setAction(RuntimeAuthorityHandoffService.ACTION_BIND_AUTHORITY)
            val connection = object : ServiceConnection {
                private val settled = AtomicBoolean(false)
                private val handler = Handler(Looper.getMainLooper())
                private val timeout = Runnable {
                    failBeforeClaim("AUTHORITY_BIND_TIMEOUT")
                }

                override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                    if (!settled.compareAndSet(false, true)) {
                        closeDescriptors("authority handoff already closed")
                        runCatching { context.unbindService(this) }
                        return
                    }
                    handler.removeCallbacks(timeout)
                    if (service == null) {
                        failClaimed("AUTHORITY_BIND_FAILED")
                        return
                    }
                    val accepted = runCatching {
                        RuntimeAuthorityBinder.submit(
                            service,
                            requestId,
                            readSide,
                            authority.size,
                        )
                    }.getOrDefault(false)
                    readSide.close()
                    if (!accepted) {
                        failClaimed("AUTHORITY_BIND_REJECTED")
                        return
                    }
                    val dispatched = runCatching {
                        handoffExecutor.execute {
                            try {
                                ParcelFileDescriptor.AutoCloseOutputStream(writeSide).use { output ->
                                    output.write(authority)
                                    output.flush()
                                }
                            } catch (_: Throwable) {
                                runCatching { writeSide.closeWithError("authority handoff failed") }
                            } finally {
                                authority.fill(0)
                            }
                        }
                    }.isSuccess
                    if (!dispatched) {
                        failClaimed("AUTHORITY_EXECUTOR_REJECTED")
                        return
                    }
                    runCatching { context.unbindService(this) }
                }

                override fun onServiceDisconnected(name: ComponentName?) = Unit

                override fun onNullBinding(name: ComponentName?) {
                    failBeforeClaim("AUTHORITY_BIND_FAILED")
                }

                fun scheduleTimeout() {
                    handler.postDelayed(timeout, RuntimeAuthorityTimeoutPolicy.BIND_MILLIS)
                }

                fun failBeforeClaim(category: String) {
                    if (!settled.compareAndSet(false, true)) return
                    handler.removeCallbacks(timeout)
                    failClaimed(category)
                }

                private fun failClaimed(category: String) {
                    closeDescriptors("authority bind failed")
                    authority.fill(0)
                    runCatching { onFailure(category) }
                    runCatching { context.unbindService(this) }
                }

                private fun closeDescriptors(message: String) {
                    runCatching { readSide.close() }
                    runCatching { writeSide.closeWithError(message) }
                }
            }
            val bound = try {
                context.bindService(bindIntent, connection, Context.BIND_AUTO_CREATE)
            } catch (_: Throwable) {
                connection.failBeforeClaim("AUTHORITY_BIND_FAILED")
                return
            }
            if (!bound) {
                connection.failBeforeClaim("AUTHORITY_BIND_FAILED")
            } else {
                connection.scheduleTimeout()
            }
        }

        fun newRequestId(): String = UUID.randomUUID().toString().replace("-", "")

        private fun validRequestId(value: String): Boolean =
            value.length == 32 && value.all { it in '0'..'9' || it in 'a'..'f' }

        fun stop(context: Context) {
            val intent = Intent(context, KurdVpnService::class.java)
                .setAction(VpnRuntimeContract.ACTION_STOP)
            context.startService(intent)
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

    private class AuthorityReadFailure(val category: String) : Exception()

    private fun readAuthority(descriptor: ParcelFileDescriptor, length: Int): ByteArray {
        val timeout = Executors.newSingleThreadScheduledExecutor { task ->
            Thread(task, "kurd-authority-timeout").apply { isDaemon = true }
        }
        val cancellation = timeout.schedule(
            { runCatching { descriptor.closeWithError("authority timeout") } },
            RuntimeAuthorityTimeoutPolicy.PIPE_READ_SECONDS,
            TimeUnit.SECONDS,
        )
        return try {
            val result = ByteArray(length)
            ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { input ->
                var offset = 0
                while (offset < result.size) {
                    val count = input.read(result, offset, result.size - offset)
                    if (count < 0) throw AuthorityReadFailure("AUTHORITY_EARLY_EOF")
                    if (count == 0) continue
                    offset += count
                }
                if (input.read() != -1) throw AuthorityReadFailure("AUTHORITY_TRAILING_BYTES")
            }
            result
        } catch (failure: AuthorityReadFailure) {
            throw failure
        } catch (_: Throwable) {
            throw AuthorityReadFailure("AUTHORITY_PIPE_READ_FAILED")
        } finally {
            cancellation.cancel(true)
            timeout.shutdownNow()
        }
    }

    private fun ByteArray.toHex(): String = joinToString(separator = "") { value ->
        "%02x".format(value.toInt() and 0xff)
    }
}
