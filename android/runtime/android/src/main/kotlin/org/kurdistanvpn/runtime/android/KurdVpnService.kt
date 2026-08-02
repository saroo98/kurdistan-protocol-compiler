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
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.UUID
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.NativeRuntimeSession
import org.kurdistanvpn.core.nativeapi.NativeRuntimeSessionSnapshot
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.runtime.api.PerAppRoutingMode
import org.kurdistanvpn.runtime.api.RuntimeStartWire
import org.kurdistanvpn.runtime.api.VpnRuntimeContract
import org.kurdistanvpn.runtime.api.VpnRuntimeState
import org.kurdistanvpn.runtime.api.VpnRuntimeConfig
import org.kurdistanvpn.runtime.api.VpnRoutingPolicy

class KurdVpnService : VpnService() {
    private val executor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "kurd-vpn-tun").apply { isDaemon = true }
    }
    private val starting = AtomicBoolean(false)
    private val mainHandler = Handler(Looper.getMainLooper())
    private var tun: ParcelFileDescriptor? = null
    private var packetLoop: TunPacketLoop? = null
    private var nativeSession: NativeRuntimeSession? = null
    private var pendingAuthorityRequest: String? = null
    private val authorityArrivalTimeout = Runnable {
        val requestId = pendingAuthorityRequest ?: return@Runnable
        pendingAuthorityRequest = null
        RuntimeAuthorityBroker.cancel(requestId)
        publish(VpnRuntimeState.FAILED, failure = "AUTHORITY_HANDOFF_TIMEOUT")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }
    private val nativeCore by lazy { NativeBridge() }
    @Volatile
    private var activeConfig: VpnRuntimeConfig? = null
    @Volatile
    private var latestSnapshot = PublishedSnapshot()
    @Volatile
    private var terminalStateOnDestroy: VpnRuntimeState? = null
    private val statusQueryReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == VpnRuntimeContract.ACTION_QUERY_STATUS) {
                publish(latestSnapshot)
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
                    publish(
                        VpnRuntimeState.FAILED,
                        failure = "MISSING_VERIFIED_AUTHORITY",
                    )
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
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
        pendingAuthorityRequest?.let(RuntimeAuthorityBroker::cancel)
        pendingAuthorityRequest = null
        closeRuntime()
        terminalStateOnDestroy?.let(::publish)
        terminalStateOnDestroy = null
        executor.shutdownNow()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    private fun armAuthorityRequest(requestId: String): Boolean {
        if (requestId.length != 32 || requestId.any { it !in '0'..'9' && it !in 'a'..'f' }) {
            return false
        }
        if (pendingAuthorityRequest != null || tun != null || starting.get()) return false
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
        if (!armed) pendingAuthorityRequest = null
        if (armed && pendingAuthorityRequest == requestId) {
            mainHandler.postDelayed(authorityArrivalTimeout, AUTHORITY_TIMEOUT_SECONDS * 1_000L)
        }
        return armed
    }

    private fun startRuntime(authority: ParcelFileDescriptor, authorityLength: Int) {
        if (tun != null) {
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
            var authoritySnapshot: NativeRuntimeSessionSnapshot? = null
            try {
                val authorityBytes = readAuthority(authority, authorityLength)
                val opened = try {
                    nativeCore.openRuntimeSession(authorityBytes)
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
                nativeSession = session
                authoritySnapshot = session.snapshot
                config = configFrom(session.snapshot)
                if (terminalStateOnDestroy != null) return@execute
                val builder = Builder()
                    .setSession("Kurdistan VPN local runtime")
                    .setMtu(config.mtu)
                    .addAddress(LOCAL_ADDRESS, 32)
                    .addRoute(TEST_ROUTE, TEST_ROUTE_PREFIX)
                    .addDnsServer(DNS_ADDRESS)
                    .setBlocking(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    builder.setMetered(config.metered)
                }
                applyPerAppPolicy(builder, config.routingPolicy)
                val descriptor = builder.establish()
                    ?: error("VPN permission is not prepared")
                tun = descriptor
                activeConfig = config
                val pollDescriptor = StructPollfd().apply {
                    fd = descriptor.fileDescriptor
                    events = OsConstants.POLLIN.toShort()
                }
                val loop = TunPacketLoop(
                    FileInputStream(descriptor.fileDescriptor),
                    FileOutputStream(descriptor.fileDescriptor),
                    kurdRoundTrip = { payload ->
                        when (val result = session.roundTrip(payload)) {
                            is NativeResult.Success -> result.value
                            is NativeResult.Failure -> null
                        }
                    },
                    onPacketCount = { count, replies, disposition ->
                        if (count <= 8L || replies in 1L..8L || count % 64L == 0L) {
                            val reportedDisposition =
                                if (replies > latestSnapshot.replies) {
                                    disposition
                                } else {
                                    latestSnapshot.disposition
                                }
                            publish(
                                VpnRuntimeState.ACTIVE_KURD_LOOPBACK,
                                count,
                                replies,
                                disposition = reportedDisposition,
                                config = config,
                                authority = authoritySnapshot,
                            )
                        }
                    },
                    awaitReadable = {
                        pollDescriptor.revents = 0
                        val ready = Os.poll(arrayOf(pollDescriptor), TUN_POLL_MILLIS)
                        if (ready == 0) {
                            false
                        } else {
                            val events = pollDescriptor.revents.toInt()
                            if (
                                events and (
                                    OsConstants.POLLERR or
                                        OsConstants.POLLHUP or
                                        OsConstants.POLLNVAL
                                    ) != 0
                            ) {
                                throw IOException("TUN descriptor poll failed")
                            }
                            events and OsConstants.POLLIN != 0
                        }
                    },
                )
                packetLoop = loop
                publish(
                    VpnRuntimeState.ACTIVE_KURD_LOOPBACK,
                    config = config,
                    authority = authoritySnapshot,
                )
                updateNotification("Verified Kurd loopback session active")
                terminalFailure = when (loop.run()) {
                    TunPacketLoop.ExitReason.STOP_REQUESTED -> null
                    TunPacketLoop.ExitReason.INPUT_EOF -> "TUN_INPUT_EOF"
                    TunPacketLoop.ExitReason.INPUT_FAILURE -> "TUN_INPUT_FAILURE"
                }
            } catch (failure: AuthorityReadFailure) {
                terminalFailure = failure.category
            } catch (_: Throwable) {
                if (starting.get()) {
                    terminalFailure = "VPN_RUNTIME_FAILURE"
                }
            } finally {
                val failure = terminalFailure
                val requestedTerminalState = terminalStateOnDestroy
                if (requestedTerminalState != null) {
                    starting.set(false)
                    closeRuntime()
                    terminalStateOnDestroy = null
                    publish(
                        requestedTerminalState,
                        config = config,
                        authority = authoritySnapshot,
                    )
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                } else if (failure != null && starting.compareAndSet(true, false)) {
                    closeRuntime()
                    publish(
                        VpnRuntimeState.FAILED,
                        failure = failure,
                        config = config,
                        authority = authoritySnapshot,
                    )
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                } else {
                    starting.set(false)
                }
            }
        }
    }

    private fun stopRuntime(finalState: VpnRuntimeState) {
        publish(VpnRuntimeState.STOPPING)
        mainHandler.removeCallbacks(authorityArrivalTimeout)
        pendingAuthorityRequest?.let(RuntimeAuthorityBroker::cancel)
        pendingAuthorityRequest = null
        terminalStateOnDestroy = finalState
        packetLoop?.requestStop()
        if (!starting.get()) {
            closeRuntime()
            terminalStateOnDestroy = null
            publish(finalState)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun closeRuntime() {
        starting.set(false)
        val descriptor = tun
        tun = null
        closeTunDescriptor(descriptor)
        val loop = packetLoop
        packetLoop = null
        loop?.close()
        runCatching { nativeSession?.close() }
        nativeSession = null
        activeConfig = null
    }

    private fun closeTunDescriptor(descriptor: ParcelFileDescriptor?) {
        if (descriptor == null) return
        val detached = runCatching { descriptor.detachFd() }.getOrNull()
        if (detached != null) {
            runCatching { ParcelFileDescriptor.adoptFd(detached).close() }
        } else {
            runCatching { descriptor.close() }
        }
    }

    private fun publish(
        state: VpnRuntimeState,
        packets: Long = 0,
        replies: Long = 0,
        failure: String? = null,
        disposition: String? = null,
        config: VpnRuntimeConfig = VpnRuntimeConfig(VpnRoutingPolicy()),
        authority: NativeRuntimeSessionSnapshot? = null,
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
                startedAtElapsedRealtime = if (
                    state == VpnRuntimeState.ACTIVE_KURD_LOOPBACK ||
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
        sendBroadcast(
            Intent(VpnRuntimeContract.ACTION_STATUS)
                .setPackage(packageName)
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
                ),
        )
    }

    private fun configFrom(snapshot: NativeRuntimeSessionSnapshot): VpnRuntimeConfig {
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
        ).validatedForLoopbackTransport()
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
        private const val LOCAL_ADDRESS = "198.18.0.1"
        private const val TEST_ROUTE = "198.18.0.0"
        private const val TEST_ROUTE_PREFIX = 15
        private const val DNS_ADDRESS = "198.18.0.53"
        private const val MAX_RUNTIME_OPEN_BYTES = RuntimeStartWire.MAX_RUNTIME_OPEN_BYTES
        private const val AUTHORITY_TIMEOUT_SECONDS = 5L
        private const val TUN_POLL_MILLIS = 250

        fun start(
            context: Context,
            authority: ByteArray,
            handoffExecutor: Executor,
            onFailure: (String) -> Unit,
        ) {
            require(authority.size in 1..MAX_RUNTIME_OPEN_BYTES) {
                "INVALID_VERIFIED_AUTHORITY"
            }
            val requestId = UUID.randomUUID().toString().replace("-", "")
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
                    handler.postDelayed(timeout, AUTHORITY_TIMEOUT_SECONDS * 1_000L)
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
        val authority: NativeRuntimeSessionSnapshot? = null,
    )

    private class AuthorityReadFailure(val category: String) : Exception()

    private fun readAuthority(descriptor: ParcelFileDescriptor, length: Int): ByteArray {
        val timeout = Executors.newSingleThreadScheduledExecutor { task ->
            Thread(task, "kurd-authority-timeout").apply { isDaemon = true }
        }
        val cancellation = timeout.schedule(
            { runCatching { descriptor.closeWithError("authority timeout") } },
            AUTHORITY_TIMEOUT_SECONDS,
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
