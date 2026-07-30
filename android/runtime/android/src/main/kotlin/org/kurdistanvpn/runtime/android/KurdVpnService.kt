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
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.runtime.api.PerAppRoutingMode
import org.kurdistanvpn.runtime.api.VpnRuntimeContract
import org.kurdistanvpn.runtime.api.VpnRuntimeState
import org.kurdistanvpn.runtime.api.VpnRoutingPolicy

class KurdVpnService : VpnService() {
    private val executor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "kurd-vpn-tun").apply { isDaemon = true }
    }
    private val starting = AtomicBoolean(false)
    private var tun: ParcelFileDescriptor? = null
    private var packetLoop: TunPacketLoop? = null
    private val nativeCore by lazy { NativeBridge() }
    @Volatile
    private var activePolicy: VpnRoutingPolicy? = null
    @Volatile
    private var latestSnapshot = PublishedSnapshot()
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
            VpnRuntimeContract.ACTION_STOP -> stopRuntime(VpnRuntimeState.IDLE)
            VpnRuntimeContract.ACTION_START -> {
                val policy = runCatching { policyFrom(intent) }.getOrElse { failure ->
                    publish(
                        VpnRuntimeState.FAILED,
                        failure = failure::class.java.simpleName,
                    )
                    stopSelf()
                    return Service.START_NOT_STICKY
                }
                startRuntime(policy)
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
        closeRuntime()
        executor.shutdownNow()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    private fun startRuntime(policy: VpnRoutingPolicy) {
        if (tun != null) {
            val establishedPolicy = activePolicy ?: VpnRoutingPolicy()
            if (establishedPolicy == policy) {
                publish(latestSnapshot)
            } else {
                publish(
                    latestSnapshot.copy(
                        failure = "POLICY_CHANGE_REQUIRES_STOP",
                        policy = establishedPolicy,
                    ),
                )
            }
            return
        }
        if (!starting.compareAndSet(false, true)) {
            publish(VpnRuntimeState.PREPARING, policy = policy)
            return
        }
        startForeground(NOTIFICATION_ID, notification("Preparing local VPN runtime"))
        publish(VpnRuntimeState.PREPARING, policy = policy)
        executor.execute {
            var terminalFailure: String? = null
            try {
                val builder = Builder()
                    .setSession("Kurdistan VPN local runtime")
                    .setMtu(1500)
                    .addAddress(LOCAL_ADDRESS, 32)
                    .addRoute(TEST_ROUTE, TEST_ROUTE_PREFIX)
                    .addDnsServer(DNS_ADDRESS)
                    .setBlocking(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    builder.setMetered(false)
                }
                applyPerAppPolicy(builder, policy)
                val descriptor = builder.establish()
                    ?: error("VPN permission is not prepared")
                tun = descriptor
                activePolicy = policy
                val loop = TunPacketLoop(
                    FileInputStream(descriptor.fileDescriptor),
                    FileOutputStream(descriptor.fileDescriptor),
                    kurdRoundTrip = { payload ->
                        when (val result = nativeCore.phase11RoundTrip(payload)) {
                            is NativeResult.Success -> result.value
                            is NativeResult.Failure -> null
                        }
                    },
                ) { count, replies, disposition ->
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
                            policy = policy,
                        )
                    }
                }
                packetLoop = loop
                publish(VpnRuntimeState.ACTIVE_KURD_LOOPBACK, policy = policy)
                updateNotification("Kurd loopback transport active")
                terminalFailure = when (loop.run()) {
                    TunPacketLoop.ExitReason.STOP_REQUESTED -> null
                    TunPacketLoop.ExitReason.INPUT_EOF -> "TUN_INPUT_EOF"
                    TunPacketLoop.ExitReason.INPUT_FAILURE -> "TUN_INPUT_FAILURE"
                }
            } catch (_: Throwable) {
                if (starting.get()) {
                    terminalFailure = "VPN_RUNTIME_FAILURE"
                }
            } finally {
                val failure = terminalFailure
                if (failure != null && starting.compareAndSet(true, false)) {
                    closeRuntime()
                    publish(
                        VpnRuntimeState.FAILED,
                        failure = failure,
                        policy = policy,
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
        closeRuntime()
        publish(finalState)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun closeRuntime() {
        starting.set(false)
        packetLoop?.close()
        packetLoop = null
        runCatching { tun?.close() }
        tun = null
        activePolicy = null
    }

    private fun publish(
        state: VpnRuntimeState,
        packets: Long = 0,
        replies: Long = 0,
        failure: String? = null,
        disposition: String? = null,
        policy: VpnRoutingPolicy = VpnRoutingPolicy(),
    ) {
        publish(
            PublishedSnapshot(
                state = state,
                packets = packets,
                replies = replies,
                failure = failure,
                disposition = disposition,
                policy = policy,
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
                    snapshot.policy.perAppMode.name,
                ),
        )
    }

    private fun policyFrom(intent: Intent): VpnRoutingPolicy {
        val mode = intent.getStringExtra(VpnRuntimeContract.EXTRA_PER_APP_MODE)
            ?.let { runCatching { PerAppRoutingMode.valueOf(it) }.getOrNull() }
            ?: PerAppRoutingMode.ALL_APPS
        val packages = intent.getStringArrayListExtra(VpnRuntimeContract.EXTRA_PACKAGES)
            ?.toSet()
            .orEmpty()
        return VpnRoutingPolicy(mode, packages).validate()
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
        fun start(context: Context, policy: VpnRoutingPolicy) {
            val validated = policy.validate()
            val intent = Intent(context, KurdVpnService::class.java)
                .setAction(VpnRuntimeContract.ACTION_START)
                .putExtra(VpnRuntimeContract.EXTRA_PER_APP_MODE, validated.perAppMode.name)
                .putStringArrayListExtra(
                    VpnRuntimeContract.EXTRA_PACKAGES,
                    ArrayList(validated.packages),
                )
            context.startForegroundService(intent)
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
        val policy: VpnRoutingPolicy = VpnRoutingPolicy(),
    )
}
