// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import java.util.concurrent.Executors
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.kurdistanvpn.runtime.android.KurdVpnService
import org.kurdistanvpn.runtime.api.PerAppRoutingMode
import org.kurdistanvpn.runtime.api.VpnRuntimeContract
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeState
import org.kurdistanvpn.core.model.DnsMode
import org.kurdistanvpn.core.model.IpMode

class VpnRuntimeController(
    private val context: Context,
) : AutoCloseable {
    private val handoffExecutor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "kurd-runtime-authority-handoff").apply { isDaemon = true }
    }
    private var stagedAuthority: ByteArray? = null
    private val mutableSnapshot = MutableStateFlow(VpnRuntimeSnapshot())
    val snapshot: StateFlow<VpnRuntimeSnapshot> = mutableSnapshot.asStateFlow()
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != VpnRuntimeContract.ACTION_STATUS) return
            val state = intent.getStringExtra(VpnRuntimeContract.EXTRA_STATE)
                ?.let { runCatching { VpnRuntimeState.valueOf(it) }.getOrNull() }
                ?: VpnRuntimeState.FAILED
            mutableSnapshot.value = VpnRuntimeSnapshot(
                state = state,
                packetsRead = intent.getLongExtra(VpnRuntimeContract.EXTRA_PACKETS, 0),
                packetsWritten =
                    intent.getLongExtra(VpnRuntimeContract.EXTRA_PACKETS_WRITTEN, 0),
                alwaysOn = intent.getBooleanExtra(VpnRuntimeContract.EXTRA_ALWAYS_ON, false),
                lockdown = intent.getBooleanExtra(VpnRuntimeContract.EXTRA_LOCKDOWN, false),
                failure = intent.getStringExtra(VpnRuntimeContract.EXTRA_FAILURE),
                packetDisposition =
                    intent.getStringExtra(VpnRuntimeContract.EXTRA_PACKET_DISPOSITION),
                perAppRoutingMode = intent
                    .getStringExtra(VpnRuntimeContract.EXTRA_PER_APP_MODE)
                    ?.let { runCatching { PerAppRoutingMode.valueOf(it) }.getOrNull() }
                    ?: PerAppRoutingMode.ALL_APPS,
                startedAtElapsedRealtime = intent.getLongExtra(
                    VpnRuntimeContract.EXTRA_STARTED_AT,
                    0,
                ),
                dnsMode = intent.getStringExtra(VpnRuntimeContract.EXTRA_DNS_MODE)
                    ?.let { runCatching { DnsMode.valueOf(it) }.getOrNull() }
                    ?: DnsMode.INTERNAL_TUN,
                ipMode = intent.getStringExtra(VpnRuntimeContract.EXTRA_IP_MODE)
                    ?.let { runCatching { IpMode.valueOf(it) }.getOrNull() }
                    ?: IpMode.AUTO,
                mtu = intent.getIntExtra(VpnRuntimeContract.EXTRA_MTU, 1500),
                profileGeneration = intent.getLongExtra(
                    VpnRuntimeContract.EXTRA_PROFILE_GENERATION,
                    0,
                ),
                planDigest = intent.getStringExtra(VpnRuntimeContract.EXTRA_PLAN_DIGEST),
                profileFingerprint = intent.getStringExtra(
                    VpnRuntimeContract.EXTRA_PROFILE_FINGERPRINT,
                ),
                strategyFingerprint = intent.getStringExtra(
                    VpnRuntimeContract.EXTRA_STRATEGY_FINGERPRINT,
                ),
                relayFingerprint = intent.getStringExtra(
                    VpnRuntimeContract.EXTRA_RELAY_FINGERPRINT,
                ),
            )
        }
    }

    init {
        ContextCompat.registerReceiver(
            context,
            receiver,
            IntentFilter(VpnRuntimeContract.ACTION_STATUS),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        context.sendBroadcast(
            Intent(VpnRuntimeContract.ACTION_QUERY_STATUS).setPackage(context.packageName),
        )
    }

    fun prepareIntent(): Intent? {
        val intent = VpnService.prepare(context)
        mutableSnapshot.value = VpnRuntimeSnapshot(
            if (intent == null) VpnRuntimeState.PREPARING else VpnRuntimeState.AWAITING_VPN_CONSENT,
        )
        return intent
    }

    fun permissionRejected() {
        clearStagedAuthority()
        mutableSnapshot.value = VpnRuntimeSnapshot(
            state = VpnRuntimeState.FAILED,
            failure = "CONSENT_REJECTED",
        )
    }

    fun notificationPermissionRejected() {
        clearStagedAuthority()
        mutableSnapshot.value = VpnRuntimeSnapshot(
            state = VpnRuntimeState.FAILED,
            failure = "NOTIFICATION_PERMISSION_REJECTED",
        )
    }

    fun stageAuthority(encoded: ByteArray) {
        require(encoded.isNotEmpty()) { "MISSING_VERIFIED_AUTHORITY" }
        clearStagedAuthority()
        stagedAuthority = encoded
        mutableSnapshot.value = VpnRuntimeSnapshot(VpnRuntimeState.PREPARING)
    }

    fun authorityRejected(category: String) {
        clearStagedAuthority()
        mutableSnapshot.value = VpnRuntimeSnapshot(
            state = VpnRuntimeState.FAILED,
            failure = category.take(64),
        )
    }

    fun startStaged() {
        val authority = stagedAuthority
        stagedAuthority = null
        if (authority == null) {
            authorityRejected("MISSING_VERIFIED_AUTHORITY")
            return
        }
        mutableSnapshot.value = VpnRuntimeSnapshot(VpnRuntimeState.CONNECTING)
        runCatching {
            KurdVpnService.start(context, authority, handoffExecutor) { category ->
                mutableSnapshot.value = VpnRuntimeSnapshot(
                    state = VpnRuntimeState.FAILED,
                    failure = category.take(64),
                )
            }
        }.onFailure {
            authority.fill(0)
            mutableSnapshot.value = VpnRuntimeSnapshot(
                state = VpnRuntimeState.FAILED,
                failure = "RUNTIME_START_FAILED",
            )
        }
    }

    fun stop() {
        val current = mutableSnapshot.value
        if (
            current.state == VpnRuntimeState.IDLE ||
            current.state == VpnRuntimeState.AWAITING_VPN_CONSENT ||
            current.state == VpnRuntimeState.BLOCKED ||
            current.state == VpnRuntimeState.REVOKED ||
            current.state == VpnRuntimeState.FAILED
        ) {
            // A terminal or not-yet-started controller must not create the VPN
            // service merely to stop it. stopService is idempotent and also closes
            // any narrow teardown race without creating a new foreground-service
            // obligation.
            context.stopService(Intent(context, KurdVpnService::class.java))
            mutableSnapshot.value = VpnRuntimeSnapshot(VpnRuntimeState.IDLE)
            return
        }
        mutableSnapshot.value = current.copy(state = VpnRuntimeState.STOPPING)
        KurdVpnService.stop(context)
    }

    override fun close() {
        clearStagedAuthority()
        handoffExecutor.shutdownNow()
        runCatching { context.unregisterReceiver(receiver) }
    }

    private fun clearStagedAuthority() {
        stagedAuthority?.fill(0)
        stagedAuthority = null
    }
}
