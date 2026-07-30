// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.kurdistanvpn.runtime.android.KurdVpnService
import org.kurdistanvpn.runtime.api.PerAppRoutingMode
import org.kurdistanvpn.runtime.api.VpnRuntimeContract
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeState
import org.kurdistanvpn.runtime.api.VpnRoutingPolicy

class VpnRuntimeController(
    private val context: Context,
) : AutoCloseable {
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
        mutableSnapshot.value = VpnRuntimeSnapshot(VpnRuntimeState.PREPARING)
        return VpnService.prepare(context)
    }

    fun permissionRejected() {
        mutableSnapshot.value = VpnRuntimeSnapshot(
            state = VpnRuntimeState.FAILED,
            failure = "CONSENT_REJECTED",
        )
    }

    fun notificationPermissionRejected() {
        mutableSnapshot.value = VpnRuntimeSnapshot(
            state = VpnRuntimeState.FAILED,
            failure = "NOTIFICATION_PERMISSION_REJECTED",
        )
    }

    fun start(
        policy: VpnRoutingPolicy = VpnRoutingPolicy(
            perAppMode = PerAppRoutingMode.INCLUDE_ONLY,
            packages = setOf(context.packageName),
        ),
    ) {
        KurdVpnService.start(context, policy)
    }

    fun stop() {
        mutableSnapshot.value = mutableSnapshot.value.copy(state = VpnRuntimeState.STOPPING)
        KurdVpnService.stop(context)
    }

    override fun close() {
        runCatching { context.unregisterReceiver(receiver) }
    }
}
