// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.SystemClock
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.kurdistanvpn.runtime.android.KurdVpnService
import org.kurdistanvpn.runtime.api.PerAppRoutingMode
import org.kurdistanvpn.runtime.api.VpnRuntimeContract
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeDiagnostics
import org.kurdistanvpn.runtime.api.VpnRuntimeState
import org.kurdistanvpn.runtime.api.validatedForDisplay
import org.kurdistanvpn.core.model.DnsMode
import org.kurdistanvpn.core.model.IpMode

/** UI lifecycle staging only. No authority or retry budget is retained in the app process. */
internal class ManualStartAdmission : AutoCloseable {
    private var generation = 0L
    private var staged: Long? = null
    private var closed = false
    @Synchronized fun stage(): Long {
        check(!closed && generation < Long.MAX_VALUE) { "MANUAL_START_UNAVAILABLE" }
        return (++generation).also { staged = it }
    }
    @Synchronized fun consume(): Long? = staged.also { staged = null }.takeIf { !closed }
    @Synchronized fun isCurrent(value: Long): Boolean = !closed && value > 0 && generation == value
    @Synchronized fun cancel() {
        staged = null
        if (generation == Long.MAX_VALUE) closed = true else generation++
    }
    @Synchronized override fun close() { closed = true; staged = null }
}

class VpnRuntimeController(private val context: Context) : AutoCloseable {
    private val startScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val admission = ManualStartAdmission()
    private val startLock = Any()
    private var pendingStart: Job? = null
    private var closed = false
    private var lastStatusQueryAt = Long.MIN_VALUE
    @Volatile private var activeRequestId: String? = null
    @Volatile private var pendingStatusQueryId: String? = null
    private val mutableSnapshot = MutableStateFlow(VpnRuntimeSnapshot())
    val snapshot: StateFlow<VpnRuntimeSnapshot> = mutableSnapshot.asStateFlow()
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != VpnRuntimeContract.ACTION_STATUS) return
            val decision = selectRuntimeStatus(
                    expectedRequestId = activeRequestId,
                    pendingQueryId = pendingStatusQueryId,
                    incomingRequestId = intent.getStringExtra(
                        VpnRuntimeContract.EXTRA_RUNTIME_REQUEST,
                    ),
                    incomingQueryId = intent.getStringExtra(
                        VpnRuntimeContract.EXTRA_STATUS_QUERY,
                    ),
                )
            if (!decision.accept) {
                // A signed-limit retry has a fresh authority request ID. Do not trust an
                // unmatched broadcast as status; obtain a new correlated service snapshot.
                if (intent.getStringExtra(VpnRuntimeContract.EXTRA_STATUS_QUERY) == null) queryStatus()
                return
            }
            if (decision.consumeQuery) pendingStatusQueryId = null
            decision.bindRequestId?.let { activeRequestId = it }
            val incomingRequestId = intent.getStringExtra(
                VpnRuntimeContract.EXTRA_RUNTIME_REQUEST,
            )
            val state = intent.getStringExtra(VpnRuntimeContract.EXTRA_STATE)
                ?.let { runCatching { VpnRuntimeState.valueOf(it) }.getOrNull() }
                ?: VpnRuntimeState.FAILED
            acceptSnapshot(VpnRuntimeSnapshot(
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
                maxReconnectAttempts = intent.getIntExtra(
                    VpnRuntimeContract.EXTRA_MAX_RECONNECT_ATTEMPTS,
                    0,
                ),
                runtimeRequestId = incomingRequestId,
                diagnostics = VpnRuntimeDiagnostics(
                    tunPacketsRead = intent.getLongExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_TUN_READ, 0),
                    outboundPacketsAccepted = intent.getLongExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_OUTBOUND, 0),
                    carrierRecordsWritten = intent.getLongExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_CARRIER_WRITE, 0),
                    carrierRecordsRead = intent.getLongExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_CARRIER_READ, 0),
                    authenticatedOperations = intent.getLongExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_AUTHENTICATED, 0),
                    innerPacketsAccepted = intent.getLongExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_INNER_ACCEPTED, 0),
                    innerPacketsRejected = intent.getLongExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_INNER_REJECTED, 0),
                    tunWriteAttempts = intent.getLongExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_TUN_ATTEMPTS, 0),
                    tunWriteFailures = intent.getLongExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_TUN_FAILURES, 0),
                    tunWriteFailureCode = intent.getLongExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_TUN_FAILURE_CODE, 0),
                    tunWriteErrno = intent.getLongExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_TUN_ERRNO, 0),
                    tunPacketsWritten = intent.getLongExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_TUN_WRITTEN, 0),
                    rejectedTunPackets = intent.getLongExtra(VpnRuntimeContract.EXTRA_DIAGNOSTIC_REJECTED, 0),
                    rejectedTunPacketCode = intent.getLongExtra(
                        VpnRuntimeContract.EXTRA_DIAGNOSTIC_REJECTION_CODE,
                        0,
                    ),
                ),
            ))
            activeRequestId = activeRequestIdAfterRuntimeStatus(
                activeRequestId = activeRequestId,
                incomingRequestId = incomingRequestId,
                state = state,
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
        queryStatus()
    }


    fun prepareIntent(): Intent? {
        val intent = VpnService.prepare(context)
        mutableSnapshot.value = VpnRuntimeSnapshot(
            if (intent == null) VpnRuntimeState.PREPARING else VpnRuntimeState.AWAITING_VPN_CONSENT)
        return intent
    }
    fun permissionRejected() = authorityRejected("CONSENT_REJECTED")
    fun notificationPermissionRejected() = authorityRejected("NOTIFICATION_PERMISSION_REJECTED")

    fun stageManualStart() {
        synchronized(startLock) {
            pendingStart?.cancel(); pendingStart = null
            admission.stage()
        }
        mutableSnapshot.value = VpnRuntimeSnapshot(VpnRuntimeState.PREPARING)
    }

    fun authorityRejected(category: String) {
        cancelPendingStart()
        activeRequestId = null
        mutableSnapshot.value = VpnRuntimeSnapshot(state = VpnRuntimeState.FAILED,
            failure = category.takeIf { it.length <= 64 && it.all { ch -> ch in 'A'..'Z' || ch == '_' || ch in '0'..'9' } }
                ?: "RUNTIME_START_REJECTED")
    }

    fun startStaged() {
        val generation = admission.consume()
        if (generation == null) { authorityRejected("MISSING_USER_START"); return }
        mutableSnapshot.value = VpnRuntimeSnapshot(VpnRuntimeState.PREPARING)
        val job = startScope.launch(start = CoroutineStart.LAZY) {
            try {
                val connectivity = context.getSystemService(ConnectivityManager::class.java)
                val ready = VpnNetworkTeardownBarrier.awaitNoRegisteredVpn(
                    timeoutMillis = VPN_NETWORK_TEARDOWN_TIMEOUT_MILLIS,
                    pollMillis = VPN_NETWORK_POLL_MILLIS,
                    vpnTransportSnapshot = { VpnNetworkTeardownBarrier.snapshot(connectivity) })
                synchronized(startLock) {
                    if (!admission.isCurrent(generation)) return@synchronized
                    if (!ready) {
                        acceptSnapshot(VpnRuntimeSnapshot(state = VpnRuntimeState.FAILED, failure = "VPN_NETWORK_TEARDOWN_TIMEOUT"))
                    } else if (VpnService.prepare(context) != null) {
                        acceptSnapshot(VpnRuntimeSnapshot(state = VpnRuntimeState.FAILED, failure = "CONSENT_REJECTED"))
                    } else {
                        val requestId = KurdVpnService.newRequestId()
                        pendingStatusQueryId = null; activeRequestId = requestId
                        mutableSnapshot.value = VpnRuntimeSnapshot(VpnRuntimeState.CONNECTING, runtimeRequestId = requestId)
                        KurdVpnService.start(context, requestId)
                    }
                }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Throwable) {
                if (admission.isCurrent(generation)) acceptSnapshot(VpnRuntimeSnapshot(
                    state = VpnRuntimeState.FAILED, failure = "RUNTIME_START_FAILED"))
            } finally {
                synchronized(startLock) { if (admission.isCurrent(generation)) pendingStart = null }
            }
        }
        synchronized(startLock) {
            if (!admission.isCurrent(generation)) { job.cancel(); return }
            pendingStart = job
        }
        job.start()
    }

    fun stop() {
        cancelPendingStart()
        val current = mutableSnapshot.value
        if (activeRequestId == null && current.state in setOf(VpnRuntimeState.IDLE, VpnRuntimeState.AWAITING_VPN_CONSENT,
                VpnRuntimeState.BLOCKED, VpnRuntimeState.REVOKED, VpnRuntimeState.FAILED)) {
            context.stopService(Intent(context, KurdVpnService::class.java))
            mutableSnapshot.value = VpnRuntimeSnapshot(VpnRuntimeState.IDLE)
        } else {
            mutableSnapshot.value = current.copy(state = VpnRuntimeState.STOPPING)
            KurdVpnService.stop(context)
        }
    }

    override fun close() {
        synchronized(startLock) { if (closed) return; closed = true }
        cancelPendingStart(); admission.close(); startScope.cancel()
        context.unregisterReceiver(receiver)
        // Activity death does not stop a valid system-owned always-on session.
    }
    private fun queryStatus() = synchronized(startLock) {
        val now = SystemClock.elapsedRealtime()
        if (closed || (lastStatusQueryAt != Long.MIN_VALUE && now - lastStatusQueryAt in 0..999)) return@synchronized
        lastStatusQueryAt = now
        val queryId = KurdVpnService.newRequestId()
        pendingStatusQueryId = queryId
        context.sendBroadcast(Intent(VpnRuntimeContract.ACTION_QUERY_STATUS).setPackage(context.packageName)
            .putExtra(VpnRuntimeContract.EXTRA_STATUS_QUERY, queryId))
    }
    private fun cancelPendingStart() = synchronized(startLock) {
        admission.cancel(); pendingStart?.cancel(); pendingStart = null
    }
    private fun acceptSnapshot(value: VpnRuntimeSnapshot) { mutableSnapshot.value = value.validatedForDisplay() }
    private companion object {
        const val VPN_NETWORK_TEARDOWN_TIMEOUT_MILLIS = 15_000L
        const val VPN_NETWORK_POLL_MILLIS = 50L
    }
}

/** The service now emits terminal failure only after its signed retry budget is settled. */
internal fun isTerminalInitialRuntimeOutcome(snapshot: VpnRuntimeSnapshot): Boolean = snapshot.state in setOf(
    VpnRuntimeState.ACTIVE_KURD_LIVE, VpnRuntimeState.REVOKED, VpnRuntimeState.IDLE,
    VpnRuntimeState.STOPPING, VpnRuntimeState.FAILED, VpnRuntimeState.BLOCKED)
