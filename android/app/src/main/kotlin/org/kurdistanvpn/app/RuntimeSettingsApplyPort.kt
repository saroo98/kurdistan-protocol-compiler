// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import kotlinx.coroutines.*
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.data.settings.*
import org.kurdistanvpn.runtime.api.*
import org.kurdistanvpn.runtime.android.RuntimeControlBinder

/** Serial draft transaction adapter. A lifecycle ticket never substitutes for fresh native authority. */
internal class RuntimeSettingsApplyPort(
    private val transition: suspend (Int, String?) -> String?,
    private val status: suspend () -> VpnRuntimeSnapshot,
    private val platformApi: Int = android.os.Build.VERSION.SDK_INT,
    private val retainOwner: suspend () -> Unit = {},
    private val releaseOwner: () -> Unit = {},
) : SettingsRuntimePort {
    private var ticket: String? = null
    private val retained = java.util.concurrent.atomic.AtomicBoolean(false)
    override suspend fun validate(previous: org.kurdistanvpn.core.model.ProductSettings,
        requested: org.kurdistanvpn.core.model.ProductSettings): SettingsPortResult<Unit> =
        if (platformApi < 29 && previous.tunnel.metered != requested.tunnel.metered)
            SettingsPortResult.Rejected(ProductFailureCode.INVALID_INPUT)
        else SettingsPortResult.Success(Unit)
    override suspend fun prepare(): SettingsPortResult<SettingsRuntimeIntent> {
        if (!retained.compareAndSet(false, true)) return SettingsPortResult.Rejected(ProductFailureCode.OPERATION_ALREADY_ACTIVE)
        try {
            retainOwner()
            val before = status()
            if (before.state == VpnRuntimeState.IDLE) return SettingsPortResult.Success(SettingsRuntimeIntent.ALREADY_STOPPED)
            // Degraded is still a live session. The service guard, not display health, authorizes teardown.
            if (before.state != VpnRuntimeState.ACTIVE_KURD_LIVE && before.state != VpnRuntimeState.DEGRADED) {
                finish(); return SettingsPortResult.Rejected(ProductFailureCode.OPERATION_ALREADY_ACTIVE)
            }
            ticket = transition(RuntimeControlBinder.SETTINGS_PREPARE, null)
            if (ticket == null) { finish(); return SettingsPortResult.Rejected(ProductFailureCode.OPERATION_INTERRUPTED) }
            if (awaitIdle()) return SettingsPortResult.Success(SettingsRuntimeIntent.RECONNECT_ONCE)
            finish()
            return SettingsPortResult.Rejected(ProductFailureCode.OPERATION_INTERRUPTED)
        } catch (cancelled: CancellationException) { withContext(NonCancellable) { finish() }; throw cancelled }
        catch (_: Exception) { finish(); return SettingsPortResult.Rejected(ProductFailureCode.INTERNAL_FAILURE) }
    }
    override suspend fun apply(intent: SettingsRuntimeIntent, committed: SettingsStoreState) = reconnect(intent, committed)
    override suspend fun restore(intent: SettingsRuntimeIntent, restoredState: SettingsStoreState) = reconnect(intent, restoredState)

    private suspend fun reconnect(intent: SettingsRuntimeIntent, committed: SettingsStoreState): SettingsPortResult<Unit> {
        if (intent == SettingsRuntimeIntent.ALREADY_STOPPED) return SettingsPortResult.Success(Unit)
        val lease = ticket ?: return SettingsPortResult.Rejected(ProductFailureCode.OPERATION_INTERRUPTED)
        var success = false
        try {
            if (transition(RuntimeControlBinder.SETTINGS_STOP, lease) == null || !awaitIdle())
                return SettingsPortResult.Rejected(ProductFailureCode.OPERATION_INTERRUPTED)
            val request = transition(RuntimeControlBinder.SETTINGS_RESUME, lease)
                ?: return SettingsPortResult.Rejected(ProductFailureCode.OPERATION_INTERRUPTED)
            val applied = withTimeoutOrNull(30_000) {
                while (true) {
                    val snapshot = status()
                    if (snapshot.runtimeRequestId == request && snapshot.state == VpnRuntimeState.ACTIVE_KURD_LIVE)
                        return@withTimeoutOrNull snapshot.appliedRevision == committed.journalRevision
                    if (snapshot.state in setOf(VpnRuntimeState.FAILED, VpnRuntimeState.BLOCKED, VpnRuntimeState.REVOKED))
                        return@withTimeoutOrNull false
                    if (snapshot.state == VpnRuntimeState.ACTIVE_KURD_LIVE && snapshot.runtimeRequestId != request)
                        return@withTimeoutOrNull false
                    delay(25)
                }
                @Suppress("UNREACHABLE_CODE") false
            } == true
            success = applied
            return if (applied) SettingsPortResult.Success(Unit)
                else SettingsPortResult.Rejected(ProductFailureCode.TUN_ESTABLISH_FAILED)
        } finally {
            if (!success) withContext(NonCancellable) {
                // A revoked continuation may not stop a newer user-owned session.
                if (transition(RuntimeControlBinder.SETTINGS_STOP, lease) != null) awaitIdle()
            }
        }
    }
    private suspend fun awaitIdle(): Boolean = withTimeoutOrNull(15_000) {
        while (true) {
            when (status().state) {
                VpnRuntimeState.IDLE -> return@withTimeoutOrNull true
                VpnRuntimeState.BLOCKED, VpnRuntimeState.REVOKED, VpnRuntimeState.FAILED -> return@withTimeoutOrNull false
                else -> delay(25)
            }
        }
        @Suppress("UNREACHABLE_CODE") false
    } == true
    override suspend fun finish() {
        val lease = ticket
        ticket = null
        try {
            if (lease != null) try { transition(RuntimeControlBinder.SETTINGS_FINISH, lease) } catch (_: Exception) { }
        } finally { if (retained.compareAndSet(true, false)) releaseOwner() }
    }
}
