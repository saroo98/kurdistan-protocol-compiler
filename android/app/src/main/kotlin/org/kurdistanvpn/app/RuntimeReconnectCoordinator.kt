// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeState

internal sealed interface FreshRuntimeAuthority {
    class Ready(val encoded: ByteArray) : FreshRuntimeAuthority
    data class Rejected(val failure: String) : FreshRuntimeAuthority
}

internal fun interface FreshRuntimeAuthorityProvider {
    suspend fun prepare(): FreshRuntimeAuthority
}

internal class RuntimeReconnectCoordinator(
    private val scope: CoroutineScope,
    private val policy: RuntimeReconnectPolicy = RuntimeReconnectPolicy(),
    private val wait: suspend (Long) -> Unit = { delay(it) },
    private val publish: (VpnRuntimeSnapshot) -> Unit,
    private val restart: (ByteArray) -> Unit,
) {
    private var generation = 0L
    private var provider: FreshRuntimeAuthorityProvider? = null
    private var pending: Job? = null
    private var lastTerminalRequestId: String? = null

    val attempts: Int
        @Synchronized get() = policy.attempts

    @Synchronized
    fun begin(authorityProvider: FreshRuntimeAuthorityProvider) {
        cancelLocked()
        policy.reset()
        provider = authorityProvider
        lastTerminalRequestId = null
    }

    fun observe(snapshot: VpnRuntimeSnapshot) {
        val failureToPublish = synchronized(this) {
            if (
                snapshot.state != VpnRuntimeState.BLOCKED &&
                snapshot.state != VpnRuntimeState.FAILED &&
                snapshot.state != VpnRuntimeState.REVOKED
            ) {
                return
            }
            if (snapshot.state == VpnRuntimeState.REVOKED) {
                cancelLocked()
                return
            }
            if (provider == null) return
            if (!isRetryableRuntimeFailure(snapshot.failure)) {
                cancelLocked()
                return
            }
            val requestId = snapshot.runtimeRequestId
            if (requestId.isNullOrBlank()) {
                cancelLocked()
                return@synchronized "RECONNECT_POLICY_REJECTED"
            }
            if (requestId == lastTerminalRequestId) return
            lastTerminalRequestId = requestId
            if (snapshot.maxReconnectAttempts !in 1..MAX_SIGNED_RECONNECT_ATTEMPTS) {
                cancelLocked()
                return@synchronized "RECONNECT_POLICY_REJECTED"
            }
            if (pending?.isActive == true) return
            val delayMillis = policy.nextDelayMillis(
                snapshot.maxReconnectAttempts,
                snapshot.failure,
            ) ?: run {
                cancelLocked()
                return@synchronized "RECONNECT_EXHAUSTED"
            }
            scheduleLocked(delayMillis, snapshot.maxReconnectAttempts)
            null
        }
        failureToPublish?.let { failure ->
            publish(
                VpnRuntimeSnapshot(
                    state = VpnRuntimeState.FAILED,
                    failure = failure,
                ),
            )
        }
    }

    @Synchronized
    fun cancel() {
        cancelLocked()
        policy.reset()
        lastTerminalRequestId = null
    }

    private fun scheduleLocked(delayMillis: Long, maxAttempts: Int) {
        val scheduledGeneration = generation
        pending = scope.launch {
            wait(delayMillis)
            val currentProvider = synchronized(this@RuntimeReconnectCoordinator) {
                if (scheduledGeneration != generation) return@launch
                pending = null
                provider
            } ?: return@launch
            publish(
                VpnRuntimeSnapshot(
                    state = VpnRuntimeState.RECONNECTING,
                    maxReconnectAttempts = maxAttempts,
                ),
            )
            val prepared = runCatching { currentProvider.prepare() }
                .getOrElse { FreshRuntimeAuthority.Rejected("RUNTIME_AUTHORITY_UNAVAILABLE") }
            when (prepared) {
                is FreshRuntimeAuthority.Rejected -> {
                    val accepted = synchronized(this@RuntimeReconnectCoordinator) {
                        if (scheduledGeneration != generation) return@synchronized false
                        cancelLocked()
                        true
                    }
                    if (accepted) {
                        publish(
                            VpnRuntimeSnapshot(
                                state = VpnRuntimeState.FAILED,
                                failure = prepared.failure.take(64),
                            ),
                        )
                    }
                }
                is FreshRuntimeAuthority.Ready -> {
                    val accepted = synchronized(this@RuntimeReconnectCoordinator) {
                        if (scheduledGeneration != generation) return@synchronized false
                        runCatching { restart(prepared.encoded) }
                            .onFailure { prepared.encoded.fill(0) }
                            .isSuccess
                    }
                    if (!accepted) {
                        prepared.encoded.fill(0)
                        if (scheduledGeneration == synchronized(this@RuntimeReconnectCoordinator) { generation }) {
                            synchronized(this@RuntimeReconnectCoordinator) { cancelLocked() }
                            publish(
                                VpnRuntimeSnapshot(
                                    state = VpnRuntimeState.FAILED,
                                    failure = "RUNTIME_START_FAILED",
                                ),
                            )
                        }
                    }
                }
            }
        }
    }

    private fun cancelLocked() {
        generation++
        pending?.cancel()
        pending = null
        provider = null
    }

    private companion object {
        const val MAX_SIGNED_RECONNECT_ATTEMPTS = 5
    }
}
