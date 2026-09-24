// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativeapi

import java.nio.ByteBuffer

interface ProductionNativeMaintenance : AutoCloseable {
    fun checkSameDeploymentUpdate(request: NativeUpdateRequest, previewOutput: ByteBuffer): NativeProductResult<NativeUpdateCheck>
    fun materializeVerifiedUpdate(candidateHandle: Long, artifactOutput: ByteBuffer): NativeProductResult<Int>
    fun releaseUpdate(candidateHandle: Long): NativeProductResult<Unit>
    fun runProbe(request: NativeProbeRequest): NativeProductResult<NativeProbeResult>
    fun cancel(): NativeProductResult<Unit>
}

data class NativeUpdateRequest(val requestedTimeoutMillis: Int) { init { require(requestedTimeoutMillis in 1000..30000) } }
sealed interface NativeUpdateCheck {
    data object NoChange : NativeUpdateCheck
    data class Candidate(val candidate: NativeUpdateCandidate) : NativeUpdateCheck
}
enum class NativeDeploymentMatch { SAME_DEPLOYMENT }
enum class NativeCandidateExpiry { VALID, EXPIRING_SOON }
enum class NativeCandidateRevocation { NOT_REVOKED }
enum class NativeCandidateCompatibility { COMPATIBLE }

data class NativeUpdateChanges(val identityAuthority: Int, val endpointSet: Int, val tunnelAddressPlan: Int,
    val routePlan: Int, val dnsPlan: Int, val strategyPlan: Int, val transport: Int, val runtimeLimits: Int,
    val services: Int, val validityAuthority: Int) {
    private val values = listOf(identityAuthority, endpointSet, tunnelAddressPlan, routePlan, dnsPlan,
        strategyPlan, transport, runtimeLimits, services, validityAuthority)
    init { require(values.all { it in 0..1 }) }
    val totalChangedCategories: Int get() = values.sum()
}

class NativeUpdateCandidate(val handle: Long, val deploymentMatch: NativeDeploymentMatch, val generation: ULong,
    val expiry: NativeCandidateExpiry, val rotationFlags: Int, val revocation: NativeCandidateRevocation,
    val compatibility: NativeCandidateCompatibility, val changes: NativeUpdateChanges, val artifactLength: Int) {
    init { require(handle != 0L && generation > 0uL && rotationFlags in 0..7 && artifactLength in 1..1052763) }
    override fun toString() = "NativeUpdateCandidate(redacted)"
}
