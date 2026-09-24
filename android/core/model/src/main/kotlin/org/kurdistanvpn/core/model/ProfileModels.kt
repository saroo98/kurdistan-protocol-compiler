// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.model

/** An already-redacted display alias. Not a parser or sanitizer for endpoint/authority material. */
data class SafeAlias(val value: String) {
    init { require(value.length in 1..96 && value == value.trim() && value.all { it.isLetterOrDigit() || it in " -_" }) }
    override fun toString(): String = "SafeAlias(redacted)"
}

data class NodeProjection(val status: ProjectionStatus = ProjectionStatus.UNAVAILABLE, val id: CatalogId? = null, val alias: SafeAlias? = null) {
    init { require(status != ProjectionStatus.UNAVAILABLE || (id == null && alias == null)); require(status != ProjectionStatus.VERIFIED || id != null || alias != null) }
}
data class StrategyProjection(val status: ProjectionStatus = ProjectionStatus.UNAVAILABLE, val id: CatalogId? = null, val alias: SafeAlias? = null) {
    init { require(status != ProjectionStatus.UNAVAILABLE || (id == null && alias == null)); require(status != ProjectionStatus.VERIFIED || id != null || alias != null) }
}
data class PathProjection(val status: ProjectionStatus = ProjectionStatus.UNAVAILABLE, val id: CatalogId? = null, val alias: SafeAlias? = null) {
    init { require(status != ProjectionStatus.UNAVAILABLE || (id == null && alias == null)); require(status != ProjectionStatus.VERIFIED || id != null || alias != null) }
}
enum class ExitRegion { UNKNOWN, EUROPE, ASIA, AFRICA, NORTH_AMERICA, SOUTH_AMERICA, OCEANIA }
data class ExitProjection(val status: ProjectionStatus = ProjectionStatus.UNAVAILABLE, val region: ExitRegion = ExitRegion.UNKNOWN) {
    init { require(status != ProjectionStatus.UNAVAILABLE || region == ExitRegion.UNKNOWN); require(status != ProjectionStatus.VERIFIED || region != ExitRegion.UNKNOWN) }
}
enum class HealthCategory { UNKNOWN, HEALTHY, DEGRADED, UNREACHABLE }
data class HealthProjection(val status: ProjectionStatus = ProjectionStatus.UNAVAILABLE, val category: HealthCategory = HealthCategory.UNKNOWN) {
    init { require(status != ProjectionStatus.UNAVAILABLE || category == HealthCategory.UNKNOWN); require(status != ProjectionStatus.VERIFIED || category != HealthCategory.UNKNOWN) }
}
enum class UpdateCategory { NOT_CHECKED, UNCHANGED, AVAILABLE, REJECTED }
data class DeploymentProjection(
    val alias: SafeAlias,
    val publicationGeneration: ULong? = null,
    val profileGeneration: ULong? = null,
    val profileExpiryEpochSeconds: Long? = null,
    val relayCompatibility: ProjectionStatus = ProjectionStatus.UNAVAILABLE,
    val rotationState: ProjectionStatus = ProjectionStatus.UNAVAILABLE,
    val emergencyDenyState: ProjectionStatus = ProjectionStatus.UNAVAILABLE,
    val update: UpdateProjection = UpdateProjection(),
    val node: NodeProjection = NodeProjection(),
    val strategy: StrategyProjection = StrategyProjection(),
    val path: PathProjection = PathProjection(),
    val exit: ExitProjection = ExitProjection(),
    val health: HealthProjection = HealthProjection(),
) {
    init {
        require(profileExpiryEpochSeconds == null || profileExpiryEpochSeconds >= 0)
        require((profileGeneration == null) == (profileExpiryEpochSeconds == null))
    }
}
data class UpdateProjection(val status: ProjectionStatus = ProjectionStatus.UNAVAILABLE, val category: UpdateCategory = UpdateCategory.NOT_CHECKED, val changeCount: Int = 0) {
    init { require(changeCount in 0..1024); require(status != ProjectionStatus.UNAVAILABLE || (category == UpdateCategory.NOT_CHECKED && changeCount == 0)) }
}
data class ProfileProjection(val id: CatalogId, val alias: SafeAlias, val generation: ULong, val expiresAtEpochSeconds: Long, val status: ProjectionStatus) {
    init { require(expiresAtEpochSeconds >= 0) }
}

/** Opaque, canonical local/catalog identity. Never an endpoint or native authority handle. */
data class CatalogId(val value: String) {
    init { require(value.matches(Regex("[a-z0-9][a-z0-9-]{0,63}"))) }
    override fun toString(): String = "CatalogId(redacted)"
}

sealed interface StrategySelection {
    data object Automatic : StrategySelection
    data object KurdOnly : StrategySelection
    data class Manual(val id: CatalogId) : StrategySelection {
        fun validatedAgainst(signed: Set<CatalogId>, native: Set<CatalogId>): Manual {
            require(signed.size <= 256 && native.size <= 256)
            require(id in signed && id in native)
            return this
        }
    }
}
