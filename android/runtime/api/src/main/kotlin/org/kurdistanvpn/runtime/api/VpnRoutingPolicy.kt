// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.api

enum class PerAppRoutingMode {
    ALL_APPS,
    INCLUDE_ONLY,
    EXCLUDE_SELECTED,
}

data class VpnRoutingPolicy(
    val perAppMode: PerAppRoutingMode = PerAppRoutingMode.ALL_APPS,
    val packages: Set<String> = emptySet(),
) {
    fun validate(): VpnRoutingPolicy {
        require(packages.size <= MAX_PACKAGES) { "too many per-app rules" }
        require(packages.all(::isValidPackageName)) { "invalid package name" }
        when (perAppMode) {
            PerAppRoutingMode.ALL_APPS ->
                require(packages.isEmpty()) { "all-apps mode cannot list packages" }
            PerAppRoutingMode.INCLUDE_ONLY ->
                require(packages.isNotEmpty()) { "include-only mode requires packages" }
            PerAppRoutingMode.EXCLUDE_SELECTED -> Unit
        }
        return copy(packages = packages.toSortedSet())
    }

    private fun isValidPackageName(value: String): Boolean =
        value.length in 3..MAX_PACKAGE_NAME_LENGTH &&
            value.split('.').size >= 2 &&
            value.split('.').all { segment ->
                segment.isNotEmpty() &&
                    (segment.first().isLetter() || segment.first() == '_') &&
                    segment.all { it.isLetterOrDigit() || it == '_' }
            }

    companion object {
        const val MAX_PACKAGES = 64
        const val MAX_PACKAGE_NAME_LENGTH = 255
    }
}
