// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.navigation3.runtime.NavKey
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName
import org.kurdistanvpn.core.model.CatalogId

/** Restorable location only. Route identity never grants permission or runtime authority. */
@Serializable
sealed interface ProductDestination : NavKey {
    @Serializable @SerialName("p18-s01")
    data object Welcome : ProductDestination

    @Serializable @SerialName("p18-s02")
    data object ImportSource : ProductDestination

    @Serializable @SerialName("p18-s03")
    data class FirstTrust(val importId: String) : ProductDestination {
        init { CatalogId(importId) }
    }

    @Serializable @SerialName("p18-s04")
    data object VpnPermissionEducation : ProductDestination

    @Serializable @SerialName("p18-s05")
    data object Home : ProductDestination

    @Serializable @SerialName("p18-s06")
    data class RouteDetail(val sessionAlias: String) : ProductDestination {
        init { CatalogId(sessionAlias) }
    }

    @Serializable @SerialName("p18-s07")
    data object Profiles : ProductDestination

    @Serializable @SerialName("p18-s08")
    data class DeploymentDetail(val deploymentId: String) : ProductDestination {
        init { CatalogId(deploymentId) }
    }

    @Serializable @SerialName("p18-s09")
    data class ProfileDetail(val profileId: String) : ProductDestination {
        init { CatalogId(profileId) }
    }

    @Serializable @SerialName("p18-s10")
    data class StrategyMatrix(val profileId: String) : ProductDestination {
        init { CatalogId(profileId) }
    }

    @Serializable @SerialName("p18-s11")
    data class ProbeHistory(val profileId: String) : ProductDestination {
        init { CatalogId(profileId) }
    }

    @Serializable @SerialName("p18-s12")
    data object Settings : ProductDestination

    @Serializable @SerialName("p18-s13")
    data object ConnectionPermissions : ProductDestination

    @Serializable @SerialName("p18-s14")
    data object TrustedNetworks : ProductDestination

    @Serializable @SerialName("p18-s15")
    data object PerAppRouting : ProductDestination

    @Serializable @SerialName("p18-s16")
    data object ExcludedRoutes : ProductDestination

    @Serializable @SerialName("p18-s17")
    data object TunnelDns : ProductDestination

    @Serializable @SerialName("p18-s18")
    data object LocalProxy : ProductDestination

    @Serializable @SerialName("p18-s19")
    data object UpdatesProbes : ProductDestination

    @Serializable @SerialName("p18-s20")
    data object AppearanceAccessibility : ProductDestination

    @Serializable @SerialName("p18-s21")
    data object PrivacyAppLock : ProductDestination

    @Serializable @SerialName("p18-s22")
    data object BackupCreation : ProductDestination

    @Serializable @SerialName("p18-s23")
    data class RestorePreview(val operationId: String) : ProductDestination {
        init { CatalogId(operationId) }
    }

    @Serializable @SerialName("p18-s24")
    data class TransferExport(val profileId: String) : ProductDestination {
        init { CatalogId(profileId) }
    }

    @Serializable @SerialName("p18-s25")
    data object RecoveryCenter : ProductDestination

    @Serializable @SerialName("p18-s26")
    data object ScopedReset : ProductDestination

    @Serializable @SerialName("p18-s27")
    data object Diagnostics : ProductDestination

    @Serializable @SerialName("p18-s28")
    data class DiagnosticExport(val operationId: String) : ProductDestination {
        init { CatalogId(operationId) }
    }

    @Serializable @SerialName("p18-s29")
    data object Troubleshooting : ProductDestination

    @Serializable @SerialName("p18-s30")
    data object NotificationsPerformance : ProductDestination

    @Serializable @SerialName("p18-s31")
    data object ExpertControls : ProductDestination

    @Serializable @SerialName("p18-s32")
    data object Automation : ProductDestination

    @Serializable @SerialName("p18-s33")
    data object About : ProductDestination

    @Serializable @SerialName("p18-s34")
    data object Legal : ProductDestination
}

internal enum class ProductPrimary { HOME, PROFILES, SETTINGS, ONBOARDING }

internal val ProductPrimary.savedId: String
    get() = when (this) {
        ProductPrimary.HOME -> "p18-s05"
        ProductPrimary.PROFILES -> "p18-s07"
        ProductPrimary.SETTINGS -> "p18-s12"
        ProductPrimary.ONBOARDING -> "p18-s01"
    }

internal val ProductDestination.primary: ProductPrimary
    get() = when (this) {
        ProductDestination.Welcome -> ProductPrimary.ONBOARDING
        ProductDestination.ImportSource -> ProductPrimary.ONBOARDING
        is ProductDestination.FirstTrust -> ProductPrimary.ONBOARDING
        ProductDestination.VpnPermissionEducation -> ProductPrimary.ONBOARDING
        ProductDestination.Home -> ProductPrimary.HOME
        is ProductDestination.RouteDetail -> ProductPrimary.HOME
        ProductDestination.Profiles -> ProductPrimary.PROFILES
        is ProductDestination.DeploymentDetail -> ProductPrimary.PROFILES
        is ProductDestination.ProfileDetail -> ProductPrimary.PROFILES
        is ProductDestination.StrategyMatrix -> ProductPrimary.PROFILES
        is ProductDestination.ProbeHistory -> ProductPrimary.PROFILES
        ProductDestination.Settings -> ProductPrimary.SETTINGS
        ProductDestination.ConnectionPermissions -> ProductPrimary.SETTINGS
        ProductDestination.TrustedNetworks -> ProductPrimary.SETTINGS
        ProductDestination.PerAppRouting -> ProductPrimary.SETTINGS
        ProductDestination.ExcludedRoutes -> ProductPrimary.SETTINGS
        ProductDestination.TunnelDns -> ProductPrimary.SETTINGS
        ProductDestination.LocalProxy -> ProductPrimary.SETTINGS
        ProductDestination.UpdatesProbes -> ProductPrimary.SETTINGS
        ProductDestination.AppearanceAccessibility -> ProductPrimary.SETTINGS
        ProductDestination.PrivacyAppLock -> ProductPrimary.SETTINGS
        ProductDestination.BackupCreation -> ProductPrimary.SETTINGS
        is ProductDestination.RestorePreview -> ProductPrimary.SETTINGS
        is ProductDestination.TransferExport -> ProductPrimary.PROFILES
        ProductDestination.RecoveryCenter -> ProductPrimary.SETTINGS
        ProductDestination.ScopedReset -> ProductPrimary.SETTINGS
        ProductDestination.Diagnostics -> ProductPrimary.SETTINGS
        is ProductDestination.DiagnosticExport -> ProductPrimary.SETTINGS
        ProductDestination.Troubleshooting -> ProductPrimary.SETTINGS
        ProductDestination.NotificationsPerformance -> ProductPrimary.SETTINGS
        ProductDestination.ExpertControls -> ProductPrimary.SETTINGS
        ProductDestination.Automation -> ProductPrimary.SETTINGS
        ProductDestination.About -> ProductPrimary.SETTINGS
        ProductDestination.Legal -> ProductPrimary.SETTINGS
    }

internal val ProductPrimary.root: ProductDestination
    get() = when (this) {
        ProductPrimary.HOME -> ProductDestination.Home
        ProductPrimary.PROFILES -> ProductDestination.Profiles
        ProductPrimary.SETTINGS -> ProductDestination.Settings
        ProductPrimary.ONBOARDING -> ProductDestination.Welcome
    }
