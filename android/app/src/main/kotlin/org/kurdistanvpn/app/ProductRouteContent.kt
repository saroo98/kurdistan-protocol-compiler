// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import org.kurdistanvpn.core.ui.ProductStateContent

@Composable
internal fun ProductNavigationRecovery(onRestart: () -> Unit) {
    ProductStateContent(
        title = stringResource(R.string.navigation_restart),
        message = stringResource(R.string.navigation_recovery),
        actionLabel = stringResource(R.string.navigation_restart),
        onAction = onRestart,
    )
}

@Composable
internal fun ProductRouteUnavailable(
    destination: ProductDestination, stale: Boolean, onBack: () -> Unit, onRoot: () -> Unit,
) {
    ProductStateContent(
        title = stringResource(destination.titleResource),
        message = stringResource(if (stale) R.string.navigation_stale else R.string.navigation_planned),
        actionLabel = stringResource(org.kurdistanvpn.core.ui.R.string.back),
        onAction = onBack,
        secondaryLabel = stringResource(R.string.navigation_root),
        onSecondary = onRoot,
    )
}

internal val ProductDestination.titleResource: Int
    get() = when (this) {
        ProductDestination.Welcome -> R.string.route_title_1
        ProductDestination.ImportSource -> R.string.route_title_2
        is ProductDestination.FirstTrust -> R.string.route_title_3
        ProductDestination.VpnPermissionEducation -> R.string.route_title_4
        ProductDestination.Home -> R.string.route_title_5
        is ProductDestination.RouteDetail -> R.string.route_title_6
        ProductDestination.Profiles -> R.string.route_title_7
        is ProductDestination.DeploymentDetail -> R.string.route_title_8
        is ProductDestination.ProfileDetail -> R.string.route_title_9
        is ProductDestination.StrategyMatrix -> R.string.route_title_10
        is ProductDestination.ProbeHistory -> R.string.route_title_11
        ProductDestination.Settings -> R.string.route_title_12
        ProductDestination.ConnectionPermissions -> R.string.route_title_13
        ProductDestination.TrustedNetworks -> R.string.route_title_14
        ProductDestination.PerAppRouting -> R.string.route_title_15
        ProductDestination.ExcludedRoutes -> R.string.route_title_16
        ProductDestination.TunnelDns -> R.string.route_title_17
        ProductDestination.LocalProxy -> R.string.route_title_18
        ProductDestination.UpdatesProbes -> R.string.route_title_19
        ProductDestination.AppearanceAccessibility -> R.string.route_title_20
        ProductDestination.PrivacyAppLock -> R.string.route_title_21
        ProductDestination.BackupCreation -> R.string.route_title_22
        is ProductDestination.RestorePreview -> R.string.route_title_23
        is ProductDestination.TransferExport -> R.string.route_title_24
        ProductDestination.RecoveryCenter -> R.string.route_title_25
        ProductDestination.ScopedReset -> R.string.route_title_26
        ProductDestination.Diagnostics -> R.string.route_title_27
        is ProductDestination.DiagnosticExport -> R.string.route_title_28
        ProductDestination.Troubleshooting -> R.string.route_title_29
        ProductDestination.NotificationsPerformance -> R.string.route_title_30
        ProductDestination.ExpertControls -> R.string.route_title_31
        ProductDestination.Automation -> R.string.route_title_32
        ProductDestination.About -> R.string.route_title_33
        ProductDestination.Legal -> R.string.route_title_34
    }
