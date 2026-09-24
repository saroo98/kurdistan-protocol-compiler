// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.os.Bundle
import androidx.navigation3.runtime.NavBackStack
import androidx.navigation3.runtime.NavKey
import androidx.savedstate.serialization.encodeToSavedState
import androidx.savedstate.serialization.decodeFromSavedState
import org.junit.Assert.*
import org.junit.Test

class ProductNavigationPersistenceDeviceTest {
    @Test fun supportedLocalesResolveNavigationWithoutEnglishFallback() {
        val context = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        fun localized(tag: String): android.content.Context = context.createConfigurationContext(
            android.content.res.Configuration(context.resources.configuration).apply {
                setLocales(android.os.LocaleList.forLanguageTags(tag))
            })
        val english = localized("en")
        val names = listOf("navigation_welcome", "navigation_continue", "navigation_history_full",
            "navigation_recovery", "navigation_restart", "navigation_stale", "navigation_planned", "navigation_root") +
            (1..34).map { "route_title_$it" }
        for (language in listOf("ckb", "ku-Latn", "fa", "ar")) {
            val translated = localized(language)
            for (name in names) {
                val id = context.resources.getIdentifier(name, "string", context.packageName)
                assertTrue("Missing resource $name", id != 0)
                assertNotEquals("English fallback: $language/$name", english.getString(id), translated.getString(id))
            }
        }
    }

    @Test fun everyRouteRoundTripsThroughActualSavedState() {
        val routes: List<NavKey> = listOf(
            ProductDestination.Welcome,
            ProductDestination.ImportSource,
            ProductDestination.FirstTrust("id-1"),
            ProductDestination.VpnPermissionEducation,
            ProductDestination.Home,
            ProductDestination.RouteDetail("id-1"),
            ProductDestination.Profiles,
            ProductDestination.DeploymentDetail("id-1"),
            ProductDestination.ProfileDetail("id-1"),
            ProductDestination.StrategyMatrix("id-1"),
            ProductDestination.ProbeHistory("id-1"),
            ProductDestination.Settings,
            ProductDestination.ConnectionPermissions,
            ProductDestination.TrustedNetworks,
            ProductDestination.PerAppRouting,
            ProductDestination.ExcludedRoutes,
            ProductDestination.TunnelDns,
            ProductDestination.LocalProxy,
            ProductDestination.UpdatesProbes,
            ProductDestination.AppearanceAccessibility,
            ProductDestination.PrivacyAppLock,
            ProductDestination.BackupCreation,
            ProductDestination.RestorePreview("id-1"),
            ProductDestination.TransferExport("id-1"),
            ProductDestination.RecoveryCenter,
            ProductDestination.ScopedReset,
            ProductDestination.Diagnostics,
            ProductDestination.DiagnosticExport("id-1"),
            ProductDestination.Troubleshooting,
            ProductDestination.NotificationsPerformance,
            ProductDestination.ExpertControls,
            ProductDestination.Automation,
            ProductDestination.About,
            ProductDestination.Legal,
        )
        val original = NavBackStack(*routes.toTypedArray())
        val saved = encodeToSavedState(ProductNavigationSerializer, original)
        assertEquals(original.toList(),
            decodeFromSavedState(ProductNavigationSerializer, saved).toList())
    }

    @Test fun unknownSavedDiscriminatorRequiresExplicitNavigationRecovery() {
        val saved = encodeToSavedState(ProductNavigationSerializer, NavBackStack<NavKey>(ProductDestination.Home))
        assertTrue(replaceDiscriminator(saved))
        val restored = decodeFromSavedState(ProductNavigationSerializer, saved)
        assertEquals(listOf(NavigationRecoveryKey), restored.toList())
        val again = encodeToSavedState(ProductNavigationSerializer, restored)
        assertEquals(listOf(NavigationRecoveryKey), decodeFromSavedState(ProductNavigationSerializer, again).toList())
    }

    @Suppress("DEPRECATION")
    private fun replaceDiscriminator(bundle: Bundle): Boolean {
        for (key in bundle.keySet()) {
            when (val value = bundle.get(key)) {
                "p18-s05" -> { bundle.putString(key, "p18-s99"); return true }
                is Bundle -> if (replaceDiscriminator(value)) return true
            }
        }
        return false
    }
}
