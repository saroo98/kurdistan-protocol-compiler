// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test

class ProductCompositionRootDeviceTest {
    @Test fun sevenBindingsAndSixFeatureOwnersSurviveRecreationWithoutProvisioning() {
        val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as KurdistanApplication
        val root = app.compositionRoot
        val before = root.protectedStateFacade()?.readProjection()
        fun bindings() = listOf(root.connectionRepository, root.profileRepository, root.settingsRepository(),
            root.privacyRepository, root.diagnosticsRepository, root.systemPolicy, root.nodeMaintenanceRepository)
        val originalBindings = bindings()
        val classes = listOf(
            org.kurdistanvpn.feature.home.ConnectionViewModel::class.java,
            org.kurdistanvpn.feature.profiles.ProfilesViewModel::class.java,
            org.kurdistanvpn.feature.settingsrecovery.SettingsViewModel::class.java,
            org.kurdistanvpn.feature.settingsrecovery.PrivacyRecoveryViewModel::class.java,
            org.kurdistanvpn.feature.diagnosticsabout.DiagnosticsViewModel::class.java,
            org.kurdistanvpn.feature.onboarding.OnboardingViewModel::class.java,
        )
        var owners = emptyList<ViewModel>()
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val provider = ViewModelProvider(activity, ProductViewModelFactory(root))
                owners = classes.map { provider[it] }
                assertEquals(6, owners.toSet().size)
            }
            scenario.recreate()
            scenario.onActivity { activity ->
                val provider = ViewModelProvider(activity, ProductViewModelFactory(root))
                classes.forEachIndexed { index, type -> assertSame(owners[index], provider[type]) }
                bindings().forEachIndexed { index, binding -> assertSame(originalBindings[index], binding) }
                assertSame(root, (activity.application as KurdistanApplication).compositionRoot)
            }
        }
        assertEquals(before, root.protectedStateFacade()?.readProjection())
        if (before == null) assertNull(root.protectedStateFacade())
    }
}
