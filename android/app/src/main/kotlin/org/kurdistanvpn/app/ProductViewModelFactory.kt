// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.createSavedStateHandle
import androidx.lifecycle.viewmodel.CreationExtras
import org.kurdistanvpn.feature.home.ConnectionViewModel
import org.kurdistanvpn.feature.settingsrecovery.SettingsViewModel

/** Manual composition only. SavedState contains opaque UI identities, never capabilities. */
internal class ProductViewModelFactory(private val root: ProductCompositionRoot) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>, extras: CreationExtras): T {
        val model = when (modelClass) {
            ConnectionViewModel::class.java -> ConnectionViewModel(root.connectionRepository)
            SettingsViewModel::class.java -> SettingsViewModel(checkNotNull(root.settingsRepository()), extras.createSavedStateHandle(), root.nodeMaintenanceRepository)
            org.kurdistanvpn.feature.diagnosticsabout.DiagnosticsViewModel::class.java ->
                org.kurdistanvpn.feature.diagnosticsabout.DiagnosticsViewModel(root.diagnosticsRepository, extras.createSavedStateHandle())
            org.kurdistanvpn.feature.profiles.ProfilesViewModel::class.java ->
                org.kurdistanvpn.feature.profiles.ProfilesViewModel(root.profileRepository, extras.createSavedStateHandle())
            org.kurdistanvpn.feature.onboarding.OnboardingViewModel::class.java ->
                org.kurdistanvpn.feature.onboarding.OnboardingViewModel(root.profileRepository, extras.createSavedStateHandle())
            org.kurdistanvpn.feature.settingsrecovery.PrivacyRecoveryViewModel::class.java ->
                org.kurdistanvpn.feature.settingsrecovery.PrivacyRecoveryViewModel(root.privacyRepository, extras.createSavedStateHandle())
            else -> error("UNSUPPORTED_VIEW_MODEL")
        }
        @Suppress("UNCHECKED_CAST")
        return model as T
    }
}
