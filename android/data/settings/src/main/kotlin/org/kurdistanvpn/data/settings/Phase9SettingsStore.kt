// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.settings

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.ThemePreference

private val Context.phase9Preferences by preferencesDataStore(name = "phase9_nonsecret_settings")

class Phase9SettingsStore(
    private val context: Context,
) {
    val settings: Flow<Phase9Settings> =
        context.phase9Preferences.data.map { values ->
            Phase9Settings(
                theme = runCatching {
                    ThemePreference.valueOf(values[THEME] ?: ThemePreference.SYSTEM.name)
                }.getOrDefault(ThemePreference.SYSTEM),
                highContrast = values[HIGH_CONTRAST] ?: false,
                reducedMotion = values[REDUCED_MOTION] ?: false,
            )
        }

    suspend fun setTheme(theme: ThemePreference) {
        context.phase9Preferences.edit { it[THEME] = theme.name }
    }

    suspend fun setHighContrast(enabled: Boolean) {
        context.phase9Preferences.edit { it[HIGH_CONTRAST] = enabled }
    }

    suspend fun setReducedMotion(enabled: Boolean) {
        context.phase9Preferences.edit { it[REDUCED_MOTION] = enabled }
    }

    private companion object {
        val THEME = stringPreferencesKey("theme")
        val HIGH_CONTRAST = booleanPreferencesKey("high_contrast")
        val REDUCED_MOTION = booleanPreferencesKey("reduced_motion")
    }
}
