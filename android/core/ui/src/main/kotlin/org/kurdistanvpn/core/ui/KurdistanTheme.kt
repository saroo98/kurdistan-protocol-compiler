// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

private val KurdViolet = Color(0xFF5C35D9)
private val KurdAmber = Color(0xFFFFB534)
private val KurdInk = Color(0xFF171421)
private val KurdPaper = Color(0xFFFFFBFF)
val LocalReducedMotion = staticCompositionLocalOf { false }

@Composable
fun KurdistanTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    highContrast: Boolean = false,
    reducedMotion: Boolean = false,
    content: @Composable () -> Unit,
) {
    val colors = if (darkTheme) {
        darkColorScheme(
            primary = if (highContrast) Color.White else Color(0xFFC9BFFF),
            secondary = KurdAmber,
            background = if (highContrast) Color.Black else KurdInk,
        )
    } else {
        lightColorScheme(
            primary = if (highContrast) Color(0xFF260080) else KurdViolet,
            secondary = Color(0xFF785900),
            background = if (highContrast) Color.White else KurdPaper,
        )
    }
    CompositionLocalProvider(LocalReducedMotion provides reducedMotion) {
        MaterialTheme(colorScheme = colors, content = content)
    }
}
