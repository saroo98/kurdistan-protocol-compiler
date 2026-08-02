// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.unit.dp

private val KurdIndigo = Color(0xFF4A3AB3)
private val KurdTeal = Color(0xFF087B77)
private val KurdSaffron = Color(0xFFAD6600)
private val KurdInk = Color(0xFF111318)
private val KurdPaper = Color(0xFFF7F6F2)
private val KurdSurface = Color(0xFFFFFEFA)
val LocalReducedMotion = staticCompositionLocalOf { false }

private val KurdistanTypography = Typography(
    displaySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 36.sp,
        lineHeight = 42.sp,
        letterSpacing = (-0.4).sp,
    ),
    headlineLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 30.sp,
        lineHeight = 36.sp,
        letterSpacing = (-0.25).sp,
    ),
    headlineMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
        lineHeight = 30.sp,
    ),
    headlineSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
        lineHeight = 26.sp,
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 18.sp,
        lineHeight = 24.sp,
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp,
        lineHeight = 22.sp,
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    bodySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 17.sp,
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
)

private val KurdistanShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(18.dp),
    large = RoundedCornerShape(26.dp),
    extraLarge = RoundedCornerShape(34.dp),
)

@Composable
fun KurdistanTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    highContrast: Boolean = false,
    reducedMotion: Boolean = false,
    content: @Composable () -> Unit,
) {
    val colors = if (darkTheme) {
        darkColorScheme(
            primary = if (highContrast) Color.White else Color(0xFFC9C1FF),
            onPrimary = if (highContrast) Color.Black else Color(0xFF21136A),
            primaryContainer = if (highContrast) Color.White else Color(0xFF34267F),
            onPrimaryContainer = if (highContrast) Color.Black else Color(0xFFE6E0FF),
            secondary = if (highContrast) Color.White else Color(0xFF74D5CF),
            onSecondary = Color(0xFF003735),
            secondaryContainer = Color(0xFF07514F),
            onSecondaryContainer = Color(0xFFA4F2ED),
            tertiary = Color(0xFFFFB95F),
            background = if (highContrast) Color.Black else KurdInk,
            surface = if (highContrast) Color.Black else Color(0xFF181B21),
            surfaceVariant = if (highContrast) Color.Black else Color(0xFF222630),
            outline = if (highContrast) Color.White else Color(0xFF8F909A),
        )
    } else {
        lightColorScheme(
            primary = if (highContrast) Color(0xFF1D005C) else KurdIndigo,
            onPrimary = Color.White,
            primaryContainer = if (highContrast) Color(0xFFE7E0FF) else Color(0xFFE8E3FF),
            onPrimaryContainer = Color(0xFF1C1458),
            secondary = if (highContrast) Color(0xFF004744) else KurdTeal,
            onSecondary = Color.White,
            secondaryContainer = Color(0xFFD4F4F0),
            onSecondaryContainer = Color(0xFF003734),
            tertiary = KurdSaffron,
            background = if (highContrast) Color.White else KurdPaper,
            surface = if (highContrast) Color.White else KurdSurface,
            surfaceVariant = if (highContrast) Color.White else Color(0xFFEDEAE3),
            outline = if (highContrast) Color.Black else Color(0xFF777680),
        )
    }
    CompositionLocalProvider(LocalReducedMotion provides reducedMotion) {
        MaterialTheme(
            colorScheme = colors,
            typography = KurdistanTypography,
            shapes = KurdistanShapes,
            content = content,
        )
    }
}
