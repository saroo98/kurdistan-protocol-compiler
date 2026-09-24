// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.selection.LocalTextSelectionColors
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.takeOrElse
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontSynthesis
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.DialogWindowProvider

val LocalReducedMotion = staticCompositionLocalOf { false }
data class NavigationAccents(val home: Color, val settings: Color)
val LocalNavigationAccents = staticCompositionLocalOf {
    NavigationAccents(Color(0xFFB73542), Color(0xFF237345))
}
val LocalEssentialBoundaryWidth = staticCompositionLocalOf { 1.dp }

/** Applies only to the current Compose dialog window, never to a device setting. */
@Composable
fun KurdistanDialogAppearance() {
    val window = (LocalView.current.parent as? DialogWindowProvider)?.window
    val originalAnimation = remember(window) { window?.attributes?.windowAnimations ?: 0 }
    val reducedMotion = LocalReducedMotion.current
    SideEffect {
        window?.setDimAmount(0.56f)
        window?.setWindowAnimations(if (reducedMotion) 0 else originalAnimation)
    }
}

/** High contrast customizes the native container stroke, preserving its label cutout. */
@Composable
fun KurdistanOutlinedTextField(
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    label: @Composable (() -> Unit)? = null,
    supportingText: @Composable (() -> Unit)? = null,
    singleLine: Boolean = false,
    visualTransformation: VisualTransformation = VisualTransformation.None,
) {
    val interactions = remember { MutableInteractionSource() }
    val focused by interactions.collectIsFocusedAsState()
    val boundary = LocalEssentialBoundaryWidth.current
    val colors = OutlinedTextFieldDefaults.colors()
    if (boundary <= 1.dp) {
        OutlinedTextField(
            value = value, onValueChange = onValueChange,
            modifier = modifier.heightIn(min = 56.dp),
            label = label, supportingText = supportingText, singleLine = singleLine,
            visualTransformation = visualTransformation, interactionSource = interactions,
            shape = MaterialTheme.shapes.small,
            colors = colors,
        )
    } else {
        val textStyle = LocalTextStyle.current
        val textColor = textStyle.color.takeOrElse {
            if (focused) colors.focusedTextColor else colors.unfocusedTextColor
        }
        // Match the pinned Material field's outer label clearance and merged target.
        val labelClearance = with(LocalDensity.current) {
            MaterialTheme.typography.bodySmall.lineHeight.toDp() / 2
        }
        CompositionLocalProvider(LocalTextSelectionColors provides colors.textSelectionColors) {
            BasicTextField(
                value = value, onValueChange = onValueChange,
                modifier = modifier.heightIn(min = 56.dp).then(
                    if (label != null) Modifier.semantics(mergeDescendants = true) {}.padding(top = labelClearance)
                    else Modifier,
                ).defaultMinSize(
                    minWidth = OutlinedTextFieldDefaults.MinWidth,
                    minHeight = OutlinedTextFieldDefaults.MinHeight,
                ),
                textStyle = textStyle.merge(TextStyle(color = textColor)),
                cursorBrush = SolidColor(colors.cursorColor),
                singleLine = singleLine, visualTransformation = visualTransformation,
                interactionSource = interactions,
                decorationBox = { innerTextField ->
                    OutlinedTextFieldDefaults.DecorationBox(
                        value = value, innerTextField = innerTextField,
                        enabled = true, singleLine = singleLine,
                        visualTransformation = visualTransformation,
                        interactionSource = interactions, label = label,
                        supportingText = supportingText, colors = colors,
                        container = {
                            OutlinedTextFieldDefaults.Container(
                                enabled = true, isError = false, interactionSource = interactions,
                                colors = colors, shape = MaterialTheme.shapes.small,
                                focusedBorderThickness = boundary, unfocusedBorderThickness = boundary,
                            )
                        },
                    )
                },
            )
        }
    }
}

private fun kurdistanTypography(arabicScript: Boolean, sorani: Boolean): Typography {
    val extraLeading = if (arabicScript) 4 else 0
    val heading = if (sorani) FontFamily(Font(R.font.sorani_magroon)) else FontFamily.SansSerif
    val body = if (sorani) FontFamily(Font(R.font.sorani_body)) else FontFamily.SansSerif
    val secondary = if (sorani) FontFamily(Font(R.font.sorani_midya)) else FontFamily.SansSerif
    fun text(size: Int, height: Int, weight: FontWeight, family: FontFamily) = TextStyle(
        fontFamily = family,
        fontWeight = if (sorani) FontWeight.Normal else weight,
        fontSynthesis = if (sorani) FontSynthesis.None else null,
        fontSize = size.sp,
        lineHeight = (height + extraLeading).sp,
        letterSpacing = 0.sp,
    )
    return Typography(
        displaySmall = text(28, 36, FontWeight.SemiBold, heading),
        headlineLarge = text(28, 36, FontWeight.SemiBold, heading),
        headlineMedium = text(22, 28, FontWeight.SemiBold, heading),
        headlineSmall = text(20, 28, FontWeight.SemiBold, heading),
        titleLarge = text(16, 24, FontWeight.SemiBold, heading),
        titleMedium = text(16, 24, FontWeight.Medium, heading),
        titleSmall = text(14, 20, FontWeight.Medium, heading),
        bodyLarge = text(16, 24, FontWeight.Normal, body),
        bodyMedium = text(14, 20, FontWeight.Normal, body),
        bodySmall = text(14, 20, FontWeight.Normal, secondary),
        labelLarge = text(16, 24, FontWeight.SemiBold, heading),
        labelMedium = text(12, 16, FontWeight.Medium, secondary),
        labelSmall = text(12, 16, FontWeight.Medium, secondary),
    )
}

private val KurdistanShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(24.dp),
)

private fun kurdistanColors(darkTheme: Boolean, highContrast: Boolean) = run {
    fun tone(light: Long, dark: Long, highLight: Long, highDark: Long) = Color(
        when {
            highContrast && darkTheme -> highDark
            highContrast -> highLight
            darkTheme -> dark
            else -> light
        },
    )
    val base = if (darkTheme) darkColorScheme() else lightColorScheme()
    base.copy(
        background = tone(0xFFF7F6F2, 0xFF111318, 0xFFFFFFFF, 0xFF000000),
        onBackground = tone(0xFF111318, 0xFFF7F6F2, 0xFF000000, 0xFFFFFFFF),
        surface = tone(0xFFFFFEFA, 0xFF181B21, 0xFFFFFFFF, 0xFF000000),
        onSurface = tone(0xFF111318, 0xFFF7F6F2, 0xFF000000, 0xFFFFFFFF),
        surfaceVariant = tone(0xFFEDEAE3, 0xFF222630, 0xFFFFFFFF, 0xFF000000),
        onSurfaceVariant = tone(0xFF5D5F67, 0xFFC4C5CC, 0xFF1F1F1F, 0xFFF0F0F0),
        surfaceTint = tone(0xFF4A3AB3, 0xFFC9C1FF, 0xFF1D005C, 0xFFFFFFFF),
        surfaceBright = tone(0xFFFFFEFA, 0xFF181B21, 0xFFFFFFFF, 0xFF000000),
        surfaceDim = tone(0xFFF7F6F2, 0xFF111318, 0xFFFFFFFF, 0xFF000000),
        surfaceContainerLowest = tone(0xFFFFFEFA, 0xFF181B21, 0xFFFFFFFF, 0xFF000000),
        surfaceContainerLow = tone(0xFFF7F6F2, 0xFF111318, 0xFFFFFFFF, 0xFF000000),
        surfaceContainer = tone(0xFFFFFEFA, 0xFF181B21, 0xFFFFFFFF, 0xFF000000),
        surfaceContainerHigh = tone(0xFFEDEAE3, 0xFF222630, 0xFFFFFFFF, 0xFF000000),
        surfaceContainerHighest = tone(0xFFEDEAE3, 0xFF222630, 0xFFFFFFFF, 0xFF000000),
        primary = tone(0xFF4A3AB3, 0xFFC9C1FF, 0xFF1D005C, 0xFFFFFFFF),
        onPrimary = tone(0xFFFFFFFF, 0xFF21136A, 0xFFFFFFFF, 0xFF000000),
        primaryContainer = tone(0xFFE8E3FF, 0xFF34267F, 0xFFE7E0FF, 0xFFFFFFFF),
        onPrimaryContainer = tone(0xFF1C1458, 0xFFE6E0FF, 0xFF1D005C, 0xFF000000),
        inversePrimary = tone(0xFFC9C1FF, 0xFF4A3AB3, 0xFFFFFFFF, 0xFF000000),
        secondary = tone(0xFF087B77, 0xFF74D5CF, 0xFF004744, 0xFFA4F2ED),
        onSecondary = tone(0xFFFFFFFF, 0xFF003735, 0xFFFFFFFF, 0xFF000000),
        secondaryContainer = tone(0xFFD4F4F0, 0xFF07514F, 0xFFFFFFFF, 0xFF000000),
        onSecondaryContainer = tone(0xFF003734, 0xFFA4F2ED, 0xFF004744, 0xFFA4F2ED),
        tertiary = tone(0xFF7A4600, 0xFFFFB95F, 0xFF663900, 0xFFFFD69B),
        onTertiary = tone(0xFFFFFFFF, 0xFF3D2400, 0xFFFFFFFF, 0xFF000000),
        tertiaryContainer = tone(0xFFFFF0DC, 0xFF51330C, 0xFFFFFFFF, 0xFF000000),
        onTertiaryContainer = tone(0xFF7A4600, 0xFFFFB95F, 0xFF663900, 0xFFFFD69B),
        error = tone(0xFFBA1A1A, 0xFFFFB4AB, 0xFF8C0009, 0xFFFFDAD6),
        onError = tone(0xFFFFFFFF, 0xFF690005, 0xFFFFFFFF, 0xFF000000),
        errorContainer = tone(0xFFFFDAD6, 0xFF690005, 0xFFFFFFFF, 0xFF000000),
        onErrorContainer = tone(0xFF410002, 0xFFFFDAD6, 0xFF8C0009, 0xFFFFDAD6),
        outline = tone(0xFF777680, 0xFF8F909A, 0xFF000000, 0xFFFFFFFF),
        outlineVariant = tone(0xFFCAC7C0, 0xFF3A3D46, 0xFF000000, 0xFFFFFFFF),
        scrim = tone(0xFF000000, 0xFF000000, 0xFF000000, 0xFF000000),
        inverseSurface = tone(0xFF222630, 0xFFF7F6F2, 0xFF000000, 0xFFFFFFFF),
        inverseOnSurface = tone(0xFFF7F6F2, 0xFF111318, 0xFFFFFFFF, 0xFF000000),
    )
}

@Composable
fun KurdistanTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    highContrast: Boolean = false,
    reducedMotion: Boolean = false,
    content: @Composable () -> Unit,
) {
    val locale = LocalConfiguration.current.locales[0]
    val arabicScript = locale.script == "Arab" || locale.language in setOf("ckb", "fa", "ar")
    val sorani = locale.language == "ckb"
    val typography = remember(arabicScript, sorani) { kurdistanTypography(arabicScript, sorani) }
    val colors = remember(darkTheme, highContrast) { kurdistanColors(darkTheme, highContrast) }
    CompositionLocalProvider(
        LocalReducedMotion provides reducedMotion,
        LocalNavigationAccents provides NavigationAccents(
            if (highContrast) colors.onSurface else if (darkTheme) Color(0xFFF18B94) else Color(0xFFB73542),
            if (highContrast) colors.onSurface else if (darkTheme) Color(0xFF77CB98) else Color(0xFF237345),
        ),
        LocalEssentialBoundaryWidth provides if (highContrast) 2.dp else 1.dp,
    ) {
        MaterialTheme(
            colorScheme = colors,
            typography = typography,
            shapes = KurdistanShapes,
        ) {
            CompositionLocalProvider(LocalContentColor provides colors.onBackground, content = content)
        }
    }
}
