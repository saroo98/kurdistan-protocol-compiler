// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.ui

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.unit.dp

object KurdistanIcons {
    val Sun: ImageVector = ImageVector.Builder(
        name = "Sun", defaultWidth = 24.dp, defaultHeight = 24.dp,
        viewportWidth = 100f, viewportHeight = 100f,
    ).apply {
        path(fill = SolidColor(Color.Black)) {
            // Twenty-one equal rays with the first pointing vertically upward.
            repeat(21) { ray ->
                val angle = ray * 2.0 * kotlin.math.PI / 21
                val c = kotlin.math.cos(angle).toFloat()
                val s = kotlin.math.sin(angle).toFloat()
                moveTo(50f - 5f * c + 23f * s, 50f - 5f * s - 23f * c)
                lineTo(50f + 47f * s, 50f - 47f * c)
                lineTo(50f + 5f * c + 23f * s, 50f + 5f * s - 23f * c)
                close()
            }
            moveTo(75f, 50f)
            arcTo(25f, 25f, 0f, false, true, 50f, 75f)
            arcTo(25f, 25f, 0f, false, true, 25f, 50f)
            arcTo(25f, 25f, 0f, false, true, 50f, 25f)
            arcTo(25f, 25f, 0f, false, true, 75f, 50f)
            close()
        }
    }.build()

    val Connection: ImageVector = outline("Connection") {
        moveTo(12f, 3f); lineTo(21f, 7f); lineTo(21f, 12f)
        curveTo(21f, 17f, 17f, 20f, 12f, 22f)
        curveTo(7f, 20f, 3f, 17f, 3f, 12f)
        lineTo(3f, 7f); close()
    }
    val Route: ImageVector = outline("Route") {
        moveTo(5f, 3f); lineTo(5f, 17f); curveTo(5f, 20f, 9f, 20f, 9f, 17f)
        lineTo(9f, 8f); curveTo(9f, 4f, 19f, 4f, 19f, 8f); lineTo(19f, 21f)
        moveTo(16f, 18f); lineTo(19f, 21f); lineTo(22f, 18f)
    }
    val Refresh: ImageVector = outline("Refresh") {
        moveTo(20f, 10f); curveTo(19f, 3f, 9f, 1f, 4f, 8f)
        moveTo(20f, 4f); lineTo(20f, 10f); lineTo(14f, 10f)
        moveTo(4f, 14f); curveTo(5f, 21f, 15f, 23f, 20f, 16f)
        moveTo(4f, 20f); lineTo(4f, 14f); lineTo(10f, 14f)
    }
    val Lock: ImageVector = outline("Lock") {
        moveTo(7f, 10f); lineTo(7f, 7f); curveTo(7f, 1f, 17f, 1f, 17f, 7f); lineTo(17f, 10f)
        moveTo(4f, 10f); lineTo(20f, 10f); lineTo(20f, 21f); lineTo(4f, 21f); close()
        moveTo(12f, 14f); lineTo(12f, 17f)
    }
    val Adjustments: ImageVector = outline("Adjustments") {
        moveTo(4f, 3f); lineTo(4f, 7f); moveTo(4f, 11f); lineTo(4f, 21f)
        moveTo(12f, 3f); lineTo(12f, 13f); moveTo(12f, 17f); lineTo(12f, 21f)
        moveTo(20f, 3f); lineTo(20f, 7f); moveTo(20f, 11f); lineTo(20f, 21f)
        moveTo(2f, 7f); lineTo(6f, 7f); lineTo(6f, 11f); lineTo(2f, 11f); close()
        moveTo(10f, 13f); lineTo(14f, 13f); lineTo(14f, 17f); lineTo(10f, 17f); close()
        moveTo(18f, 7f); lineTo(22f, 7f); lineTo(22f, 11f); lineTo(18f, 11f); close()
    }

    val Star: ImageVector = outline("Star") { starPath() }
    val StarFilled: ImageVector = icon("StarFilled") { starPath() }

    private fun androidx.compose.ui.graphics.vector.PathBuilder.starPath() {
        moveTo(12f, 2.5f)
        lineTo(15f, 8.6f)
        lineTo(21.7f, 9.6f)
        lineTo(16.9f, 14.3f)
        lineTo(18f, 21f)
        lineTo(12f, 17.8f)
        lineTo(6f, 21f)
        lineTo(7.1f, 14.3f)
        lineTo(2.3f, 9.6f)
        lineTo(9f, 8.6f)
        close()
    }

    val Info: ImageVector = outline("Info") {
        moveTo(12f, 3f)
        curveTo(7f, 3f, 3f, 7f, 3f, 12f)
        curveTo(3f, 17f, 7f, 21f, 12f, 21f)
        curveTo(17f, 21f, 21f, 17f, 21f, 12f)
        curveTo(21f, 7f, 17f, 3f, 12f, 3f)
        close()
        moveTo(12f, 11f)
        lineTo(12f, 16f)
        moveTo(12f, 7.5f)
        lineTo(12f, 7.6f)
    }

    val Warning: ImageVector = outline("Warning") {
        moveTo(12f, 3f)
        lineTo(22f, 21f)
        lineTo(2f, 21f)
        close()
        moveTo(12f, 9f)
        lineTo(12f, 14f)
        moveTo(12f, 17.5f)
        lineTo(12f, 17.6f)
    }

    val ChevronForward: ImageVector = outline("ChevronForward", autoMirror = true) {
        moveTo(9f, 5f)
        lineTo(16f, 12f)
        lineTo(9f, 19f)
    }

    val ChevronDown: ImageVector = outline("ChevronDown") {
        moveTo(5f, 9f)
        lineTo(12f, 16f)
        lineTo(19f, 9f)
    }

    val Home: ImageVector = icon("Home") {
        moveTo(3f, 10.8f)
        lineTo(12f, 3f)
        lineTo(21f, 10.8f)
        lineTo(21f, 21f)
        lineTo(14.5f, 21f)
        lineTo(14.5f, 14.5f)
        lineTo(9.5f, 14.5f)
        lineTo(9.5f, 21f)
        lineTo(3f, 21f)
        close()
    }

    val Profiles: ImageVector = icon("Profiles") {
        moveTo(4f, 4f)
        lineTo(7f, 4f)
        lineTo(7f, 7f)
        lineTo(4f, 7f)
        close()
        moveTo(9f, 4.5f)
        lineTo(21f, 4.5f)
        lineTo(21f, 6.5f)
        lineTo(9f, 6.5f)
        close()
        moveTo(4f, 10.5f)
        lineTo(7f, 10.5f)
        lineTo(7f, 13.5f)
        lineTo(4f, 13.5f)
        close()
        moveTo(9f, 11f)
        lineTo(21f, 11f)
        lineTo(21f, 13f)
        lineTo(9f, 13f)
        close()
        moveTo(4f, 17f)
        lineTo(7f, 17f)
        lineTo(7f, 20f)
        lineTo(4f, 20f)
        close()
        moveTo(9f, 17.5f)
        lineTo(21f, 17.5f)
        lineTo(21f, 19.5f)
        lineTo(9f, 19.5f)
        close()
    }

    val Settings: ImageVector = icon("Settings") {
        moveTo(10.8f, 2f)
        lineTo(13.2f, 2f)
        lineTo(13.8f, 4.5f)
        curveTo(14.5f, 4.7f, 15.2f, 5f, 15.8f, 5.4f)
        lineTo(18f, 4.1f)
        lineTo(19.9f, 6f)
        lineTo(18.6f, 8.2f)
        curveTo(19f, 8.8f, 19.3f, 9.5f, 19.5f, 10.2f)
        lineTo(22f, 10.8f)
        lineTo(22f, 13.2f)
        lineTo(19.5f, 13.8f)
        curveTo(19.3f, 14.5f, 19f, 15.2f, 18.6f, 15.8f)
        lineTo(19.9f, 18f)
        lineTo(18f, 19.9f)
        lineTo(15.8f, 18.6f)
        curveTo(15.2f, 19f, 14.5f, 19.3f, 13.8f, 19.5f)
        lineTo(13.2f, 22f)
        lineTo(10.8f, 22f)
        lineTo(10.2f, 19.5f)
        curveTo(9.5f, 19.3f, 8.8f, 19f, 8.2f, 18.6f)
        lineTo(6f, 19.9f)
        lineTo(4.1f, 18f)
        lineTo(5.4f, 15.8f)
        curveTo(5f, 15.2f, 4.7f, 14.5f, 4.5f, 13.8f)
        lineTo(2f, 13.2f)
        lineTo(2f, 10.8f)
        lineTo(4.5f, 10.2f)
        curveTo(4.7f, 9.5f, 5f, 8.8f, 5.4f, 8.2f)
        lineTo(4.1f, 6f)
        lineTo(6f, 4.1f)
        lineTo(8.2f, 5.4f)
        curveTo(8.8f, 5f, 9.5f, 4.7f, 10.2f, 4.5f)
        close()
        moveTo(12f, 8f)
        curveTo(9.8f, 8f, 8f, 9.8f, 8f, 12f)
        curveTo(8f, 14.2f, 9.8f, 16f, 12f, 16f)
        curveTo(14.2f, 16f, 16f, 14.2f, 16f, 12f)
        curveTo(16f, 9.8f, 14.2f, 8f, 12f, 8f)
        close()
    }

    val Shield: ImageVector = icon("Shield") {
        moveTo(12f, 2f)
        lineTo(21f, 6f)
        lineTo(21f, 12f)
        curveTo(21f, 17.5f, 17.2f, 21.6f, 12f, 23f)
        curveTo(6.8f, 21.6f, 3f, 17.5f, 3f, 12f)
        lineTo(3f, 6f)
        close()
        moveTo(7.5f, 12f)
        lineTo(10.5f, 15f)
        lineTo(16.8f, 8.7f)
        lineTo(18.2f, 10.1f)
        lineTo(10.5f, 17.8f)
        lineTo(6.1f, 13.4f)
        close()
    }

    private fun outline(
        name: String,
        autoMirror: Boolean = false,
        draw: androidx.compose.ui.graphics.vector.PathBuilder.() -> Unit,
    ): ImageVector = ImageVector.Builder(
        name = name,
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
        autoMirror = autoMirror,
    ).apply {
        path(
            stroke = SolidColor(Color.Black),
            strokeLineWidth = 1.8f,
            strokeLineCap = StrokeCap.Round,
            strokeLineJoin = StrokeJoin.Round,
            pathBuilder = draw,
        )
    }.build()

    private fun icon(
        name: String,
        draw: androidx.compose.ui.graphics.vector.PathBuilder.() -> Unit,
    ): ImageVector = ImageVector.Builder(
        name = name,
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
    ).apply {
        path(fill = SolidColor(Color.Black), pathBuilder = draw)
    }.build()
}
