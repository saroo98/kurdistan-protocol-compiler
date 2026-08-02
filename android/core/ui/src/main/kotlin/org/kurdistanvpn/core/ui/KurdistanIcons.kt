// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.ui

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.unit.dp

object KurdistanIcons {
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
