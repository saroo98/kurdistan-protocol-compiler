// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.ui

import androidx.compose.foundation.Canvas
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics

/** Fixed identity geometry, never mirrored or used as connection-state feedback. */
@Composable
fun KurdistanBrandMark(modifier: Modifier = Modifier) {
    val name = stringResource(R.string.product_name)
    val color = MaterialTheme.colorScheme.onSurface
    val silhouette = remember {
        Path().apply {
            moveTo(24f, 24f); lineTo(106f, 24f); lineTo(106f, 88f)
            lineTo(166f, 24f); lineTo(232f, 24f); lineTo(152f, 116f)
            lineTo(238f, 232f); lineTo(172f, 232f); lineTo(106f, 160f)
            lineTo(106f, 232f); lineTo(24f, 232f); close()
        }
    }
    val knockout = remember {
        Path().apply {
            moveTo(16f, 128f); lineTo(126f, 128f)
            moveTo(126f, 128f); lineTo(244f, 16f)
            moveTo(126f, 128f); lineTo(244f, 240f)
        }
    }
    Canvas(modifier.semantics { contentDescription = name }.graphicsLayer {
        // Clear must affect only the mark, not the screen behind it.
        compositingStrategy = CompositingStrategy.Offscreen
    }) {
        scale(size.width / 256f, size.height / 256f, Offset.Zero) {
            drawPath(silhouette, color)
            drawPath(knockout, Color.Black, style = Stroke(24f, cap = StrokeCap.Square, join = StrokeJoin.Bevel), blendMode = BlendMode.Clear)
        }
    }
}
