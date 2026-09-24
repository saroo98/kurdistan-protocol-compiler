// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.ui

import org.junit.Assert.*
import org.junit.Test

class AdaptiveProductLayoutTest {
    @Test fun boundariesUseAvailableWindowWidth() {
        listOf(599f to ProductLayoutMode.COMPACT, 600f to ProductLayoutMode.RAIL,
            839f to ProductLayoutMode.RAIL, 840f to ProductLayoutMode.LIST_DETAIL).forEach { (width, expected) ->
            assertEquals(expected, adaptiveProductLayout(ProductRect(20f, 30f, 20f + width, 900f), companion = true).mode)
        }
        val wide = adaptiveProductLayout(ProductRect(0f, 0f, 1000f, 800f), companion = true)
        assertEquals(ProductRect(80f, 0f, 440f, 800f), wide.companion)
        assertEquals(ProductRect(440f, 0f, 1000f, 800f), wide.current)
    }

    @Test fun physicalHingesAndInsetsNeverOverlapEitherPane() {
        val content = ProductRect(20f, 30f, 1220f, 930f)
        listOf(
            ProductFold(ProductRect(610f, 0f, 630f, 1000f), vertical = true),
            ProductFold(ProductRect(0f, 460f, 1300f, 480f), vertical = false),
            ProductFold(ProductRect(620f, 0f, 620f, 1000f), vertical = true),
        ).forEach { fold ->
            val layout = adaptiveProductLayout(content, fold, companion = true)
            assertNotNull(layout.companion)
            val local = fold.bounds.translated(-content.left, -content.top)
            assertFalse(layout.current.overlaps(local))
            assertFalse(layout.companion!!.overlaps(local))
            layout.rail?.let { assertFalse(it.overlaps(local)) }
        }
    }

    @Test fun irrelevantHingeDoesNotSplitAndNarrowPaneFallsBack() {
        val content = ProductRect(0f, 0f, 1000f, 800f)
        val normal = adaptiveProductLayout(content, companion = true)
        assertEquals(normal, adaptiveProductLayout(content,
            ProductFold(ProductRect(1200f, 0f, 1220f, 800f), true), companion = true))
        assertEquals(normal, adaptiveProductLayout(content,
            ProductFold(ProductRect(490f, 0f, 510f, 800f), true, separating = false), companion = true))
        val small = adaptiveProductLayout(content, ProductFold(ProductRect(100f, 0f, 120f, 800f), true), companion = true)
        assertNull(small.companion)
        assertTrue(small.current.left >= 120f)
        assertTrue(small.current.width >= 320f)
    }

    @Test fun rtlPlacesTheListAtLogicalStartWithoutMirroringPhysicalHinge() {
        val layout = adaptiveProductLayout(ProductRect(0f, 0f, 1200f, 800f),
            ProductFold(ProductRect(590f, 0f, 610f, 800f), true), rtl = true, companion = true)
        assertEquals(ProductRect(1120f, 0f, 1200f, 800f), layout.rail)
        assertEquals(ProductRect(610f, 0f, 1120f, 800f), layout.companion)
        assertEquals(ProductRect(0f, 0f, 590f, 800f), layout.current)
    }

    @Test fun hingePartlyOutsideContentStillExcludesItsOccludedBand() {
        val layout = adaptiveProductLayout(ProductRect(20f, 30f, 1020f, 830f),
            ProductFold(ProductRect(10f, 0f, 40f, 900f), true), companion = true)
        assertTrue(layout.current.left >= 20f)
        layout.rail?.let { assertTrue(it.left >= 20f) }
    }
}
