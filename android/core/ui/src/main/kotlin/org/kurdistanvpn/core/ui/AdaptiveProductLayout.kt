// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.ui

data class ProductRect(val left: Float, val top: Float, val right: Float, val bottom: Float) {
    init { require(listOf(left, top, right, bottom).all { it.isFinite() } && right >= left && bottom >= top) }
    val width: Float get() = right - left
    val height: Float get() = bottom - top
    fun translated(x: Float, y: Float) = ProductRect(left + x, top + y, right + x, bottom + y)
    fun overlaps(other: ProductRect) = width > 0 && height > 0 && other.width > 0 && other.height > 0 &&
        left < other.right && right > other.left && top < other.bottom && bottom > other.top
}

/** Bounds use window coordinates in dp. A zero-width separating fold still divides content. */
data class ProductFold(val bounds: ProductRect, val vertical: Boolean, val separating: Boolean = true)
enum class ProductLayoutMode { COMPACT, RAIL, LIST_DETAIL }
data class ProductPaneLayout(val mode: ProductLayoutMode, val current: ProductRect,
    val companion: ProductRect? = null, val rail: ProductRect? = null)

/** Returns physical, content-local rectangles. RTL changes ownership, never physical hinge position. */
fun adaptiveProductLayout(content: ProductRect, fold: ProductFold? = null,
    rtl: Boolean = false, companion: Boolean = false): ProductPaneLayout {
    val area = ProductRect(0f, 0f, content.width, content.height)
    val band = fold?.bounds?.translated(-content.left, -content.top)
    val separating = fold?.separating == true && band != null && if (fold.vertical)
        band.right > 0 && band.left < area.right && band.bottom > 0 && band.top < area.bottom
        else band.bottom > 0 && band.top < area.bottom && band.right > 0 && band.left < area.right

    fun railIn(pane: ProductRect): Pair<ProductRect?, ProductRect> {
        if (content.width < 600f || pane.width < 400f) return null to pane
        return if (rtl) ProductRect(pane.right - 80f, pane.top, pane.right, pane.bottom) to
            ProductRect(pane.left, pane.top, pane.right - 80f, pane.bottom)
        else ProductRect(pane.left, pane.top, pane.left + 80f, pane.bottom) to
            ProductRect(pane.left + 80f, pane.top, pane.right, pane.bottom)
    }
    fun single(pane: ProductRect): ProductPaneLayout {
        val (rail, body) = railIn(pane)
        return ProductPaneLayout(if (rail == null) ProductLayoutMode.COMPACT else ProductLayoutMode.RAIL, body, rail = rail)
    }
    fun usable(pane: ProductRect) = pane.width >= 320f && pane.height >= 240f

    if (separating) {
        val cut = requireNotNull(band)
        val first: ProductRect
        val second: ProductRect
        if (requireNotNull(fold).vertical) {
            first = ProductRect(0f, 0f, cut.left.coerceIn(0f, area.right), area.bottom)
            second = ProductRect(cut.right.coerceIn(0f, area.right), 0f, area.right, area.bottom)
        } else {
            first = ProductRect(0f, 0f, area.right, cut.top.coerceIn(0f, area.bottom))
            second = ProductRect(0f, cut.bottom.coerceIn(0f, area.bottom), area.right, area.bottom)
        }
        val leading = if (fold.vertical && rtl) second else first
        val trailing = if (fold.vertical && rtl) first else second
        val (rail, list) = railIn(leading)
        if (companion && usable(list) && usable(trailing))
            return ProductPaneLayout(ProductLayoutMode.LIST_DETAIL, trailing, list, rail)
        return single(if (first.width * first.height >= second.width * second.height) first else second)
    }
    val (rail, body) = railIn(area)
    if (companion && area.width >= 840f && body.height >= 240f) {
        val list = if (rtl) ProductRect(body.right - 360f, 0f, body.right, body.bottom)
            else ProductRect(body.left, 0f, body.left + 360f, body.bottom)
        val detail = if (rtl) ProductRect(body.left, 0f, list.left, body.bottom)
            else ProductRect(list.right, 0f, body.right, body.bottom)
        return ProductPaneLayout(ProductLayoutMode.LIST_DETAIL, detail, list, rail)
    }
    return single(area)
}
