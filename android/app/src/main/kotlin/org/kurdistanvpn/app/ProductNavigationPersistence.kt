// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import androidx.compose.runtime.Composable
import androidx.compose.runtime.saveable.rememberSerializable
import androidx.navigation3.runtime.NavBackStack
import androidx.navigation3.runtime.NavKey
import androidx.navigation3.runtime.serialization.NavBackStackSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/** Not a destination. Invalid saved navigation remains visible until explicitly discarded. */
internal data object NavigationRecoveryKey : NavKey

internal object ProductNavigationSerializer : KSerializer<NavBackStack<NavKey>> {
    private val delegate = NavBackStackSerializer(ProductDestination.serializer())
    override val descriptor = delegate.descriptor

    override fun serialize(encoder: Encoder, value: NavBackStack<NavKey>) {
        val routes = if (value.size == 1 && value[0] == NavigationRecoveryKey) emptyList()
            else value.map { requireNotNull(it as? ProductDestination) }
        require(routes.size <= 64)
        delegate.serialize(encoder, NavBackStack(*routes.toTypedArray()))
    }

    override fun deserialize(decoder: Decoder): NavBackStack<NavKey> = try {
        val routes = delegate.deserialize(decoder)
        if (routes.isEmpty() || routes.size > 64) NavBackStack(NavigationRecoveryKey)
        else NavBackStack(*routes.toTypedArray())
    } catch (_: SerializationException) {
        NavBackStack(NavigationRecoveryKey)
    } catch (_: IllegalArgumentException) {
        // Includes CatalogId validation. It does not catch runtime, storage or resource failures.
        NavBackStack(NavigationRecoveryKey)
    }
}

@Composable
internal fun rememberProductBackStack(root: ProductDestination): NavBackStack<NavKey> =
    rememberSerializable(serializer = ProductNavigationSerializer) { NavBackStack(root) }
