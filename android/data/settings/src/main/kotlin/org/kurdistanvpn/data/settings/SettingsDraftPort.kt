// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.data.settings

import org.kurdistanvpn.core.model.CatalogId
import org.kurdistanvpn.core.model.ProductSettings

data class StoredSettingsDraft(val id: CatalogId, val base: SettingsStoreState, val requested: ProductSettings) {
    override fun toString() = "StoredSettingsDraft(redacted)"
}

interface SettingsDraftPort {
    suspend fun create(value: StoredSettingsDraft): SettingsPortResult<Unit>
    suspend fun read(id: CatalogId): SettingsPortResult<StoredSettingsDraft>
    suspend fun replace(value: StoredSettingsDraft): SettingsPortResult<Unit>
    /** Missing record is OPERATION_INTERRUPTED; only cancel may treat proven absence as success. */
    suspend fun delete(id: CatalogId): SettingsPortResult<Unit>
}
