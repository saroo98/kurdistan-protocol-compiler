// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.domain

import kotlinx.coroutines.flow.Flow
import org.kurdistanvpn.core.model.*

enum class ProductPermission { VPN_CONSENT, NOTIFICATIONS, CAMERA, NETWORK_IDENTITY }
enum class PermissionStatus { GRANTED, NOT_GRANTED, UNAVAILABLE }
enum class PlatformSetting { VPN, NOTIFICATIONS, BATTERY, APP_DETAILS, LANGUAGE }
enum class ProductLocale { SYSTEM, ENGLISH, SORANI, KURMANJI, ARABIC, PERSIAN }
enum class ClipboardState { EMPTY, OWNED_SENSITIVE_VALUE, OTHER_OR_UNAVAILABLE }
enum class ScreenshotPolicy { PROTECTED, ALLOWED }
data class SystemPolicyState(val alwaysOn: Boolean?, val lockdown: Boolean?, val batteryRestricted: Boolean?)
data class NetworkPolicyState(val available: Boolean, val metered: Boolean?, val captivePortal: Boolean?,
    val identity: NetworkIdentityCategory, val matchingProtectedRule: CatalogId?)

interface SystemPolicyRepository {
    fun observePermission(permission: ProductPermission): Flow<PermissionStatus>
    suspend fun requestPermission(permission: ProductPermission): DomainResult<PermissionStatus>
    fun observeSystemState(): Flow<SystemPolicyState>
    fun observeNetwork(): Flow<NetworkPolicyState>
    /** Launchable applications only; never broad installed-package visibility. */
    suspend fun installedApplications(): DomainResult<List<InstalledApplication>>
    fun observeLocale(): Flow<ProductLocale>
    suspend fun setLocale(locale: ProductLocale): DomainResult<Unit>
    fun observeClipboard(): Flow<ClipboardState>
    /** Explicit user action, bounded import staging and preview; returns no clipboard contents. */
    suspend fun previewClipboardImport(): DomainResult<ProfileImportPreview>
    suspend fun copyRedactedSummary(profileId: CatalogId): DomainResult<Unit>
    suspend fun clearOwnedClipboard(): DomainResult<Unit>
    fun observeScreenshotPolicy(): Flow<ScreenshotPolicy>
    suspend fun setScreenshotPolicy(policy: ScreenshotPolicy): DomainResult<Unit>
    suspend fun openPlatformSettings(setting: PlatformSetting): DomainResult<Unit>
}
