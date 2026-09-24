// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.platform.system

import android.Manifest
import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.os.LocaleListCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.withContext
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

/** Only a resumed Activity implements these operations. No Activity is retained by this module. */
interface ForegroundSystemActions {
    suspend fun requestPermission(permission: ProductPermission): DomainResult<Unit>
    suspend fun openSettings(setting: PlatformSetting): DomainResult<Unit>
    fun screenshotPolicy(): ScreenshotPolicy
    fun setScreenshotPolicy(policy: ScreenshotPolicy): DomainResult<Unit>
    fun clipboardState(): ClipboardState
    suspend fun previewClipboardImport(): DomainResult<ProfileImportPreview>
    suspend fun copyRedactedSummary(profileId: CatalogId): DomainResult<Unit>
    fun clearOwnedClipboard(): DomainResult<Unit>
}

class AndroidSystemPolicyRepository(
    private val context: Context,
    private val runtimePolicy: Flow<SystemPolicyState>,
    private val foreground: () -> ForegroundSystemActions?,
) : SystemPolicyRepository {
    private val refresh = MutableStateFlow(0L)
    /** Called on foreground return, including a return from system settings. No polling. */
    fun refreshPlatformState() { refresh.value++ }

    override fun observePermission(permission: ProductPermission): Flow<PermissionStatus> =
        refresh.map { permissionStatus(permission) }.distinctUntilChanged()

    override suspend fun requestPermission(permission: ProductPermission): DomainResult<PermissionStatus> =
        withContext(Dispatchers.Main.immediate) {
            val actions = foreground() ?: return@withContext interrupted()
            when (val result = actions.requestPermission(permission)) {
                is DomainResult.Rejected -> result
                is DomainResult.Success -> {
                    refreshPlatformState()
                    DomainResult.Success(permissionStatus(permission))
                }
            }
        }

    private fun permissionStatus(permission: ProductPermission): PermissionStatus = try {
        val granted = when (permission) {
            ProductPermission.VPN_CONSENT -> VpnService.prepare(context) == null
            ProductPermission.NOTIFICATIONS -> NotificationManagerCompat.from(context).areNotificationsEnabled() &&
                (Build.VERSION.SDK_INT < 33 || ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED)
            ProductPermission.CAMERA -> ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
            // No network-identity permission or raw SSID collection is admitted by this app.
            ProductPermission.NETWORK_IDENTITY -> return PermissionStatus.UNAVAILABLE
        }
        if (granted) PermissionStatus.GRANTED else PermissionStatus.NOT_GRANTED
    } catch (_: RuntimeException) { PermissionStatus.UNAVAILABLE }

    override fun observeSystemState(): Flow<SystemPolicyState> = combine(runtimePolicy, refresh) { state, _ ->
        state.copy(batteryRestricted = if (Build.VERSION.SDK_INT >= 28)
            context.getSystemService(ActivityManager::class.java)?.isBackgroundRestricted else null)
    }.distinctUntilChanged()

    override fun observeNetwork(): Flow<NetworkPolicyState> = callbackFlow {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        var current: Network? = null
        fun absent() = NetworkPolicyState(false, null, null, NetworkIdentityCategory.UNKNOWN, null)
        trySend(absent())
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { current = network }
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                if (network != current) return
                trySend(NetworkPolicyState(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
                    !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
                    NetworkIdentityCategory.UNKNOWN, null))
            }
            override fun onLost(network: Network) {
                if (current == network) { current = null; trySend(absent()) }
            }
        }
        try { manager.registerDefaultNetworkCallback(callback) }
        catch (_: RuntimeException) { close(); return@callbackFlow }
        awaitClose { manager.unregisterNetworkCallback(callback) }
    }.distinctUntilChanged()

    override suspend fun installedApplications(): DomainResult<List<InstalledApplication>> = withContext(Dispatchers.IO) {
        try {
            val manager = context.packageManager
            val query = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            val resolved = if (Build.VERSION.SDK_INT >= 33)
                manager.queryIntentActivities(query, PackageManager.ResolveInfoFlags.of(0))
            else { @Suppress("DEPRECATION") manager.queryIntentActivities(query, 0) }
            DomainResult.Success(resolved.mapNotNull { info ->
                val app = info.activityInfo?.applicationInfo ?: return@mapNotNull null
                InstalledApplication(app.packageName, info.loadLabel(manager).toString().take(128),
                    app.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0)
            }.distinctBy { it.packageName }.sortedBy { it.label.lowercase() }.take(512))
        } catch (_: RuntimeException) { DomainResult.Rejected(ProductFailure(ProductFailureCode.INTERNAL_FAILURE)) }
    }

    override fun observeLocale(): Flow<ProductLocale> = refresh.map {
        when (AppCompatDelegate.getApplicationLocales().toLanguageTags()) {
            "en" -> ProductLocale.ENGLISH
            "ckb" -> ProductLocale.SORANI
            "ku-Latn" -> ProductLocale.KURMANJI
            "ar" -> ProductLocale.ARABIC
            "fa" -> ProductLocale.PERSIAN
            else -> ProductLocale.SYSTEM
        }
    }.distinctUntilChanged()

    override suspend fun setLocale(locale: ProductLocale): DomainResult<Unit> = withContext(Dispatchers.Main.immediate) {
        if (foreground() == null) return@withContext interrupted()
        val tag = when (locale) {
            ProductLocale.SYSTEM -> ""
            ProductLocale.ENGLISH -> "en"
            ProductLocale.SORANI -> "ckb"
            ProductLocale.KURMANJI -> "ku-Latn"
            ProductLocale.ARABIC -> "ar"
            ProductLocale.PERSIAN -> "fa"
        }
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(tag))
        refreshPlatformState()
        DomainResult.Success(Unit)
    }

    override fun observeClipboard(): Flow<ClipboardState> = refresh.map {
        foreground()?.clipboardState() ?: ClipboardState.OTHER_OR_UNAVAILABLE
    }.distinctUntilChanged()
    override suspend fun previewClipboardImport(): DomainResult<ProfileImportPreview> = withContext(Dispatchers.Main.immediate) {
        foreground()?.previewClipboardImport() ?: interrupted()
    }
    override suspend fun copyRedactedSummary(profileId: CatalogId): DomainResult<Unit> = withContext(Dispatchers.Main.immediate) {
        foreground()?.copyRedactedSummary(profileId) ?: interrupted()
    }
    override suspend fun clearOwnedClipboard(): DomainResult<Unit> = withContext(Dispatchers.Main.immediate) {
        (foreground()?.clearOwnedClipboard() ?: interrupted()).also { refreshPlatformState() }
    }
    override fun observeScreenshotPolicy(): Flow<ScreenshotPolicy> = refresh.map {
        foreground()?.screenshotPolicy() ?: ScreenshotPolicy.ALLOWED
    }.distinctUntilChanged()
    override suspend fun setScreenshotPolicy(policy: ScreenshotPolicy): DomainResult<Unit> = withContext(Dispatchers.Main.immediate) {
        (foreground()?.setScreenshotPolicy(policy) ?: interrupted()).also { refreshPlatformState() }
    }
    override suspend fun openPlatformSettings(setting: PlatformSetting): DomainResult<Unit> = withContext(Dispatchers.Main.immediate) {
        foreground()?.openSettings(setting) ?: interrupted()
    }
    private fun interrupted() = DomainResult.Rejected(ProductFailure(ProductFailureCode.OPERATION_INTERRUPTED))
}
