// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import android.app.Activity
import android.app.KeyguardManager
import android.os.Build
import android.os.SystemClock
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import org.kurdistanvpn.core.model.AllowedAuthenticator

internal data class SensitiveAuthenticationPolicy(val mask: Int, val legacyCredential: Boolean)
internal fun sensitiveAuthenticationPolicy(sdk: Int, allowed: Set<AllowedAuthenticator>): SensitiveAuthenticationPolicy? {
    if (allowed.isEmpty()) return null
    val credential = AllowedAuthenticator.DEVICE_CREDENTIAL in allowed
    val mask = (if (AllowedAuthenticator.STRONG_BIOMETRIC in allowed) BiometricManager.Authenticators.BIOMETRIC_STRONG else 0) or
        (if (credential) BiometricManager.Authenticators.DEVICE_CREDENTIAL else 0)
    return SensitiveAuthenticationPolicy(mask, sdk < 30 && credential)
}

enum class SensitiveAction {
    REVEAL,
    COPY,
    SHOW_QR,
    EXPORT_PROFILE,
    CREATE_BACKUP,
}

internal class SensitiveActionAuthorizer(
    private val activity: FragmentActivity,
    private val effectOwner: () -> ProductActivityEffects = { ProductActivityEffects() },
) : DefaultLifecycleObserver {
    private var effects: ProductActivityEffects? = null
    private var request: ActivityEffectRequest? = null
    private var pending: ((Boolean) -> Unit)? = null
    private var result: Boolean? = null
    private var started = 0L
    private var prompt: BiometricPrompt? = null
    var isDeviceCredentialPending = false
        private set
    private val credential = activity.activityResultRegistry.register("product-sensitive-credential", activity,
        ActivityResultContracts.StartActivityForResult()) {
        complete(it.resultCode == Activity.RESULT_OK)
    }

    init { activity.lifecycle.addObserver(this) }

    private fun complete(accepted: Boolean) {
        if (pending == null || result != null) return
        result = accepted && SystemClock.elapsedRealtime() - started in 0..60_000
        if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) deliver()
    }

    private fun deliver() {
        val accepted = result ?: return
        val callback = pending ?: return
        val current = request
        val confirmed = current != null && effects?.complete(current.id, current.operationId, true) == EffectCompletion.COMPLETED
        request = null; effects = null
        pending = null; result = null; prompt = null; isDeviceCredentialPending = false
        callback(confirmed && accepted && SystemClock.elapsedRealtime() - started in 0..60_000)
    }

    override fun onResume(owner: LifecycleOwner) { deliver() }
    override fun onDestroy(owner: LifecycleOwner) {
        val callback = pending
        request?.let { effects?.cancel(it.id) }
        request = null; effects = null
        pending = null; result = null; isDeviceCredentialPending = false
        prompt?.cancelAuthentication(); prompt = null
        callback?.invoke(false)
    }

    fun authorize(
        action: SensitiveAction,
        title: String,
        subtitle: String,
        allowedAuthenticators: Set<AllowedAuthenticator> = setOf(AllowedAuthenticator.STRONG_BIOMETRIC, AllowedAuthenticator.DEVICE_CREDENTIAL),
        onResult: (Boolean) -> Unit,
    ) {
        val policy = sensitiveAuthenticationPolicy(Build.VERSION.SDK_INT, allowedAuthenticators)
            ?: run { onResult(false); return }
        if (pending != null || !activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
            onResult(false)
            return
        }
        val owner = effectOwner()
        val next = ActivityEffectRequest(org.kurdistanvpn.core.model.CatalogId(java.util.UUID.randomUUID().toString()),
            org.kurdistanvpn.core.model.CatalogId(java.util.UUID.randomUUID().toString()), ActivityEffectKind.SENSITIVE_AUTHENTICATION)
        if (!owner.offer(next)) { onResult(false); return }
        if (!owner.claim(next.id, activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED))) {
            owner.cancel(next.id); onResult(false); return
        }
        effects = owner; request = next
        pending = onResult
        started = SystemClock.elapsedRealtime()
        // Strong+credential is unsupported on API28-29. Use the real system credential
        // screen on older releases, never BIOMETRIC_WEAK or a successful fallback.
        if (policy.legacyCredential) {
            val keyguard = activity.getSystemService(KeyguardManager::class.java)
            @Suppress("DEPRECATION")
            val intent = if (keyguard?.isDeviceSecure == true)
                keyguard.createConfirmDeviceCredentialIntent(title, subtitle) else null
            if (intent == null) { complete(false); return }
            isDeviceCredentialPending = true
            try { credential.launch(intent) } catch (_: RuntimeException) { complete(false) }
            return
        }
        val authenticators = policy.mask
        val availability = BiometricManager.from(activity).canAuthenticate(authenticators)
        if (availability != BiometricManager.BIOMETRIC_SUCCESS) {
            complete(false)
            return
        }
        val activePrompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult,
                ) {
                    complete(true)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    complete(false)
                }
            },
        )
        prompt = activePrompt
        try { activePrompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setAllowedAuthenticators(authenticators)
                .apply {
                    if (AllowedAuthenticator.DEVICE_CREDENTIAL !in allowedAuthenticators)
                        setNegativeButtonText(activity.getString(android.R.string.cancel))
                }
                .build(),
        ) } catch (_: RuntimeException) { complete(false) }
    }
}
