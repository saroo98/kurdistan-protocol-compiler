// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import org.kurdistanvpn.runtime.api.RuntimeAuthorityLimits

/** Shared classification for the launch and foreground-promotion boundaries. */
fun runtimeStartFailure(context: android.content.Context, failure: Throwable): String = when {
    android.os.Build.VERSION.SDK_INT >= 31 &&
        failure is android.app.ForegroundServiceStartNotAllowedException -> "FOREGROUND_START_BLOCKED"
    failure is SecurityException -> {
        val consentMissing = try { android.net.VpnService.prepare(context) != null } catch (_: Exception) { false }
        if (consentMissing) "CONSENT_REJECTED" else "RUNTIME_PERMISSION_DENIED"
    }
    else -> "RUNTIME_START_FAILED"
}

enum class RuntimePrivateMarker { ABSENT, VALID, MALFORMED }

/** Adapter must flag unparcel failures and every forbidden/reserved extra before classification. */
data class SanitizedRuntimeCommand(val action: String?, val marker: RuntimePrivateMarker,
    val hasReservedExtras: Boolean, val requestId: String?, val malformed: Boolean = false)

sealed interface RuntimeServiceCommand {
    data class Manual(val requestId: String) : RuntimeServiceCommand
    data object AutomaticTrigger : RuntimeServiceCommand
    data object Stop : RuntimeServiceCommand
    data object Recover : RuntimeServiceCommand
    data class Rejected(val reason: String) : RuntimeServiceCommand

    companion object {
        const val ACTION_START = "org.kurdistanvpn.runtime.action.START"
        const val ACTION_STOP = "org.kurdistanvpn.runtime.action.STOP"
        const val ACTION_RECOVER = "org.kurdistanvpn.runtime.action.RECOVER_INTERNET"
        const val MARKER_KEY = "private_command_version"
        const val MARKER_VERSION = 2
        const val REQUEST_KEY = "authority_request"

        /** Only bounded scalar metadata is admitted. Neither a marker nor a request ID is authority. */
        fun fromScalars(action: String?, extras: Map<String, Any?>): RuntimeServiceCommand {
            if (extras.size > 2 || action?.length?.let { it > 256 } == true)
                return Rejected("MALFORMED_PRIVATE_COMMAND")
            val snapshot = extras.toMap()
            if (snapshot.keys.any { it != MARKER_KEY && it != REQUEST_KEY })
                return Rejected("FORBIDDEN_START_EXTRA")
            val marker = when {
                !snapshot.containsKey(MARKER_KEY) -> RuntimePrivateMarker.ABSENT
                snapshot[MARKER_KEY] is Int && snapshot[MARKER_KEY] == MARKER_VERSION -> RuntimePrivateMarker.VALID
                else -> RuntimePrivateMarker.MALFORMED
            }
            val request = snapshot[REQUEST_KEY]
            if (snapshot.containsKey(REQUEST_KEY) && request !is String)
                return Rejected("MALFORMED_REQUEST_ID")
            return classify(SanitizedRuntimeCommand(action, marker, false, request as String?))
        }
        fun classify(input: SanitizedRuntimeCommand): RuntimeServiceCommand {
            if (input.malformed || input.hasReservedExtras || input.marker == RuntimePrivateMarker.MALFORMED)
                return Rejected("MALFORMED_PRIVATE_COMMAND")
            if (input.marker == RuntimePrivateMarker.VALID) return when (input.action) {
                ACTION_START -> input.requestId?.takeIf(RuntimeAuthorityLimits::validId)?.let(::Manual)
                    ?: Rejected("INVALID_REQUEST_ID")
                ACTION_STOP -> if (input.requestId == null) Stop else Rejected("STOP_HAS_AUTHORITY")
                ACTION_RECOVER -> if (input.requestId == null) Recover else Rejected("RECOVERY_HAS_AUTHORITY")
                else -> Rejected("INVALID_PRIVATE_ACTION")
            }
            if (input.requestId != null || input.action == ACTION_START || input.action == ACTION_STOP ||
                input.action?.startsWith("org.kurdistanvpn.runtime.action.") == true) return Rejected("UNMARKED_PRIVATE_COMMAND")
            // Null Intent/action, standard VPN and OEM lifecycle actions carry no authority.
            return AutomaticTrigger
        }
    }
}
