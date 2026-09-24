// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.model

enum class ProductFailureCode {
    INVALID_INPUT, SIZE_LIMIT, PROFILE_UNTRUSTED, PROFILE_EXPIRED, PROFILE_REVOKED,
    PROFILE_ROLLBACK, PROFILE_WRONG_DEVICE, PROFILE_INCOMPATIBLE, STORAGE_LOCKED,
    STORAGE_KEY_INVALIDATED, STORAGE_DEGRADED, MIGRATION_REQUIRED, VPN_CONSENT_REQUIRED,
    VPN_CONSENT_DENIED, NETWORK_UNAVAILABLE, NETWORK_IDENTITY_UNAVAILABLE, CAPTIVE_PORTAL,
    NODE_UNREACHABLE, SESSION_AUTHENTICATION_FAILED, NO_PERMITTED_STRATEGY,
    SOCKET_PROTECTION_FAILED, TUN_ESTABLISH_FAILED, ROUTE_POLICY_REJECTED,
    DNS_POLICY_REJECTED, DNS_HEALTH_FAILED, APP_POLICY_DRIFT, FOREGROUND_START_BLOCKED,
    RECONNECT_EXHAUSTED, UPDATE_SIGNATURE_INVALID, UPDATE_ROLLBACK, UPDATE_INCOMPATIBLE,
    PROXY_BIND_FAILED, PROXY_AUTHENTICATION_FAILED, LOW_MEMORY, THERMAL_LIMIT,
    CANCELLED, INTERNAL_FAILURE, OPERATION_ALREADY_ACTIVE, OPERATION_INTERRUPTED,
    RESOURCE_LIMIT, RATE_LIMITED, OPERATION_TIMED_OUT, UPDATE_FETCH_REJECTED,
}

/** Typed localization references. UI must exhaustively resolve these to resources, never enum names. */
sealed interface ProductText {
    data class OperationTitle(val category: OperationCategory) : ProductText
    data class OperationExplanation(val category: OperationCategory) : ProductText
    data class ConnectionTitle(val category: ConnectionCategory) : ProductText
    data class ConnectionExplanation(val category: ConnectionCategory) : ProductText
    data class FailureTitle(val code: ProductFailureCode) : ProductText
    data class FailureExplanation(val code: ProductFailureCode) : ProductText
    data class ActionLabel(val action: ProductAction) : ProductText
}

enum class ProductAction {
    NONE, IMPORT_PROFILE, REVIEW_PROFILE, UNLOCK_STORAGE, OPEN_SETTINGS, RETRY, DISMISS,
    CONNECT, DISCONNECT, GRANT_PERMISSION, RECOVER_INTERNET, CANCEL, CONFIRM, RESUME,
    REVIEW_IMPORT, REVIEW_UPDATE, REVIEW_RESTORE, REVIEW_BACKUP, REVIEW_RESET, REVIEW_PROBE, REVIEW_SETTINGS,
}

enum class ConnectionCategory {
    NO_PROFILE, STORAGE_BLOCKED, DISCONNECTED, AWAITING_VPN_PERMISSION, PREPARING, CONNECTING,
    CONNECTED, DEGRADED, FALLING_BACK, RECONNECTING, STOPPING, RECOVERING, REVOKED,
    POLICY_BLOCKED, FAILED, SAFE_MODE,
}
enum class StorageBlockReason { LOCKED, KEY_INVALIDATED, DEGRADED, MIGRATION_REQUIRED }
enum class DegradationReason { HEALTH, NETWORK, RESOURCE_LIMIT }
enum class RecoveryReason { PROCESS_RECREATION, INTERRUPTED_OPERATION, INTERNET_RECOVERY }
enum class RevocationReason { PROFILE, DEPLOYMENT, DEVICE }
enum class PolicyBlockReason { NO_PERMITTED_STRATEGY, ROUTE, DNS, APP_POLICY, NETWORK_TRUST }
enum class SafeModeReason { REPEATED_FAILURE, INCONSISTENT_STATE }
enum class AnnouncementPolicy { NONE, POLITE, ASSERTIVE }
enum class PersistencePolicy { NEVER_PERSIST_AUTHORITY }

data class ReadyContext(val profileId: CatalogId)
data class AttemptSummary(val attempt: Int) { init { require(attempt in 1..10) } }
data class VerifiedRouteSnapshot(val profileId: CatalogId, val ipMode: IpMode, val mtu: Int) {
    init { require(ipMode != IpMode.AUTO && mtu in 1280..1500) }
    override fun toString(): String = "VerifiedRouteSnapshot(redacted)"
}
data class FallbackProgress(val attempt: Int, val maximum: Int) {
    init { require(maximum in 1..256 && attempt in 1..maximum) }
}
data class ReconnectProgress(val attempt: Int, val maximum: Int) {
    init { require(maximum in 1..10 && attempt in 1..maximum) }
}
data class RecoveryProgress(val reason: RecoveryReason)
data class RevocationSummary(val reason: RevocationReason)
data class SafeModeSummary(val reason: SafeModeReason)

class StateMetadata(
    val title: ProductText,
    val explanation: ProductText,
    val primaryAction: ProductAction,
    val secondaryAction: ProductAction,
    disabledActions: Set<ProductAction>,
    val announcement: AnnouncementPolicy,
    val persistence: PersistencePolicy = PersistencePolicy.NEVER_PERSIST_AUTHORITY,
) {
    val disabledActions: Set<ProductAction> = java.util.Collections.unmodifiableSet(disabledActions.toSet())
    init { require(primaryAction !in disabledActions && secondaryAction !in disabledActions) }
    val primaryActionLabel: ProductText get() = ProductText.ActionLabel(primaryAction)
    val secondaryActionLabel: ProductText get() = ProductText.ActionLabel(secondaryAction)
}

sealed interface ConnectionState {
    data object NoProfile : ConnectionState
    data class StorageBlocked(val reason: StorageBlockReason) : ConnectionState
    data class Disconnected(val context: ReadyContext) : ConnectionState
    data object AwaitingVpnPermission : ConnectionState
    data class Preparing(val attempt: AttemptSummary) : ConnectionState
    data class Connecting(val attempt: AttemptSummary) : ConnectionState
    data class Connected(val route: VerifiedRouteSnapshot) : ConnectionState
    data class Degraded(val route: VerifiedRouteSnapshot, val reason: DegradationReason) : ConnectionState
    data class FallingBack(val progress: FallbackProgress) : ConnectionState
    data class Reconnecting(val progress: ReconnectProgress) : ConnectionState
    data object Stopping : ConnectionState
    data class Recovering(val progress: RecoveryProgress) : ConnectionState
    data class Revoked(val summary: RevocationSummary) : ConnectionState
    data class PolicyBlocked(val reason: PolicyBlockReason) : ConnectionState
    data class Failed(val failure: ProductFailure) : ConnectionState
    data class SafeMode(val summary: SafeModeSummary) : ConnectionState

    val category: ConnectionCategory get() = when (this) {
        NoProfile -> ConnectionCategory.NO_PROFILE
        is StorageBlocked -> ConnectionCategory.STORAGE_BLOCKED
        is Disconnected -> ConnectionCategory.DISCONNECTED
        AwaitingVpnPermission -> ConnectionCategory.AWAITING_VPN_PERMISSION
        is Preparing -> ConnectionCategory.PREPARING
        is Connecting -> ConnectionCategory.CONNECTING
        is Connected -> ConnectionCategory.CONNECTED
        is Degraded -> ConnectionCategory.DEGRADED
        is FallingBack -> ConnectionCategory.FALLING_BACK
        is Reconnecting -> ConnectionCategory.RECONNECTING
        Stopping -> ConnectionCategory.STOPPING
        is Recovering -> ConnectionCategory.RECOVERING
        is Revoked -> ConnectionCategory.REVOKED
        is PolicyBlocked -> ConnectionCategory.POLICY_BLOCKED
        is Failed -> ConnectionCategory.FAILED
        is SafeMode -> ConnectionCategory.SAFE_MODE
    }

    val metadata: StateMetadata get() {
        val primary = when (this) {
            NoProfile -> ProductAction.IMPORT_PROFILE
            is StorageBlocked -> if (reason == StorageBlockReason.LOCKED) ProductAction.UNLOCK_STORAGE else ProductAction.OPEN_SETTINGS
            is Disconnected -> ProductAction.CONNECT
            AwaitingVpnPermission -> ProductAction.GRANT_PERMISSION
            is Preparing, is Connecting, is FallingBack, is Reconnecting -> ProductAction.DISCONNECT
            is Connected, is Degraded -> ProductAction.DISCONNECT
            Stopping, is Recovering -> ProductAction.NONE
            is Revoked -> ProductAction.REVIEW_PROFILE
            is PolicyBlocked -> ProductAction.OPEN_SETTINGS
            is Failed -> failure.nextAction
            is SafeMode -> ProductAction.RECOVER_INTERNET
        }
        val secondary = when (this) {
            is Connected, is Degraded, is Preparing, is Connecting,
            is FallingBack, is Reconnecting -> ProductAction.RECOVER_INTERNET
            AwaitingVpnPermission -> ProductAction.CANCEL
            else -> ProductAction.NONE
        }
        return StateMetadata(
            ProductText.ConnectionTitle(category), ProductText.ConnectionExplanation(category), primary, secondary,
            ProductAction.entries.filter { it != ProductAction.NONE && it != primary && it != secondary }.toSet(),
            when (this) {
                is Revoked, is Failed, is SafeMode -> AnnouncementPolicy.ASSERTIVE
                else -> AnnouncementPolicy.POLITE
            },
        )
    }

    /** No persisted presentation state proves a live session or fresh authority after process death. */
    fun processRecreated(): ConnectionState = when (this) {
        NoProfile, is StorageBlocked, is Disconnected, is Revoked, is PolicyBlocked,
        is Failed, is SafeMode -> this
        else -> Recovering(RecoveryProgress(RecoveryReason.PROCESS_RECREATION))
    }
}

/** Deliberately has no exception, message, endpoint, or arbitrary diagnostic field. */
data class ProductFailure(val code: ProductFailureCode) {
    val title: ProductText get() = ProductText.FailureTitle(code)
    val explanation: ProductText get() = ProductText.FailureExplanation(code)
    val nextAction: ProductAction get() = when (code) {
        ProductFailureCode.PROFILE_UNTRUSTED, ProductFailureCode.PROFILE_EXPIRED,
        ProductFailureCode.PROFILE_REVOKED, ProductFailureCode.PROFILE_ROLLBACK,
        ProductFailureCode.PROFILE_WRONG_DEVICE, ProductFailureCode.PROFILE_INCOMPATIBLE,
        ProductFailureCode.UPDATE_SIGNATURE_INVALID, ProductFailureCode.UPDATE_ROLLBACK,
        ProductFailureCode.UPDATE_INCOMPATIBLE -> ProductAction.REVIEW_PROFILE
        ProductFailureCode.STORAGE_LOCKED -> ProductAction.UNLOCK_STORAGE
        ProductFailureCode.VPN_CONSENT_REQUIRED, ProductFailureCode.VPN_CONSENT_DENIED,
        ProductFailureCode.ROUTE_POLICY_REJECTED, ProductFailureCode.DNS_POLICY_REJECTED,
        ProductFailureCode.APP_POLICY_DRIFT -> ProductAction.OPEN_SETTINGS
        ProductFailureCode.NETWORK_UNAVAILABLE, ProductFailureCode.NODE_UNREACHABLE,
        ProductFailureCode.RECONNECT_EXHAUSTED, ProductFailureCode.RESOURCE_LIMIT,
        ProductFailureCode.OPERATION_TIMED_OUT, ProductFailureCode.UPDATE_FETCH_REJECTED -> ProductAction.RETRY
        ProductFailureCode.RATE_LIMITED -> ProductAction.DISMISS
        else -> ProductAction.DISMISS
    }
    override fun toString(): String = "ProductFailure(redacted)"
}
