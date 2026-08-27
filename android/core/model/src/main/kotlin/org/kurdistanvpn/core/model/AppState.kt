// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.model

sealed interface AppState {
    data object Booting : AppState
    data object CompatibilityCheck : AppState
    data object FirstLaunch : AppState
    data object LockedStorage : AppState
    data object NoProfiles : AppState
    data class Ready(val profiles: List<ProfileSummary>) : AppState
    data class Importing(val source: ImportSource) : AppState
    data class ImportPreview(val preview: RedactedProfilePreview) : AppState
    data class ImportRejected(val error: OperationError) : AppState
    data object MigrationRequired : AppState
    data object KeyInvalidated : AppState
    data object DegradedStorage : AppState
    data object Quarantined : AppState
    data object FatalRecovery : AppState
}

enum class ProtectedRecoveryReason {
    RECOVERY_REQUIRED,
    QUARANTINED,
    INCONSISTENT,
    CLEANUP_UNPROVEN,
    MUTATION_UNPROVEN,
}

enum class ProtectedRecoveryAction {
    RECOVER_PRESENTATION,
}

/**
 * User-visible protected-state condition. Only an actual pending presentation mutation may expose
 * the broker-backed recovery action; every other condition remains fail-closed and diagnostic-only.
 */
sealed interface ProtectedRecoveryPresentation {
    data object NotRequired : ProtectedRecoveryPresentation

    data class Required(
        val reason: ProtectedRecoveryReason,
        val action: ProtectedRecoveryAction? = null,
    ) : ProtectedRecoveryPresentation {
        init {
            require(action == null || reason == ProtectedRecoveryReason.RECOVERY_REQUIRED)
        }

        val canRecoverPresentation: Boolean
            get() = reason == ProtectedRecoveryReason.RECOVERY_REQUIRED &&
                action == ProtectedRecoveryAction.RECOVER_PRESENTATION
    }
}

/** Ephemeral UI confirmation. It is never persisted or restored after process recreation. */
enum class ProtectedRecoveryConfirmation {
    UNCONFIRMED,
    PREPARED;

    fun prepare(presentation: ProtectedRecoveryPresentation): ProtectedRecoveryConfirmation =
        if ((presentation as? ProtectedRecoveryPresentation.Required)?.canRecoverPresentation == true) {
            PREPARED
        } else {
            UNCONFIRMED
        }

    fun permits(presentation: ProtectedRecoveryPresentation): Boolean =
        this == PREPARED &&
            (presentation as? ProtectedRecoveryPresentation.Required)?.canRecoverPresentation == true

    fun cancel(): ProtectedRecoveryConfirmation = UNCONFIRMED
}

/** Transient UI consent only. The broker still validates all migration preconditions. */
enum class ProtectedStateMigrationConfirmation {
    UNCONFIRMED,
    PREPARED;

    fun prepare(available: Boolean): ProtectedStateMigrationConfirmation =
        if (available) PREPARED else UNCONFIRMED

    fun permitsMigration(available: Boolean): Boolean = available && this == PREPARED

    fun cancel(): ProtectedStateMigrationConfirmation = UNCONFIRMED
}

enum class ImportSource {
    FILE,
    KURD_URI,
    CLIPBOARD,
    SHARE_INTENT,
    SINGLE_QR,
    MULTIPART_QR,
}

enum class ProfileTrust {
    VERIFIED_NONPRODUCTION,
    VERIFIED_PRODUCTION,
    UNAVAILABLE,
    REJECTED,
}

enum class StorageHealth {
    AVAILABLE,
    LOCKED,
    KEY_INVALIDATED,
    DEGRADED,
    QUARANTINED,
}

enum class RuntimeAvailability {
    PHASE_9_NO_RUNTIME,
}

enum class ThemePreference {
    SYSTEM,
    LIGHT,
    DARK,
}

data class Phase9Settings(
    val theme: ThemePreference = ThemePreference.SYSTEM,
    val highContrast: Boolean = false,
    val reducedMotion: Boolean = false,
    val connection: ConnectionPreferences = ConnectionPreferences(),
    val tunnel: TunnelPreferences = TunnelPreferences(),
    val routing: RoutingPreferences = RoutingPreferences(),
    val updates: UpdatePreferences = UpdatePreferences(),
    val probes: ProbePreferences = ProbePreferences(),
    val diagnostics: DiagnosticPreferences = DiagnosticPreferences(),
    val expert: ExpertPreferences = ExpertPreferences(),
    val profiles: ProfilePreferences = ProfilePreferences(),
)

data class CompatibilitySummary(
    val goCoreVersion: String,
    val profileSchema: String,
    val strategyRegistry: String,
    val relaySchema: String,
    val diagnosticSchema: String,
    val cryptoSuite: Int,
)

data class ProfileSummary(
    val localRecordId: String,
    val displayAlias: String,
    val trust: ProfileTrust,
    val generation: ULong,
    val expiresAtEpochSeconds: Long,
)

data class RedactedProfilePreview(
    val artifactClass: String,
    val audienceClass: String,
    val contentFingerprint: String,
    val lineageFingerprint: String,
    val generation: ULong,
    val validUntilEpochSeconds: Long,
    val sealed: Boolean,
    val deploymentFingerprint: String = "",
    val relayEndpointSummary: String = "",
    val authorityScope: String = "",
    val updateLocation: String = "",
    val ownerControlled: Boolean = false,
    val updatesEnabled: Boolean = false,
)

data class EnrollmentKeySummary(
    val localRecordId: String,
    val requestFingerprint: String,
    val createdAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
    val boundProfileCount: Int,
)

data class QrDisplayMatrix(
    val width: Int,
    val modules: BooleanArray,
) {
    init {
        require(width in 21..177)
        require(modules.size == width * width)
    }
}

sealed interface EnrollmentUiState {
    data object NoEnrollmentKey : EnrollmentUiState
    data object Working : EnrollmentUiState
    data class RequestReady(val keys: List<EnrollmentKeySummary>) : EnrollmentUiState
    data class AwaitingProfile(val keys: List<EnrollmentKeySummary>) : EnrollmentUiState
    data class ProfileVerified(val keys: List<EnrollmentKeySummary>) : EnrollmentUiState
    data class MissingKey(val fingerprint: String) : EnrollmentUiState
    data object KeyInvalidated : EnrollmentUiState
    data object RecoveryRequired : EnrollmentUiState
    data class OfferKeyDeletion(val key: EnrollmentKeySummary) : EnrollmentUiState
    data class Failed(val error: OperationError) : EnrollmentUiState
}

enum class OperationError {
    INVALID_INPUT,
    SIZE_LIMIT,
    AUTHORITY_UNAVAILABLE,
    TRUST_REJECTED,
    POLICY_REJECTED,
    DUPLICATE,
    STORAGE_FAILURE,
    KEY_INVALIDATED,
    RECOVERY_REQUIRED,
    QUARANTINED,
    INCOMPATIBLE_NATIVE_CORE,
    CANCELLED,
    INTERNAL_FAILURE,
    ENDPOINT_UNAVAILABLE,
    TLS_REJECTED,
    KURD_AUTH_REJECTED,
    TUN_IO_FAILED,
    DNS_UNAVAILABLE,
    NETWORK_LOST,
    FALLBACK_EXHAUSTED,
    NODE_DRAINED,
    DEPLOYMENT_DISABLED,
    RESOURCE_LIMIT,
    STATE_CORRUPT,
}

sealed interface BackupWorkflowState {
    data object Idle : BackupWorkflowState
    data object Working : BackupWorkflowState
    data class RestorePreview(
        val recordCount: Int,
        val nativeProfileCount: Int,
    ) : BackupWorkflowState
    data class Completed(val restoredProfiles: Int) : BackupWorkflowState
    data class Failed(val error: OperationError) : BackupWorkflowState
}

sealed interface DiagnosticWorkflowState {
    data object Idle : DiagnosticWorkflowState
    data object Working : DiagnosticWorkflowState
    data class Preview(
        val categoryCount: Int,
        val entryCount: String,
        val encodedSize: String,
    ) : DiagnosticWorkflowState
    data object Completed : DiagnosticWorkflowState
    data class Failed(val error: OperationError) : DiagnosticWorkflowState
}
