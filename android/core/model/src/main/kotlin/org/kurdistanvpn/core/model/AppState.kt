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
)

enum class OperationError {
    INVALID_INPUT,
    SIZE_LIMIT,
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
