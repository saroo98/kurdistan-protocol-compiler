// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.model

sealed interface AppState {
    data object Booting : AppState
    data object CompatibilityCheck : AppState
    data object FirstLaunch : AppState
    data object LockedStorage : AppState
    data object NoProfiles : AppState
    class Ready(profiles: List<ProfileSummary>) : AppState {
        init { require(profiles.size <= 1024) }
        val profiles: List<ProfileSummary> = java.util.Collections.unmodifiableList(profiles.toList())
        fun copy(profiles: List<ProfileSummary> = this.profiles): Ready = Ready(profiles)
        override fun equals(other: Any?): Boolean = other is Ready && profiles == other.profiles
        override fun hashCode(): Int = profiles.hashCode()
        override fun toString(): String = "Ready(redacted)"
    }
    data class Importing(val source: ImportSource) : AppState
    data class ImportPreview(val preview: RedactedProfilePreview) : AppState
    data class ImportRejected(val error: OperationError) : AppState
    data object MigrationRequired : AppState
    data object CoreIncompatible : AppState
    data object CoreUnavailable : AppState
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
    NOT_ADMITTED,
}

enum class ThemePreference {
    SYSTEM,
    LIGHT,
    DARK,
}

data class ProductSettings(
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
    val tunnelMode: TunnelMode = TunnelMode.TUN_ONLY,
    val networkMeteredPolicy: NetworkMeteredPolicy = NetworkMeteredPolicy.ASK,
    val pausePolicy: PausePolicy = PausePolicy.NOT_PAUSED,
    val localProxy: LocalProxyPreferences = LocalProxyPreferences(),
    val privacy: PrivacyPreferences = PrivacyPreferences(),
    val notifications: NotificationPreferences = NotificationPreferences(),
    val automation: AutomationPreferences = AutomationPreferences(),
    val networkTrust: NetworkTrustPreferences = NetworkTrustPreferences(),
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
) {
    init {
        require(localRecordId.matches(Regex("[a-z0-9-]{1,64}")))
        require(displayAlias.length in 1..96 && expiresAtEpochSeconds >= 0)
    }
    override fun toString(): String = "ProfileSummary(redacted)"
}

enum class RedactedFieldPresence { NOT_PROVIDED, PROVIDED_REDACTED }
enum class PreviewAuthorityScope { UNAVAILABLE, DEPLOYMENT_LOCAL }

data class RedactedProfilePreview(
    val artifactClass: String,
    val audienceClass: String,
    val contentFingerprint: String,
    val lineageFingerprint: String,
    val generation: ULong,
    val validUntilEpochSeconds: Long,
    val sealed: Boolean,
    val deploymentFingerprint: String = "",
    val relayEndpoint: RedactedFieldPresence = RedactedFieldPresence.NOT_PROVIDED,
    val authorityScope: PreviewAuthorityScope = PreviewAuthorityScope.UNAVAILABLE,
    val updateSource: RedactedFieldPresence = RedactedFieldPresence.NOT_PROVIDED,
    val ownerControlled: Boolean = false,
    val updatesEnabled: Boolean = false,
) {
    init {
        require(listOf(artifactClass, audienceClass).all { it.matches(Regex("[A-Za-z0-9_-]{1,64}")) })
        require(listOf(contentFingerprint, lineageFingerprint).all { it.matches(Regex("[A-Za-z0-9_-]{1,255}")) })
        require(deploymentFingerprint.isEmpty() || deploymentFingerprint.matches(Regex("[A-Za-z0-9_-]{1,255}")))
        require(validUntilEpochSeconds >= 0)
    }
    override fun toString(): String = "RedactedProfilePreview(redacted)"
}

data class EnrollmentKeySummary(
    val localRecordId: String,
    val requestFingerprint: String,
    val createdAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
    val boundProfileCount: Int,
) {
    init {
        require(localRecordId.matches(Regex("[a-z0-9-]{1,64}")))
        require(requestFingerprint.length in 1..256)
        require(createdAtEpochSeconds >= 0 && expiresAtEpochSeconds >= createdAtEpochSeconds)
        require(boundProfileCount in 0..64)
    }
    override fun toString(): String = "EnrollmentKeySummary(redacted)"
}

class QrDisplayMatrix(
    val width: Int,
    modules: BooleanArray,
) {
    init {
        require(width in 21..177)
        require(modules.size == width * width)
    }
    private val ownedModules = modules.clone()
    val modules: BooleanArray get() = ownedModules.clone()
    fun copy(width: Int = this.width, modules: BooleanArray = ownedModules): QrDisplayMatrix = QrDisplayMatrix(width, modules)
    override fun equals(other: Any?): Boolean = other is QrDisplayMatrix && width == other.width && ownedModules.contentEquals(other.ownedModules)
    override fun hashCode(): Int = 31 * width + ownedModules.contentHashCode()
    override fun toString(): String = "QrDisplayMatrix(redacted)"
}

sealed interface EnrollmentUiState {
    data object NoEnrollmentKey : EnrollmentUiState
    data object Working : EnrollmentUiState
    class RequestReady(keys: List<EnrollmentKeySummary>) : EnrollmentUiState {
        init { require(keys.size <= 32) }
        val keys: List<EnrollmentKeySummary> = java.util.Collections.unmodifiableList(keys.toList())
        fun copy(keys: List<EnrollmentKeySummary> = this.keys): RequestReady = RequestReady(keys)
        override fun equals(other: Any?): Boolean = other is RequestReady && keys == other.keys
        override fun hashCode(): Int = keys.hashCode()
        override fun toString(): String = "RequestReady(redacted)"
    }
    class AwaitingProfile(keys: List<EnrollmentKeySummary>) : EnrollmentUiState {
        init { require(keys.size <= 32) }
        val keys: List<EnrollmentKeySummary> = java.util.Collections.unmodifiableList(keys.toList())
        fun copy(keys: List<EnrollmentKeySummary> = this.keys): AwaitingProfile = AwaitingProfile(keys)
        override fun equals(other: Any?): Boolean = other is AwaitingProfile && keys == other.keys
        override fun hashCode(): Int = keys.hashCode()
        override fun toString(): String = "AwaitingProfile(redacted)"
    }
    class ProfileVerified(keys: List<EnrollmentKeySummary>) : EnrollmentUiState {
        init { require(keys.size <= 32) }
        val keys: List<EnrollmentKeySummary> = java.util.Collections.unmodifiableList(keys.toList())
        fun copy(keys: List<EnrollmentKeySummary> = this.keys): ProfileVerified = ProfileVerified(keys)
        override fun equals(other: Any?): Boolean = other is ProfileVerified && keys == other.keys
        override fun hashCode(): Int = keys.hashCode()
        override fun toString(): String = "ProfileVerified(redacted)"
    }
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
    data object Exported : BackupWorkflowState
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
