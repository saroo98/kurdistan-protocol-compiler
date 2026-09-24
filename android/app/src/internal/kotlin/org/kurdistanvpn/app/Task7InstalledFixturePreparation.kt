// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.os.SystemClock
import java.io.File
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativejni.Task7InstalledFixtureNative
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.kurdistanvpn.data.protectedstate.ProtectedExternalPreviewResult
import org.kurdistanvpn.platform.importing.*
import org.kurdistanvpn.domain.DomainResult

internal fun task7InstalledCommittedJournalMatches(before: Long, after: Long): Boolean =
    // JournalControl.reserve consumes old+1 DIRTY and old+2 CLEAN, independently of settingsRevision.
    after == Math.addExact(before, 2)

internal fun task7UpdatePreparedMatchesV1(rows:List<String>,revision:Long,selected:String?,profiles:Int,
    probesMatch:Boolean,appliedMatch:Boolean):Boolean = rows.size==2 && rows[0].isNotEmpty() &&
    rows[1].toLongOrNull()==revision && rows[0]==selected && profiles==1 && probesMatch && appliedMatch

/** Explicit fresh-emulator setup only; never an application startup path. */
object Task7InstalledFixturePreparation {
    suspend fun prepareOrVerify(application: KurdistanApplication) = prepare(application,false)
    suspend fun prepareUpdateOrVerify(application: KurdistanApplication) = prepare(application,true)
    suspend fun prepareProxyOrVerify(application: KurdistanApplication) = prepare(application, false, true)
    private suspend fun prepare(application: KurdistanApplication, update:Boolean, proxy: Boolean = false) {
        check(application.packageName == "org.kurdistanvpn.app.internal")
        val root = application.compositionRoot
        val directory = File(application.filesDir, if (proxy) "task12-installed-proxy-v1" else if(update) "task7-installed-update-v2" else "task7-installed-v1")
        val marker = File(directory, "prepared-selection")
        val existing = root.protectedStateFacade()
        if (existing != null) {
            check(marker.isFile && marker.length() in 1..256) { "TASK7_EXISTING_STATE_REJECTED" }
            val rows = marker.readLines()
            check(rows.size == 2)
            val projection = checkNotNull(existing.readProjection())
            if (proxy) {
                // The emulator-only settings round trip commits a change and an exact restore.
                // Re-check the complete original fixture before advancing its non-authority marker.
                val before = checkNotNull(rows[1].toLongOrNull())
                if (projection.revision == before + 4) {
                    val expected = ProductSettings(profiles = ProfilePreferences(activeLocalRecordId = rows[0]),
                        probes = selectedProbe(), tunnelMode = TunnelMode.TUN_PLUS_PROXY)
                    check(projection.profiles.size == 1 && projection.settings == expected)
                    marker.outputStream().use { stream ->
                        stream.write("${rows[0]}\n${projection.revision}\n".toByteArray(Charsets.US_ASCII)); stream.fd.sync()
                    }
                }
                check(projection.revision == marker.readLines()[1].toLongOrNull() && projection.profiles.size == 1 &&
                    projection.settings.profiles.activeLocalRecordId == rows[0] &&
                    projection.settings.tunnelMode == TunnelMode.TUN_PLUS_PROXY && projection.settings.probes == selectedProbe())
                return
            }
            if(update) {
                val applied=checkNotNull(existing.settingsRepository()).appliedRevision()
                check(task7UpdatePreparedMatchesV1(rows,projection.revision,projection.settings.profiles.activeLocalRecordId,
                    projection.profiles.size,projection.settings.probes==selectedProbe(),
                    applied is DomainResult.Success && applied.value.settings==projection.settings)) { "TASK7_EXISTING_STATE_REJECTED" }
                return
            }
            check(projection.revision == rows[1].toLongOrNull() &&
                projection.settings.profiles.activeLocalRecordId == rows[0] && projection.profiles.size == 1)
            if (projection.settings.probes != selectedProbe()) {
                check(projection.settings.probes == ProbePreferences(method = ProbeMethod.TCP_CONNECT,
                    signedTargetId = CatalogId("1"), timeoutSeconds = 1)) { "TASK7_EXISTING_STATE_REJECTED" }
                val settingsOwner = checkNotNull(existing.settingsRepository())
                val applied = settingsOwner.appliedRevision()
                check(applied is DomainResult.Success && applied.value.settings == projection.settings)
                val requested = projection.settings.copy(probes = selectedProbe())
                val changed = existing.applyProductionSettings(projection.revision, applied.value.revision, requested)
                check(changed is ProtectedStateApplicationFacade.CommandResult.Committed)
                val verified = checkNotNull(existing.readProjection())
                val appliedAfter = settingsOwner.appliedRevision()
                check(appliedAfter is DomainResult.Success && appliedAfter.value.revision == changed.value.settingsRevision &&
                    appliedAfter.value.settings == requested)
                check(task7InstalledCommittedJournalMatches(projection.revision, verified.revision) && verified.settings == requested &&
                    verified.settings.profiles.activeLocalRecordId == rows[0] && verified.profiles.size == 1)
                check(marker.readLines() == rows)
                // An interrupted rewrite leaves a stale/partial marker and fails closed on reuse.
                marker.outputStream().use { stream ->
                    stream.write("${rows[0]}\n${verified.revision}\n".toByteArray(Charsets.US_ASCII)); stream.fd.sync()
                }
            }
            return
        }
        check(root.storageFailure == ProductCompositionRoot.StorageFailure.FIRST_USE && !directory.exists()) {
            "TASK7_FRESH_STATE_REQUIRED"
        }
        check(root.initializeProtectedStateForExplicitUserAction())
        val facade = checkNotNull(root.protectedStateFacade())
        val initial = checkNotNull(facade.readProjection())
        check(initial.profiles.isEmpty() && initial.settings.profiles.activeLocalRecordId == null)
        val enrollment = facade.createEnrollment(24 * 60 * 60, System.currentTimeMillis() / 1000)
        check(enrollment is ProtectedStateApplicationFacade.CommandResult.Committed)
        val request = checkNotNull(facade.enrollmentRequest(enrollment.value.localRecordId))
        val artifact = try { Task7InstalledFixtureNative().issueForPublicEnrollment(directory.absolutePath, request) }
            finally { request.fill(0) }
        val encoded = try { VerifyRequestEncoder.encode(ImportCandidate(IngressKind.FILE, ArtifactClass.DEVICE_RECIPIENT, listOf(artifact))) }
            finally { artifact.fill(0) }
        val selected = try {
            val preview = facade.previewExternalImport(encoded, { false }, SystemClock::elapsedRealtime)
            check(preview is ProtectedExternalPreviewResult.Ready)
            preview.preview.use { pending -> pending.confirm().use { confirmed ->
                val imported = facade.confirmImport(confirmed)
                check(imported is ProtectedStateApplicationFacade.CommandResult.Committed) {
                    when (imported) {
                        is ProtectedStateApplicationFacade.CommandResult.Committed -> "TASK7_IMPORT_COMMITTED"
                        is ProtectedStateApplicationFacade.CommandResult.Rejected -> "TASK7_IMPORT_REJECTED_${imported.error.name}"
                        ProtectedStateApplicationFacade.CommandResult.Busy -> "TASK7_IMPORT_BUSY"
                        ProtectedStateApplicationFacade.CommandResult.Unproven -> "TASK7_IMPORT_UNPROVEN"
                    }
                }
                imported.value
            } }
        } finally { encoded.fill(0) }
        val beforeSelection = checkNotNull(facade.readProjection())
        val settings = beforeSelection.settings.copy(profiles = beforeSelection.settings.profiles.copy(activeLocalRecordId = selected))
        val selection = facade.replaceSettings(beforeSelection.revision, settings)
        check(selection is ProtectedStateApplicationFacade.CommandResult.Committed) {
            val category = when (selection) {
                is ProtectedStateApplicationFacade.CommandResult.Committed -> "COMMITTED"
                is ProtectedStateApplicationFacade.CommandResult.Rejected -> "REJECTED_${selection.error.name}"
                ProtectedStateApplicationFacade.CommandResult.Busy -> "BUSY"
                ProtectedStateApplicationFacade.CommandResult.Unproven -> "UNPROVEN"
            }
            val observed = facade.readProjection()
            val state = when {
                observed == null -> "PROJECTION_UNAVAILABLE"
                observed.settings.profiles.activeLocalRecordId == selected -> "SELECTED_MATCH"
                else -> "SELECTED_DIFFERENT"
            }
            "TASK7_SELECTION_${category}_$state"
        }
        val beforeProduction = checkNotNull(facade.readProjection())
        check(beforeProduction.settings.profiles.activeLocalRecordId == selected)
        val requested = beforeProduction.settings.copy(probes = selectedProbe(),
            tunnelMode = if (proxy) TunnelMode.TUN_PLUS_PROXY else beforeProduction.settings.tunnelMode)
        check(facade.applyProductionSettings(beforeProduction.revision, 0, requested) is ProtectedStateApplicationFacade.CommandResult.Committed)
        val prepared = checkNotNull(facade.readProjection())
        check(prepared.settings.profiles.activeLocalRecordId == selected && prepared.settings.probes == selectedProbe())
        // A partial marker fails reuse rather than repairing/resetting protected state.
        check(marker.createNewFile())
        marker.outputStream().use { stream -> stream.write("$selected\n${prepared.revision}\n".toByteArray(Charsets.US_ASCII)); stream.fd.sync() }
    }

    fun selectedProbe() = ProbePreferences(method = ProbeMethod.TCP_CONNECT, signedTargetId = CatalogId("probe-1"), timeoutSeconds = 1)
}
