// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.os.Build
import android.os.Process
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.kurdistanvpn.core.model.CatalogId
import org.kurdistanvpn.domain.DomainResult

/** Two host-orchestrated phases. A generic suite does not count a skipped phase as process-death proof. */
class SettingsDraftProcessDeviceTest {
    private fun app(): KurdistanApplication {
        check(Build.FINGERPRINT.contains("generic") || Build.MODEL.contains("sdk")) { "EMULATOR_ONLY" }
        return InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as KurdistanApplication
    }
    @Test fun stageBeforeProcessDeath(): Unit = runBlocking {
        assumeTrue(InstrumentationRegistry.getArguments().getString("draftPhase") == "stage")
        val app = app()
        Task7InstalledFixturePreparation.prepareProxyOrVerify(app)
        val marker = File(app.filesDir, "task13-draft-process-proof")
        check(!marker.exists()) { "PREVIOUS_PROOF_NOT_CONSUMED" }
        val repository = checkNotNull(app.compositionRoot.settingsRepository())
        val opened = (repository.openDraft() as DomainResult.Success).value
        val requested = opened.basedOn.settings.copy(highContrast = !opened.basedOn.settings.highContrast)
        assertTrue(repository.saveDraft(opened.id, requested) is DomainResult.Success)
        assertEquals(opened.basedOn.settings, (repository.appliedRevision() as DomainResult.Success).value.settings)
        // Test-only opaque IDs and original scalar, never credentials or authority.
        marker.outputStream().use { out ->
            java.io.DataOutputStream(out).apply {
                writeInt(Process.myPid()); writeUTF(opened.id.value); writeBoolean(opened.basedOn.settings.highContrast)
                flush(); out.fd.sync()
            }
        }
    }
    @Test fun resumeAfterProcessDeath() = runBlocking {
        assumeTrue(InstrumentationRegistry.getArguments().getString("draftPhase") == "resume")
        val app = app(); val marker = File(app.filesDir, "task13-draft-process-proof")
        require(marker.isFile && marker.length() in 1..128)
        val repository = checkNotNull(app.compositionRoot.settingsRepository())
        java.io.DataInputStream(marker.inputStream()).use { input ->
            assertNotEquals("Must be a different application process", input.readInt(), Process.myPid())
            val id = CatalogId(input.readUTF()); val original = input.readBoolean(); assertEquals(-1, input.read())
            val restored = (repository.resumeDraft(id) as DomainResult.Success).value
            assertEquals(!original, restored.requested.highContrast)
            assertEquals(original, (repository.appliedRevision() as DomainResult.Success).value.settings.highContrast)
            assertTrue(repository.cancel(id) is DomainResult.Success)
            assertTrue(repository.resumeDraft(id) is DomainResult.Rejected)
        }
        check(marker.delete())
    }
}
