// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Field-only entry point that deliberately has no Activity or Compose rule.
 * Repeated owner-VPS actions must not launch and tear down the product UI.
 */
@SdkSuppress(minSdkVersion = 26)
class Phase17FieldActionDeviceTest {
    @Test
    fun runRequestedFieldAction() = runBlocking {
        val requested = InstrumentationRegistry.getArguments()
            .getString("phase17FieldAction")
            ?.isNotBlank() == true
        if (!requested) {
            assertFalse(Phase17FieldHarness.runIfRequested())
            return@runBlocking
        }
        assertTrue(Phase17FieldHarness.runIfRequested())
    }
}
