// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade

@RunWith(AndroidJUnit4::class)
class ProtectedStateResetDeviceTest {
    @Test
    fun explicitResetRecreatesAnEmptyUsableProtectedStore() = runBlocking {
        val application =
            InstrumentationRegistry.getInstrumentation()
                .targetContext.applicationContext as KurdistanApplication
        val root = application.compositionRoot

        assertTrue(root.initializeProtectedStateForExplicitUserAction())
        assertTrue(root.resetProtectedStateConfirmed() is ProtectedStateApplicationFacade.CommandResult.Committed)
        assertNull("reset must not recreate state", root.protectedStateFacade())
        assertTrue("replacement requires a distinct explicit action", root.initializeProtectedStateForExplicitUserAction())
        val replacement = root.protectedStateFacade()
        assertNotNull(replacement)
        assertTrue(requireNotNull(replacement!!.readProjection()).profiles.isEmpty())
    }
}
