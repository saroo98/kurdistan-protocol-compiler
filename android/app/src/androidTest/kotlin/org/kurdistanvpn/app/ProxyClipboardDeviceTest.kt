// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.content.ClipData
import android.content.ClipboardManager
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test

class ProxyClipboardDeviceTest {
    @Test fun sensitiveCopyClearsOnlyItsOwnCurrentClip() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
        val focused = java.util.concurrent.atomic.AtomicBoolean(false)
        val deadline = android.os.SystemClock.elapsedRealtime() + 5000
        do {
            scenario.onActivity { focused.set(it.hasWindowFocus()) }
            if (!focused.get()) android.os.SystemClock.sleep(25)
        } while (!focused.get() && android.os.SystemClock.elapsedRealtime() < deadline)
        assertTrue("Clipboard verification requires a focused app window", focused.get())
        scenario.onActivity {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val platform = context.getSystemService(ClipboardManager::class.java)
        val clipboard = ProxyClipboard(context)
        val fixture = "fixture-not-a-credential".toCharArray()
        clipboard.copy(fixture)
        assertTrue(platform.primaryClip!!.description.extras!!.getBoolean("android.content.extra.IS_SENSITIVE"))
        assertEquals("fixture-not-a-credential", platform.primaryClip!!.getItemAt(0).text.toString())
        platform.setPrimaryClip(ClipData.newPlainText("other-owner", "unrelated fixture"))
        clipboard.clear()
        assertEquals("unrelated fixture", platform.primaryClip!!.getItemAt(0).text.toString())
        clipboard.copy(fixture)
        clipboard.clear()
        assertTrue(!platform.hasPrimaryClip() || platform.primaryClip!!.getItemAt(0).text.isEmpty())
        fixture.fill('\u0000')
        }
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val clipboard = ProxyClipboard(context)
        scenario.onActivity { clipboard.copy("background-fixture".toCharArray()) }
        scenario.moveToState(androidx.lifecycle.Lifecycle.State.CREATED)
        InstrumentationRegistry.getInstrumentation().runOnMainSync { clipboard.clear() }
        scenario.moveToState(androidx.lifecycle.Lifecycle.State.RESUMED)
        val resumedBy = android.os.SystemClock.elapsedRealtime() + 5000
        do {
            scenario.onActivity { focused.set(it.hasWindowFocus()) }
            if (!focused.get()) android.os.SystemClock.sleep(25)
        } while (!focused.get() && android.os.SystemClock.elapsedRealtime() < resumedBy)
        assertTrue(focused.get())
        scenario.onActivity {
            clipboard.clear()
            val platform = context.getSystemService(ClipboardManager::class.java)
            assertTrue("A background denial must retain ownership for foreground cleanup",
                !platform.hasPrimaryClip() || platform.primaryClip!!.getItemAt(0).text.isEmpty())
        }
        }
    }
}
