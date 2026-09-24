// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.app.KeyguardManager
import android.os.Build
import android.os.SystemClock
import android.os.ParcelFileDescriptor
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import java.util.concurrent.CopyOnWriteArrayList
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

class SensitiveActionDeviceTest {
    @Test fun realCredentialPromptPreservesPendingActionAndDeliversOnce() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val pin = InstrumentationRegistry.getArguments().getString("testOnlyEmulatorPin")
        assumeTrue("Requires an owned emulator with an explicitly supplied temporary PIN",
            Build.HARDWARE in setOf("ranchu", "goldfish") && pin?.matches(Regex("[0-9]{4,8}")) == true)
        assertTrue(instrumentation.targetContext.getSystemService(KeyguardManager::class.java).isDeviceSecure)
        val results = CopyOnWriteArrayList<Boolean>()
        val stoppedWithPending = CopyOnWriteArrayList<Boolean>()
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            lateinit var authorizer: SensitiveActionAuthorizer
            scenario.onActivity { activity ->
                val field = MainActivity::class.java.getDeclaredField("sensitiveAuthorizer")
                field.isAccessible = true
                authorizer = field.get(activity) as SensitiveActionAuthorizer
                activity.lifecycle.addObserver(object : DefaultLifecycleObserver {
                    override fun onStop(owner: LifecycleOwner) {
                        stoppedWithPending.add(authorizer.isDeviceCredentialPending)
                    }
                })
                authorizer.authorize(SensitiveAction.REVEAL, "Credential verification", "Owned emulator test", onResult = results::add)
            }
            fun shell(command: String) {
                ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command)).use {
                    it.readBytes()
                }
            }
            fun awaitCondition(message: String, condition: () -> Boolean) {
                val deadline = SystemClock.elapsedRealtime() + 15_000
                while (!condition() && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(100)
                assertTrue(message, condition())
            }
            fun systemPromptVisible(): Boolean = instrumentation.uiAutomation.rootInActiveWindow?.packageName
                ?.toString() in setOf("com.android.systemui", "com.android.settings")
            awaitCondition("System credential screen did not open") { systemPromptVisible() }
            awaitCondition("System credential input did not become ready") {
                instrumentation.uiAutomation.rootInActiveWindow
                    ?.findFocus(android.view.accessibility.AccessibilityNodeInfo.FOCUS_INPUT)
                    ?.let { it.isEditable && it.isEnabled } == true
            }
            // SystemUI exposes the input before its opening transition has finished.
            // Wait for the system accessibility stream, not just the app's Compose clock.
            instrumentation.uiAutomation.waitForIdle(500, 3_000)
            shell("input text $pin")
            shell("input keyevent 66")
            awaitCondition("Successful credential result was not delivered") { results.isNotEmpty() }
            assertEquals(listOf(true), results.toList())
            assertTrue("Owned credential screen invalidates pending protected action", stoppedWithPending.all { it })
            scenario.onActivity {
                assertFalse(authorizer.isDeviceCredentialPending)
                authorizer.authorize(SensitiveAction.REVEAL, "Credential verification", "Cancel this request", onResult = results::add)
            }
            awaitCondition("Second credential screen did not open") { systemPromptVisible() }
            shell("input keyevent 4")
            awaitCondition("Cancellation was not delivered") { results.size == 2 }
            assertEquals(listOf(true, false), results.toList())
            scenario.onActivity { assertFalse(authorizer.isDeviceCredentialPending) }
        }
        assertEquals("Closing the activity must not replay authorization", 2, results.size)
    }
}
