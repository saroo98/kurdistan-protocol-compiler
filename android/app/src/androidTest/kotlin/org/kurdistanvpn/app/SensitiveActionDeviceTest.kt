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
            fun shell(command: String): String =
                ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command)).use {
                    it.readBytes().toString(Charsets.UTF_8)
                }
            fun awaitCondition(message: String, diagnostic: (() -> String)? = null, condition: () -> Boolean) {
                val deadline = SystemClock.elapsedRealtime() + 15_000
                while (!condition() && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(100)
                if (!condition() && diagnostic != null) {
                    throw AssertionError("KURDISTAN_TEST_SETUP expected=CREDENTIAL_RESULT actual=TIMEOUT setup=${diagnostic()}")
                }
                assertTrue(message, condition())
            }
            fun systemPromptVisible(): Boolean = instrumentation.uiAutomation.rootInActiveWindow?.packageName
                ?.toString() in setOf("com.android.systemui", "com.android.settings")
            fun promptState(): String =
                Regex("(?m)^\\s*containerState=([0-5])\\s*$").find(
                    shell("dumpsys activity service com.android.systemui/.SystemUIService AuthController"))
                    ?.groupValues?.get(1) ?: "NONE"
            awaitCondition("System credential screen did not open") { systemPromptVisible() }
            awaitCondition("System credential input did not become ready") {
                val root = instrumentation.uiAutomation.rootInActiveWindow
                val focused = root?.findFocus(android.view.accessibility.AccessibilityNodeInfo.FOCUS_INPUT)
                if (focused?.let { it.isEditable && it.isEnabled } == true) {
                    true
                } else {
                    // Older Settings can initially focus Cancel instead of the PIN field.
                    // Focus the real credential input before sending any test-only digits.
                    if (Build.VERSION.SDK_INT < 30 && systemPromptVisible()) {
                        root?.findAccessibilityNodeInfosByViewId("com.android.settings:id/password_entry")
                            ?.singleOrNull()?.takeIf { it.isEditable && it.isEnabled && it.isVisibleToUser }
                            ?.performAction(android.view.accessibility.AccessibilityNodeInfo.ACTION_FOCUS)
                    }
                    false
                }
            }
            // Accessibility exposes the input during ANIMATING_IN. On these owned
            // emulator images, state 3 (SHOWING) proves the transition has completed.
            if (Build.VERSION.SDK_INT < 30) instrumentation.uiAutomation.waitForIdle(500, 3_000)
            else awaitCondition("System credential prompt did not finish opening") { promptState() == "3" }
            shell("input text $pin")
            shell("input keyevent 66")
            awaitCondition("Successful credential result was not delivered") { results.isNotEmpty() }
            assertEquals(listOf(true), results.toList())
            assertTrue("Owned credential screen invalidates pending protected action", stoppedWithPending.all { it })
            scenario.onActivity {
                assertFalse(authorizer.isDeviceCredentialPending)
                authorizer.authorize(SensitiveAction.REVEAL, "Credential verification", "Cancel this request", onResult = results::add)
            }
            awaitCondition("Second credential screen did not become ready") {
                val root = instrumentation.uiAutomation.rootInActiveWindow
                systemPromptVisible() && root?.findAccessibilityNodeInfosByText("Cancel this request")
                    ?.any { it.isVisibleToUser } == true
            }
            // Cancellation needs the new system prompt, not keyboard input focus.
            assertEquals(listOf(true), results.toList())
            if (Build.VERSION.SDK_INT < 30) {
                scenario.onActivity { assertTrue(authorizer.isDeviceCredentialPending) }
            }
            // The previous prompt can remain visible while the new one is opening.
            instrumentation.uiAutomation.waitForIdle(500, 3_000)
            var backActions = 1
            assertTrue(instrumentation.uiAutomation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
            instrumentation.uiAutomation.waitForIdle(100, 2_000)
            // Back may first dismiss the credential keyboard. Never send another
            // action after the result or outside the real system prompt.
            if (results.size == 1 && systemPromptVisible()) {
                backActions++
                assertTrue(instrumentation.uiAutomation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
            }
            awaitCondition("Cancellation was not delivered", diagnostic = {
                val root = when (instrumentation.uiAutomation.rootInActiveWindow?.packageName?.toString()) {
                    "com.android.systemui" -> "SYSTEMUI"
                    "com.android.settings" -> "SETTINGS"
                    instrumentation.targetContext.packageName -> "APP"
                    null -> "NONE"
                    else -> "OTHER"
                }
                val ime = Regex("mInputShown=(true|false)").find(shell("dumpsys input_method"))
                    ?.groupValues?.get(1)?.uppercase(java.util.Locale.ROOT) ?: "UNKNOWN"
                "AUTH_${promptState()},IME_$ime,ROOT_$root,BACK_$backActions,LIFECYCLE_${scenario.state.name},RESULTS_${results.size}"
            }) { results.size == 2 }
            assertEquals(listOf(true, false), results.toList())
            scenario.onActivity { assertFalse(authorizer.isDeviceCredentialPending) }
        }
        assertEquals("Closing the activity must not replay authorization", 2, results.size)
    }
}
