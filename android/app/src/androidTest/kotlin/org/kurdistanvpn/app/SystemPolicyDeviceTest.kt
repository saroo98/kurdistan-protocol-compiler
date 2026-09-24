// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.Manifest
import android.content.pm.PackageManager
import android.view.WindowManager
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.domain.*

class SystemPolicyDeviceTest {
    @Test fun foregroundPolicyReadsRealPlatformAndAppliesSecureWindow(): Unit = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = (context.applicationContext as KurdistanApplication).compositionRoot
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            assertSame(root.systemPolicy, root.systemPolicy)
            val apps = root.systemPolicy.installedApplications() as DomainResult.Success
            assertTrue(apps.value.any { it.packageName == context.packageName })
            assertEquals(apps.value.size, apps.value.distinctBy { it.packageName }.size)
            val expectedCamera = if (context.checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
                PermissionStatus.GRANTED else PermissionStatus.NOT_GRANTED
            assertEquals(expectedCamera, root.systemPolicy.observePermission(ProductPermission.CAMERA).first())
            assertEquals(PermissionStatus.UNAVAILABLE, root.systemPolicy.observePermission(ProductPermission.NETWORK_IDENTITY).first())
            try {
                assertTrue(root.systemPolicy.setScreenshotPolicy(ScreenshotPolicy.PROTECTED) is DomainResult.Success)
                scenario.onActivity { assertTrue(it.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0) }
                assertEquals(ScreenshotPolicy.PROTECTED, root.systemPolicy.observeScreenshotPolicy().first())
            } finally { root.systemPolicy.setScreenshotPolicy(ScreenshotPolicy.ALLOWED) }
        }
        assertTrue(root.systemPolicy.setScreenshotPolicy(ScreenshotPolicy.PROTECTED) is DomainResult.Rejected)
    }

    @Test fun cancelledCameraPermissionIsNotReportedGranted(): Unit = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        // Revoke from the host before instrumentation: Android kills the UID on permission revocation.
        assertEquals("Host must revoke CAMERA before this test", PackageManager.PERMISSION_DENIED,
            context.checkSelfPermission(Manifest.permission.CAMERA))
        val repository = (context.applicationContext as KurdistanApplication).compositionRoot.systemPolicy
        ActivityScenario.launch(MainActivity::class.java).use {
            val result = async { repository.requestPermission(ProductPermission.CAMERA) }
            val permissionPackages = setOf("com.android.permissioncontroller", "com.google.android.permissioncontroller",
                "com.android.packageinstaller", "com.google.android.packageinstaller")
            withTimeout(10_000) {
                while (instrumentation.uiAutomation.rootInActiveWindow?.packageName?.toString() !in permissionPackages) delay(50)
            }
            if (android.os.Build.VERSION.SDK_INT < 30) {
                // Older permission dialogs deliberately ignore Back; decline through the real button.
                val automation = instrumentation.uiAutomation
                automation.serviceInfo = automation.serviceInfo.apply {
                    flags = flags or android.accessibilityservice.AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
                }
                val window = checkNotNull(automation.rootInActiveWindow)
                // The Google package can retain the AOSP resource namespace.
                val deny = permissionPackages.flatMap {
                    window.findAccessibilityNodeInfosByViewId("$it:id/permission_deny_button")
                }
                    .first { it.isEnabled && it.isClickable }
                assertTrue(deny.performAction(android.view.accessibility.AccessibilityNodeInfo.ACTION_CLICK))
            } else {
                assertTrue(instrumentation.uiAutomation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
            }
            val completed = withTimeout(10_000) { result.await() }
            assertTrue(completed is DomainResult.Success && completed.value == PermissionStatus.NOT_GRANTED)
            assertEquals(PackageManager.PERMISSION_DENIED, context.checkSelfPermission(Manifest.permission.CAMERA))
        }
    }
}
