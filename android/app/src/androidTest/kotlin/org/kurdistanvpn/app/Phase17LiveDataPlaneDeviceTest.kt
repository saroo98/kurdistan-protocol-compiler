// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.Manifest
import android.content.ComponentName
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.kurdistanvpn.core.model.DnsMode
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.nativeapi.BackupPreviewHandle
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.runtime.android.KurdVpnService
import org.kurdistanvpn.runtime.android.LiveTunnelInvariantProbe
import org.kurdistanvpn.runtime.api.LiveTunnelFailure
import org.kurdistanvpn.runtime.api.VpnRoutingPolicy
import org.kurdistanvpn.runtime.api.VpnRuntimeConfig
import org.kurdistanvpn.runtime.api.VpnRuntimeState

class Phase17LiveDataPlaneDeviceTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun liveIpv4LifecycleProtectsSocketBeforeConnectAndStopsCleanly() {
        val success = LiveTunnelInvariantProbe.exercise(protectSucceeds = true)
        assertTrue(success.runningBeforeStop)
        assertFalse(success.runningAfterStop)
        assertNull(success.failure)
        assertOrdered(
            success.events,
            "protect:37",
            "connect",
            "tls",
            "kurd",
            "establish",
            "attach:71",
            "stage:RUNNING",
            "stop",
            "close",
            "stage:STOPPED",
        )

        val rejected = LiveTunnelInvariantProbe.exercise(protectSucceeds = false)
        assertFalse(rejected.runningBeforeStop)
        assertFalse(rejected.runningAfterStop)
        assertEquals(LiveTunnelFailure.SOCKET_PROTECT_FAILED, rejected.failure)
        assertTrue(rejected.events.contains("protect:37"))
        assertTrue(rejected.events.contains("commit-false"))
        assertFalse(rejected.events.contains("connect"))
        assertFalse(rejected.events.contains("establish"))
    }

    @Test
    fun permissionRevocationAndProcessDeathRequireFreshAuthority() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val staged = ByteArray(64) { 0x5a }
        VpnRuntimeController(context).use { controller ->
            controller.stageAuthority(staged)
            controller.permissionRejected()
            assertTrue(staged.all { it == 0.toByte() })
            assertEquals(VpnRuntimeState.FAILED, controller.snapshot.value.state)
            assertEquals("CONSENT_REJECTED", controller.snapshot.value.failure)
            controller.startStaged()
            assertEquals("MISSING_VERIFIED_AUTHORITY", controller.snapshot.value.failure)
        }

        VpnRuntimeController(context).use { recreated ->
            recreated.startStaged()
            assertEquals(VpnRuntimeState.FAILED, recreated.snapshot.value.state)
            assertEquals("MISSING_VERIFIED_AUTHORITY", recreated.snapshot.value.failure)
        }
    }

    @Test
    fun emergencyStopLeavesNoRuntimeOrSecretEvidence() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val staged = ByteArray(48) { 0x6b }
        VpnRuntimeController(context).use { controller ->
            controller.stageAuthority(staged)
            controller.authorityRejected("PROFILE_REVOKED")
            assertTrue(staged.all { it == 0.toByte() })
            assertEquals(VpnRuntimeState.FAILED, controller.snapshot.value.state)
            assertEquals("PROFILE_REVOKED", controller.snapshot.value.failure)
            assertNoAuthorityEvidence(controller.snapshot.value)

            controller.stop()
            assertEquals(VpnRuntimeState.IDLE, controller.snapshot.value.state)
            assertNull(controller.snapshot.value.failure)
            assertNoAuthorityEvidence(controller.snapshot.value)
        }
    }

    @SdkSuppress(minSdkVersion = 34)
    @Test
    fun dualStackDnsHandoverAndReconnectRemainPolicyBound() {
        val permitted = VpnRuntimeConfig(
            routingPolicy = VpnRoutingPolicy(),
            ipMode = IpMode.DUAL_STACK,
            dnsMode = DnsMode.INTERNAL_TUN,
            mtu = 1280,
        ).validatedForLiveTransport()
        assertEquals(IpMode.DUAL_STACK, permitted.ipMode)
        assertEquals(DnsMode.INTERNAL_TUN, permitted.dnsMode)
        assertEquals(1280, permitted.mtu)

        assertPolicyRejected {
            VpnRuntimeConfig(
                routingPolicy = VpnRoutingPolicy(),
                dnsMode = DnsMode.CLOUDFLARE,
            ).validatedForLiveTransport()
        }
        assertPolicyRejected {
            VpnRuntimeConfig(
                routingPolicy = VpnRoutingPolicy(),
                dnsMode = DnsMode.CUSTOM,
                customDns = "resolver.example",
            ).validatedForLiveTransport()
        }
        assertPolicyRejected {
            VpnRuntimeConfig(
                routingPolicy = VpnRoutingPolicy(),
                allowLan = true,
            ).validatedForLiveTransport()
        }
        assertPolicyRejected {
            VpnRuntimeConfig(
                routingPolicy = VpnRoutingPolicy(),
                mtu = 1279,
            ).validatedForLiveTransport()
        }
    }

    @SdkSuppress(minSdkVersion = 34)
    @Test
    fun profileRevocationAndBackupRestoreFailClosed() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val application = instrumentation.targetContext.applicationContext as KurdistanApplication
        val root = application.compositionRoot

        VpnRuntimeController(application).use { controller ->
            controller.authorityRejected("PROFILE_REVOKED")
            assertEquals(VpnRuntimeState.FAILED, controller.snapshot.value.state)
            assertEquals("PROFILE_REVOKED", controller.snapshot.value.failure)
            assertNoAuthorityEvidence(controller.snapshot.value)
        }

        assertTrue(root.resetProtectedState())
        val journal = requireNotNull(root.admissionJournal)
        val payload = journal.backupPayload()
        val passphrase = "phase17-device-backup".encodeToByteArray()
        var opened: BackupPreviewHandle? = null
        var backup = byteArrayOf()
        try {
            backup = requireSuccess(root.nativeCore.createBackup(payload, passphrase))
            opened = requireSuccess(root.nativeCore.openBackup(backup.copyOf(), passphrase))
            val restored = requireSuccess(root.nativeCore.restoreBackup(opened))
            try {
                assertArrayEquals(payload, restored)
            } finally {
                restored.fill(0)
            }
            assertTrue(root.nativeCore.releaseBackup(opened) is NativeResult.Success)
            opened = null

            val tampered = backup.copyOf()
            tampered[tampered.lastIndex] = (tampered.last().toInt() xor 1).toByte()
            try {
                assertTrue(
                    "modified backup must fail before restore",
                    root.nativeCore.openBackup(tampered, passphrase) is NativeResult.Failure,
                )
            } finally {
                tampered.fill(0)
            }
            assertTrue(root.resetProtectedState())
            assertTrue(requireNotNull(root.admissionJournal).listProfiles().isEmpty())
        } finally {
            opened?.let(root.nativeCore::releaseBackup)
            backup.fill(0)
            payload.fill(0)
            passphrase.fill(0)
        }
    }

    @SdkSuppress(minSdkVersion = 36)
    @Test
    fun completeCurrentManifestAccessibilityAndLifecycleRemainTruthful() {
        val activity = compose.activity
        val packageManager = activity.packageManager
        val requested = requireNotNull(
            packageManager.getPackageInfo(activity.packageName, PackageManager.GET_PERMISSIONS)
                .requestedPermissions,
        ).toSet()
        assertTrue(requested.contains(Manifest.permission.INTERNET))
        assertTrue(requested.contains(Manifest.permission.ACCESS_NETWORK_STATE))
        assertTrue(requested.contains(Manifest.permission.FOREGROUND_SERVICE))

        val service = packageManager.getServiceInfo(
            ComponentName(activity, KurdVpnService::class.java),
            PackageManager.GET_META_DATA,
        )
        assertFalse(service.exported)
        assertEquals(Manifest.permission.BIND_VPN_SERVICE, service.permission)
        assertTrue(service.processName.endsWith(":vpn"))
        assertTrue(
            service.foregroundServiceType and ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE != 0,
        )
        assertFalse(
            service.metaData.getBoolean("android.net.VpnService.SUPPORTS_ALWAYS_ON", true),
        )

        compose.onNodeWithTag("connection_hero").assertIsDisplayed()
        compose.onNodeWithTag("connect_button").assertIsDisplayed().assertHasClickAction()
        assertFalse(activity.appStateSnapshotForTesting().toString().contains("PRODUCTION_READY"))
    }

    private fun assertOrdered(events: List<String>, vararg expected: String) {
        var previous = -1
        expected.forEach { event ->
            val index = events.indexOf(event)
            assertTrue("missing event $event in $events", index >= 0)
            assertTrue("event $event is out of order in $events", index > previous)
            previous = index
        }
    }

    private fun assertPolicyRejected(block: () -> Unit) {
        val error = runCatching(block).exceptionOrNull()
        assertTrue("unsafe policy was accepted", error is IllegalArgumentException)
    }

    private fun assertNoAuthorityEvidence(snapshot: org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot) {
        assertEquals(0, snapshot.profileGeneration)
        assertNull(snapshot.planDigest)
        assertNull(snapshot.profileFingerprint)
        assertNull(snapshot.strategyFingerprint)
        assertNull(snapshot.relayFingerprint)
    }

    private fun <T> requireSuccess(result: NativeResult<T>): T = when (result) {
        is NativeResult.Success -> result.value
        is NativeResult.Failure -> throw AssertionError("native operation failed: ${result.error}")
    }
}
