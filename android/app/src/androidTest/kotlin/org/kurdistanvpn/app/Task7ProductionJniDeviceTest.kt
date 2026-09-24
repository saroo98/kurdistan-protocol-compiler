// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.content.Intent
import android.net.VpnService
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test

class Task7ProductionJniDeviceTest {
    private fun tunCase(case:Int):Task7InstalledDriverClient.TunResult = Task7InstalledDriverClient().use {
        it.prepareFreshFixtureOrVerifyExactPreparedState();it.runTunCase(case)
    }
    @Test fun realTunPacketDeliveryWaitsForExactWriteAndAck() {
        val p=tunCase(2).packets
        assertEquals(1L,p[22]);assertEquals(1L,p[23]);assertTrue(p[24]>=50);assertEquals(2L,p[25])
        assertEquals(44L,p[26]);assertEquals(16L,p[27]);assertEquals(0L,p[28])
        assertEquals(44L,p[29]);assertEquals(44L,p[30]);assertEquals(16L,p[31]);assertEquals(0L,p[32])
    }
    @Test fun realTunWrongDeliveryTokenTerminatesOwner() {
        val p=tunCase(3).packets;assertEquals(3L,p[33]);assertEquals(-1L,p[26]);assertEquals(1L,p[55])
    }
    @Test fun realTunShortDestinationWriteCannotBeAcknowledged() {
        val p=tunCase(4).packets;assertEquals(43L,p[26]);assertEquals(3L,p[34]);assertEquals(1L,p[55])
    }
    @Test fun realTunRejectedDestinationWriteRetiresReceipt() {
        val p=tunCase(5).packets;assertTrue(p[35] in 1..3);assertEquals(4L,p[36]);assertEquals(-1L,p[28])
    }
    @Test fun realTunWithheldDeliveryCancellationJoins() {
        val result=tunCase(6);assertEquals(3L,result.summary[2]);assertEquals(2L,result.summary[3])
        assertEquals(1L,result.packets[37]);assertEquals(1L,result.packets[38]);assertEquals(-1L,result.packets[28])
    }
    @Test fun realTunClosedOwnerRejectsRetainedDeliveryAfterReestablish() {
        val p=tunCase(7).packets;assertEquals(4L,p[46]);for(i in 47..50)assertEquals(1L,p[i])
    }
    /** Actual request component only: no callback registration, network selection or VPN mutation. */
    @Test fun maintenanceVisibleRequestHasNoImplicitVpnOrCapabilityFilter() {
        val factory = Class.forName("org.kurdistanvpn.runtime.android.VpnMaintenanceNetworkLeaseKt")
            .getDeclaredMethod("maintenanceVisibleNetworkRequestV1").apply { isAccessible = true }
        val request = factory.invoke(null) as android.net.NetworkRequest
        if (android.os.Build.VERSION.SDK_INT >= 31) {
            assertEquals(0, request.capabilities.size)
            assertEquals(0, request.transportTypes.size)
        } else if (android.os.Build.VERSION.SDK_INT >= 28) {
            for (capability in 0..17) assertFalse(request.hasCapability(capability))
            for (transport in 0..5) assertFalse(request.hasTransport(transport))
        } else {
            // API26/27 lack the public request accessors. Their AOSP Parcelable
            // starts with NetworkCapabilities; use its public API21 accessors.
            val parcel = android.os.Parcel.obtain()
            try {
                request.writeToParcel(parcel, 0)
                parcel.setDataPosition(0)
                @Suppress("DEPRECATION")
                val capabilities = checkNotNull(parcel.readParcelable<android.net.NetworkCapabilities>(null))
                for (capability in 0..17) assertFalse(capabilities.hasCapability(capability))
                for (transport in 0..5) assertFalse(capabilities.hasTransport(transport))
            } finally { parcel.recycle() }
        }
    }

    /** Platform component reproduction, not production RPC or installed VPN qualification. */
    @Test fun reliablePipeParcelTransferPreservesEofAndRemoteError() {
        val primitives = org.kurdistanvpn.core.nativejni.NativeBridge().durableFiles()
        for ((transferOwnership, remoteError) in listOf(false to false, true to false, true to true)) {
            val pair = android.os.ParcelFileDescriptor.createReliablePipe()
            val parcel = android.os.Parcel.obtain()
            val deadline = SystemClock.elapsedRealtime() + 5_000
            val live = { SystemClock.elapsedRealtime() < deadline }
            val owners = mutableListOf<org.kurdistanvpn.runtime.android.RuntimeAuthorityPipeOwner>()
            try {
                fun own(fd: android.os.ParcelFileDescriptor, access: Int) =
                    org.kurdistanvpn.runtime.android.RuntimeAuthorityPipeOwner.take(fd, primitives,
                        android.os.Process.myUid().toLong(), access, deadline, live).also { owners += it }
                val input = own(pair[0], 0); val output = own(pair[1], 1)
                val bytes = ByteArray(32) { 7 }
                org.kurdistanvpn.runtime.android.RuntimeReissuePipeIo.writeExact(output, bytes, live)
                if (remoteError) output.withDescriptor { it.closeWithError("TASK7_FIXED_PIPE_ERROR") }
                output.close()
                input.withDescriptor {
                    parcel.writeTypedObject(it, if (transferOwnership) android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE else 0)
                }
                // Old flags=0 close consumes the peer's status. SILENCE has already
                // closed the sender PFD, making this tracked-owner close idempotent.
                input.close()
                parcel.setDataPosition(0)
                val receiver = own(checkNotNull(parcel.readTypedObject(android.os.ParcelFileDescriptor.CREATOR)), 0)
                if (!transferOwnership || remoteError) {
                    assertThrows(java.io.IOException::class.java) {
                        org.kurdistanvpn.runtime.android.RuntimeReissuePipeIo.readExact(receiver, bytes.size, live)
                    }
                } else assertArrayEquals(bytes,
                    org.kurdistanvpn.runtime.android.RuntimeReissuePipeIo.readExact(receiver, bytes.size, live))
            } finally {
                var clean = true
                owners.asReversed().forEach { try { it.close() } catch (_: Exception) { clean = false } }
                pair.forEach { try { it.close() } catch (_: Exception) { clean = false } }
                parcel.recycle()
                check(clean) { "TASK7_PIPE_COMPONENT_CLEANUP_UNPROVEN" }
            }
        }
    }

    /** Read-only setup diagnosis; success is not fixture or runtime qualification. */
    @Test fun readOnlyRetainedFixtureSelectionDiagnostic() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val application = instrumentation.targetContext.applicationContext as KurdistanApplication
        check(application.packageName == "org.kurdistanvpn.app.internal")
        val projection = application.compositionRoot.protectedStateFacade()?.readProjection()
        val selected = projection?.settings?.profiles?.activeLocalRecordId
        val soleProfile = projection?.profiles?.singleOrNull()
        instrumentation.sendStatus(0, android.os.Bundle().apply {
            putString("task7_projection", if (projection == null) "UNAVAILABLE" else "AVAILABLE")
            putBoolean("task7_selected_present", selected != null)
            putBoolean("task7_exactly_one_profile", soleProfile != null)
            putBoolean("task7_selected_matches_sole_profile", selected != null && selected == soleProfile?.localRecordId)
        })
    }

    /** Setup only: the operator must accept Android's real system consent dialog. */
    @Test fun requestRealVpnConsentForFixtureSetup() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        VpnService.prepare(context)?.let {
            context.startActivity(Intent(context, Task7InstalledConsentActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            val deadline = SystemClock.elapsedRealtime() + 30_000
            while (VpnService.prepare(context) != null && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(100)
        }
        assertNull("Actual Android VPN consent is required", VpnService.prepare(context))
    }

    @Test fun realOwnerSelectedProbeRejectsRetainedDelegateAfterStop() {
        Task7InstalledDriverClient().use { client ->
            client.prepareFreshFixtureOrVerifyExactPreparedState()
            val result = client.runCase(1, 0)
            assertEquals("case completed", 2L, result[2])
            assertEquals("genuine selected probe", 1L, result[7])
            assertEquals("retained delegate rejected", 1L, result[8])
            assertEquals("owner cleanup joined", 1L, result[9])
            assertEquals("no relay accept before protection", 1L, result[10])
        }
    }
}
