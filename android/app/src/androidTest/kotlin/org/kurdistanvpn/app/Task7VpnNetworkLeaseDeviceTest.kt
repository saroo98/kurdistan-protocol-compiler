// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.junit.Assert.*
import org.junit.Test

class Task7VpnNetworkLeaseDeviceTest {
    companion object {
        private var dnsCompleted = -1L
    }
    private fun dnsCase(case: Int): LongArray {
        if (dnsCompleted >= 0) {
            val remaining = dnsCompleted + 60000 - android.os.SystemClock.elapsedRealtime()
            if (remaining > 0) android.os.SystemClock.sleep(remaining)
        }
        val p=Task7InstalledDriverClient().use{it.prepareFreshUpdateFixtureOrVerifyExactPreparedState();it.runMaintenanceDnsCase(case)}.measurement
        if (dnsCompleted >= 0) assertTrue("missing native-process rate history", p[20]>=0 && p[22]>=60000)
        dnsCompleted=android.os.SystemClock.elapsedRealtime()
        android.util.Log.i("Task7Maintenance", "DNS_PASS_V1_${case}_${p[0]}_${p[20]}_${p[21]}_${p[22]}_${p[52]}")
        return p
    }
    @Test fun signedUpdateUdpDnsReachesOwnedTunThenHttpsSynCancels() {
        val p=dnsCase(12)
        assertEquals(92L,p[43]);assertEquals(1L,p[52]);assertTrue(p[47] in 40..80)
    }
    @Test fun signedUpdateTruncatedDnsReachesTcpSynThenCancels() {
        val p=dnsCase(13)
        assertEquals(61L,p[43]);assertEquals(1L,p[52]);assertTrue(p[47] in 40..80)
    }
    @Test fun signedUpdateTunLossInvalidatesLeaseAndCannotPublish() {
        val p=dnsCase(14)
        assertEquals(61L,p[40]);assertEquals(-1L,p[43]);assertTrue(p[52] in 1..2)
    }
    @Test fun associatedMaintenanceLeaseUsesOwnedTunAndRetiresWithOwner() {
        val result=Task7InstalledDriverClient().use{it.prepareFreshFixtureOrVerifyExactPreparedState();it.runMaintenanceCase(8)}
        val p=result.measurement
        assertEquals(2L,result.terminal[2]);assertEquals(1L,result.terminal[9])
        assertEquals(3L,p[8]);assertEquals(0L,p[44]);assertEquals(1L,p[60]);assertEquals(1L,p[61])
        assertEquals(7L,p[52]);assertEquals(7L,p[69]);assertEquals(1L,p[64]);assertEquals(1L,p[68])
        assertEquals(0L,p[67]);assertEquals(1L,p[70])
    }
    @Test fun disconnectedMaintenanceAcquiresAndClosesWithoutNetworkIO() {
        val result=Task7InstalledDriverClient().use{it.prepareFreshFixtureOrVerifyExactPreparedState();it.runMaintenanceCase(9)}
        val p=result.measurement
        assertEquals(2L,result.terminal[2]);assertEquals(1L,result.terminal[9])
        assertEquals(3L,p[8]);assertEquals(1L,p[62]);assertEquals(0L,p[63]);assertEquals(0L,p[48])
        assertEquals(-1L,p[43]);assertEquals(-1L,p[55]);assertEquals(7L,p[52])
    }
}
