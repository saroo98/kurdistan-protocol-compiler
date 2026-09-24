// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.junit.Assert.*
import org.junit.Test

class Task7PlatformTrustDeviceTest {
    @Test fun signedHttpsAndJoinedCleanupAtFiniteMemoryPressure() {
        fun run(case:Int,level:Int){
            val result=Task7InstalledDriverClient().use{it.prepareFreshFixtureOrVerifyExactPreparedState();it.runMaintenanceCase(case,level)}
            assertEquals(1L,result.terminal[9])
            assertEquals((if(case==303)30 else 1).toLong(),result.measurement[71])
            assertEquals(level.toLong(),result.measurement[6])
        }
        // Fail immediately. No escalating beyond an unsuccessful baseline/cell.
        for(case in listOf(301,304,302,303))run(case,0)
        for(level in listOf(16,32,64))run(301,level)
        for(case in listOf(304,302,303))run(case,64)
    }
    @Test fun genuineSystemRootsBuildNativePool() {
        val result=Task7InstalledDriverClient().use{it.prepareFreshFixtureOrVerifyExactPreparedState();it.runMaintenanceCase(10)}
        val p=result.measurement
        assertEquals(2L,result.terminal[2]);assertEquals(1L,result.terminal[9])
        assertEquals(1L,p[8]);assertEquals(0L,p[20]);assertTrue(p[21] in 1..512);assertTrue(p[22] in 3..1048576)
        assertEquals(-1L,p[24]);assertEquals(1L,p[34]);assertEquals(1L,p[38]);assertEquals(1L,p[39]);assertEquals(7L,p[52])
    }
    @Test fun genuineSystemRootsRejectMatchingSanUntrustedTLS() {
        val result=Task7InstalledDriverClient().use{it.prepareFreshFixtureOrVerifyExactPreparedState();it.runMaintenanceCase(11)}
        val p=result.measurement
        assertEquals(2L,result.terminal[2]);assertEquals(1L,result.terminal[9])
        assertEquals(2L,p[8]);assertEquals(13L,p[24]);assertEquals(1L,p[25])
        for(i in 26..28)assertEquals(1L,p[i])
        for(i in 29..31)assertEquals(0L,p[i])
        assertEquals(1L,p[32]);assertEquals(1L,p[34]);assertEquals(0L,p[35]);assertEquals(0L,p[36]);assertEquals(7L,p[52])
    }
}
