// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*

class ProbeHistoryStoreTest {
    @Test fun malformedProbeFieldsAndNoncanonicalChronologyFailClosed() {
        val sample = ProbeSample(0, 0, 0, 0, ProbeStability.UNKNOWN, null)
        val bytes = StoredProbeHistory(1, listOf(sample)).encode()
        checkMalformed(bytes, listOf({ putLong(it, 6, -1) }, { putShort(it, 14, 201) }, { putLong(it, 16, -1) },
            { putLong(it, 16, 2) }, { putInt(it, 24, 30001) }, { putInt(it, 28, -1) }, { putInt(it, 32, 10001) },
            { it[38] = '?'.code.toByte() }, { it[45] = 2 }, { it[48] = '?'.code.toByte() })) { StoredProbeHistory.decode(it) }
        val ordered = StoredProbeHistory(1, listOf(sample, sample.copy(coarseEpochMinutes = 1))).encode()
        val unsorted = ordered.copyOfRange(0, 16) + ordered.copyOfRange(60, 104) + ordered.copyOfRange(16, 60)
        assertThrows(IllegalArgumentException::class.java) { StoredProbeHistory.decode(unsorted) }
    }
    @Test fun probeRoundTripSortsStablyAndRejectsInvalidRetention() {
        val later = ProbeSample(60, 2, 3, 4, ProbeStability.STABLE, null)
        val first = ProbeSample(59, 1, 2, 3, ProbeStability.UNKNOWN, ProductFailureCode.OPERATION_INTERRUPTED)
        val equal = later.copy(latencyMillis = 8)
        val samples = mutableListOf(later, first, equal)
        val value = StoredProbeHistory(60, samples); samples.clear()
        checkRecord(value.encode(), 22, 32768) { StoredProbeHistory.decode(it).encode() }
        assertEquals(listOf(first, later, equal), value.samples)
        for (pair in listOf(-1L to emptyList(), 0L to listOf(later), 43261L to listOf(later), 60L to List(201) { later }))
            assertThrows(IllegalArgumentException::class.java) { StoredProbeHistory(pair.first, pair.second) }
    }
    @Test fun probeWrapperContract() {
        val value = StoredProbeHistory(0, emptyList())
        checkStore("profile-a", SecureDataClass.PROBE_HISTORY, value.encode(),
            { ProbeHistoryStore(it).save("profile-a", value) }, { ProbeHistoryStore(it).load("profile-a")?.encode() },
            { ProbeHistoryStore(it).delete("profile-a") }, { ProbeHistoryStore.readOnly(it).save("profile-a", value) },
            { ProbeHistoryStore.readOnly(it).delete("profile-a") })
    }
}
