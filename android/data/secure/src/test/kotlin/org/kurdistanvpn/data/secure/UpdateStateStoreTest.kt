// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*

class UpdateStateStoreTest {
    @Test fun malformedUpdateFieldsFailClosed() {
        val bytes = StoredUpdateState(null, null, UpdateCategory.NOT_CHECKED, 0, 0, 0).encode()
        checkMalformed(bytes, listOf({ it[6] = 2 }, { it[7] = 2 }, { putShort(it, 8, 65) }, { it[10] = 0x7f },
            { putLong(it, 21, -1) }, { putLong(it, 29, -1) }, { it[37] = 11 })) { StoredUpdateState.decode(it) }
        assertEquals(0uL, StoredUpdateState.decode(StoredUpdateState(0uL, ULong.MAX_VALUE, UpdateCategory.UNCHANGED, Long.MAX_VALUE, Long.MAX_VALUE, 0).encode()).publicationGeneration)
    }
    @Test fun updateRoundTripPreservesUnsignedGenerationsAndBounds() {
        val value = StoredUpdateState(ULong.MAX_VALUE, 0uL, UpdateCategory.AVAILABLE, 4, 5, 10)
        checkRecord(value.encode(), 21, 1024) { StoredUpdateState.decode(it).encode() }
        assertEquals(ULong.MAX_VALUE, StoredUpdateState.decode(value.encode()).publicationGeneration)
        for (bad in listOf<() -> Any>({ StoredUpdateState(null, null, UpdateCategory.NOT_CHECKED, -1, 1, 0) },
            { StoredUpdateState(null, null, UpdateCategory.NOT_CHECKED, 2, 1, 0) },
            { StoredUpdateState(null, null, UpdateCategory.NOT_CHECKED, 0, 0, 11) })) assertThrows(IllegalArgumentException::class.java) { bad() }
    }
    @Test fun updateWrapperOwnsBuffersAndCannotUpgradeReadOnly() {
        val value = StoredUpdateState(null, null, UpdateCategory.NOT_CHECKED, 0, 0, 0)
        checkStore("profile-a", SecureDataClass.UPDATE_STATE, value.encode(),
            { UpdateStateStore(it).save("profile-a", value) }, { UpdateStateStore(it).load("profile-a")?.encode() },
            { UpdateStateStore(it).delete("profile-a") }, { UpdateStateStore.readOnly(it).save("profile-a", value) },
            { UpdateStateStore.readOnly(it).delete("profile-a") })
    }
}
