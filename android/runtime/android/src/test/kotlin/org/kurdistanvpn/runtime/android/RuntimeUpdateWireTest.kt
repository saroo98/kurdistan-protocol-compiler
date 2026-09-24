// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.runtime.android

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.nativeapi.*

class RuntimeUpdateWireTest {
    @Test fun exactArtifactLengthAndChangeFlagsAreRequiredBeforePublication() {
        val original = RuntimeVerifiedUpdate(2u, NativeUpdateChanges(0, 1, 0, 0, 0, 0, 0, 0, 0, 0), byteArrayOf(1, 2, 3))
        val metadata = RuntimeUpdateWire.encode(NativeProductResult.Success(original))
        val decoded = checkNotNull((RuntimeUpdateWire.decode(metadata, byteArrayOf(1, 2, 3)) as NativeProductResult.Success).value)
        assertEquals(2uL, decoded.generation)
        assertEquals(1, decoded.changes.endpointSet)
        assertArrayEquals(byteArrayOf(1, 2, 3), decoded.artifact)
        assertThrows(IllegalArgumentException::class.java) { RuntimeUpdateWire.decode(metadata, byteArrayOf(1)) }
        metadata[5] = 4294967297
        assertThrows(IllegalArgumentException::class.java) { RuntimeUpdateWire.decode(metadata, byteArrayOf(1, 2, 3)) }
        assertEquals(NativeProductResult.Success<RuntimeVerifiedUpdate?>(null), RuntimeUpdateWire.decode(longArrayOf(1, 0), byteArrayOf()))
    }
}
