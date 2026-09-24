// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.nativeapi.NativeCompatibility

internal fun bootstrapCompatibility() = NativeCompatibility("bridge-v1", "core-v1", "profile-v1", "strategy-v1", "relay-v1", "diagnostic-v1", 1, 100, 4, 100, 100, 10)

class RuntimeBootstrapStoreTest {
    @Test fun productionV2UnsignedGenerationAndVersionIsolation() {
        val v1=RuntimeBootstrapRecord(1,null,0,byteArrayOf(),bootstrapCompatibility()).encode()
        val empty=v1.copyOf().apply{this[4]=2}
        assertArrayEquals(empty,RuntimeProductionBootstrapRecord(1,null,0uL,byteArrayOf(),bootstrapCompatibility()).encode())
        assertThrows(IllegalArgumentException::class.java){RuntimeBootstrapRecord.decode(empty)}
        assertThrows(IllegalArgumentException::class.java){RuntimeProductionBootstrapRecord.decode(v1)}
        val digest=ByteArray(32){7}
        val record=RuntimeProductionBootstrapRecord(4,"profile-canary",0x8000000000000001uL,digest,bootstrapCompatibility())
        digest.fill(0)
        val wire=record.encode()
        val decoded=RuntimeProductionBootstrapRecord.decode(wire)
        assertEquals(0x8000000000000001uL,decoded.profileGeneration)
        assertTrue(decoded.matches(4,"profile-canary",0x8000000000000001uL,ByteArray(32){7},bootstrapCompatibility()))
        assertFalse(decoded.toString().contains("canary"))
        for(end in wire.indices)assertThrows(IllegalArgumentException::class.java){RuntimeProductionBootstrapRecord.decode(wire.copyOf(end))}
        assertThrows(IllegalArgumentException::class.java){RuntimeProductionBootstrapRecord.decode(wire+byteArrayOf(0))}
        assertThrows(IllegalArgumentException::class.java){RuntimeProductionBootstrapRecord(1,null,1uL,ByteArray(32){1},bootstrapCompatibility())}
        assertThrows(IllegalArgumentException::class.java){RuntimeProductionBootstrapRecord(1,"selected",0uL,ByteArray(32){1},bootstrapCompatibility())}
    }
    @Test fun frozenBootstrapV1BytesRemainCompatible() {
        val expected = ("4b524231011a00000000000000010000000000000000000000" +
            "00096272696467652d76310007636f72652d7631000a70726f66696c652d7631000b73747261746567792d7631000872656c61792d7631000d646961676e6f737469632d7631" +
            "00000001000000640000000400000064000000640000000a").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        assertArrayEquals(expected, RuntimeBootstrapRecord(1, null, 0, byteArrayOf(), bootstrapCompatibility()).encode())
        assertArrayEquals(expected, RuntimeBootstrapRecord.decode(expected).encode())
    }
    @Test fun absentProfileIsExplicitlyNonconnectableWithoutInventedPlan() {
        val record = RuntimeBootstrapRecord(1, null, 0, byteArrayOf(), bootstrapCompatibility())
        val restored = RuntimeBootstrapRecord.decode(record.encode())
        assertFalse(restored.connectable)
        assertTrue(restored.matches(1, null, 0, byteArrayOf(), bootstrapCompatibility()))
        assertThrows(IllegalArgumentException::class.java) { RuntimeBootstrapRecord(1, null, 1, ByteArray(32) { 1 }, bootstrapCompatibility()) }
    }
    @Test fun selectedBootstrapBindsEveryFreshAuthorityIdentityAndOwnsDigest() {
        val digest = ByteArray(32) { 7 }
        val record = RuntimeBootstrapRecord(4, "profile-canary", 3, digest, bootstrapCompatibility())
        digest.fill(0)
        val restored = RuntimeBootstrapRecord.decode(record.encode())
        assertTrue(restored.connectable)
        assertTrue(restored.matches(4, "profile-canary", 3, ByteArray(32) { 7 }, bootstrapCompatibility()))
        assertFalse(restored.matches(5, "profile-canary", 3, ByteArray(32) { 7 }, bootstrapCompatibility()))
        assertFalse(restored.matches(4, "other-profile", 3, ByteArray(32) { 7 }, bootstrapCompatibility()))
        assertFalse(restored.matches(4, "profile-canary", 4, ByteArray(32) { 7 }, bootstrapCompatibility()))
        assertFalse(restored.matches(4, "profile-canary", 3, ByteArray(32) { 8 }, bootstrapCompatibility()))
        assertFalse(restored.matches(4, "profile-canary", 3, ByteArray(32) { 7 }, bootstrapCompatibility().copy(bridgeVersion = "bridge-v2")))
        assertFalse(restored.toString().contains("canary"))
    }
    @Test fun malformedBootstrapNeverDecodesOrLeaksInput() {
        val encoded = RuntimeBootstrapRecord(1, null, 0, byteArrayOf(), bootstrapCompatibility()).encode()
        for (end in encoded.indices) assertThrows(IllegalArgumentException::class.java) { RuntimeBootstrapRecord.decode(encoded.copyOf(end)) }
        for (offset in listOf(4, 5)) assertThrows(IllegalArgumentException::class.java) { RuntimeBootstrapRecord.decode(encoded.clone().also { it[offset] = 99 }) }
        assertThrows(IllegalArgumentException::class.java) { RuntimeBootstrapRecord.decode(encoded + 0) }
    }
}
