// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*

class EncryptedProductStoresTest {
    @Test fun boundedEncoderStopsBeforeWritingPastItsDeclaredLimit() {
        var wrotePastLimit = false
        assertThrows(IllegalArgumentException::class.java) {
            encodeRecord(0x50363239, SecureDataClass.CRASH_SAFE_MODE_STATE, 7) {
                it.write(ByteArray(2))
                wrotePastLimit = true
            }
        }
        assertFalse(wrotePastLimit)
    }
    @Test fun rejectedCanonicalOrTrailingInputClosesDecodedOwnedRecords() {
        for (trailing in listOf(false, true)) {
            val value = ProductOperationState(ByteArray(32) { 1 }, 16, null, null, 0, 0, 2, 4, 0, 0, byteArrayOf(1), byteArrayOf(2))
            val raw = byteArrayOf(0x50, 0x36, 0x32, 0x37, 1, 27) + if (trailing) byteArrayOf(0) else byteArrayOf()
            assertThrows(IllegalArgumentException::class.java) {
                decodeRecord<ProductOperationState>(raw, 100, 0x50363237, SecureDataClass.OPERATION_STATE, { value }, { it.encode() })
            }
            assertThrows(IllegalStateException::class.java) { value.encode() }
        }
    }
    @Test fun malformedDeploymentEntriesAndIdOrderingFailClosed() {
        val a = DeploymentDisplayEntry(CatalogId("a"), SafeAlias("A"), 0, false, UpdateCategory.NOT_CHECKED)
        val bytes = DeploymentDisplayMetadata(listOf(a)).encode()
        checkMalformed(bytes, listOf({ putShort(it, 6, 1025) }, { putShort(it, 8, 65) }, { it[10] = 'A'.code.toByte() },
            { putShort(it, 11, 385) }, { it[13] = 0xc0.toByte() }, { putInt(it, 14, -1) }, { putInt(it, 14, 1024) },
            { it[18] = 2 }, { it[21] = '?'.code.toByte() })) { DeploymentDisplayMetadata.decode(it) }
        val ordered = DeploymentDisplayMetadata(listOf(a, a.copy(profileId = CatalogId("b")))).encode()
        val unsorted = ordered.copyOfRange(0, 8) + ordered.copyOfRange(32, 56) + ordered.copyOfRange(8, 32)
        val duplicate = ordered.clone().also { it[34] = 'a'.code.toByte() }
        for (bad in listOf(unsorted, duplicate)) assertThrows(IllegalArgumentException::class.java) { DeploymentDisplayMetadata.decode(bad) }
    }
    @Test fun everySecureRoleKeepsItsIndependentWireIdentity() {
        val expected = mapOf(
            "PROFILE_ARTIFACT" to 1,
            "VERIFIED_RECEIPT" to 2,
            "LOCAL_ALIAS" to 3,
            "RECIPIENT_PRIVATE_MATERIAL" to 4,
            "IMPORT_REQUEST" to 5,
            "PROFILE_PREVIEW" to 6,
            "ACTIVATION_STAGED" to 7,
            "ACTIVATION_ACTIVE" to 8,
            "ACTIVATION_LAST_KNOWN_GOOD" to 9,
            "RESTORE_BATCH" to 10,
            "ROUTING_POLICY" to 11,
            "DIAGNOSTIC_EVENTS" to 12,
            "RECIPIENT_KEY_INDEX" to 13,
            "PROTECTED_JOURNAL_CONTROL" to 14,
            "PROTECTED_JOURNAL_RECORD" to 15,
            "PROTECTED_CHECKPOINT" to 16,
            "PROTECTED_RESET_MANIFEST" to 17,
            "PROTECTED_PROJECTION_WITNESS" to 18,
            "PROFILE_PROJECTION" to 19,
            "DEPLOYMENT_METADATA" to 20,
            "UPDATE_STATE" to 21,
            "PROBE_HISTORY" to 22,
            "TRUSTED_NETWORK_RULES" to 23,
            "USAGE_AGGREGATES" to 24,
            "APP_LOCK_STATE" to 25,
            "RUNTIME_BOOTSTRAP" to 26,
            "OPERATION_STATE" to 27,
            "LOCAL_PROXY_POLICY" to 28,
            "CRASH_SAFE_MODE_STATE" to 29,
            "PAUSE_STATE" to 30)
        assertEquals(expected, SecureDataClass.entries.associate { it.name to it.wireValue })
        assertEquals(30, SecureDataClass.entries.map { it.wireValue }.toSet().size)
    }
    @Test fun deploymentDisplayIsCanonicalAndSeparateFromFavorites() {
        val entries = mutableListOf(DeploymentDisplayEntry(CatalogId("b"), SafeAlias("B"), 0, false, UpdateCategory.REJECTED),
            DeploymentDisplayEntry(CatalogId("a"), SafeAlias("A"), 0, true, UpdateCategory.AVAILABLE))
        val value = DeploymentDisplayMetadata(entries); entries.clear()
        checkRecord(value.encode(), 20, 1048576) { DeploymentDisplayMetadata.decode(it).encode() }
        assertEquals(listOf("a", "b"), value.entries.map { it.profileId.value })
        assertThrows(IllegalArgumentException::class.java) { DeploymentDisplayMetadata(listOf(value.entries[0], value.entries[0])) }
        assertThrows(IllegalArgumentException::class.java) { DeploymentDisplayEntry(CatalogId("a"), SafeAlias("A"), 1024, false, UpdateCategory.NOT_CHECKED) }
        checkStore("deployment-display-current", SecureDataClass.DEPLOYMENT_METADATA, value.encode(),
            { DeploymentDisplayMetadataStore(it).save(value) }, { DeploymentDisplayMetadataStore(it).load()?.encode() },
            { DeploymentDisplayMetadataStore(it).delete() }, { DeploymentDisplayMetadataStore.readOnly(it).save(value) },
            { DeploymentDisplayMetadataStore.readOnly(it).delete() })
    }
    @Test fun frozenMetadataV1BytesRemainCompatible() {
        val expected = "4b504d31011400000000000000010000000000000000".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        assertArrayEquals(expected, ProductSettingsMetadata(1, emptySet(), SettingsIdentifiers()).encode())
        assertArrayEquals(expected, ProductSettingsMetadata.decode(expected).encode())
    }
    @Test fun metadataOwnsCanonicalFavoriteAndProfileDerivedRequestReferences() {
        val favorites = mutableSetOf("favorite-b", "favorite-a")
        val ids = SettingsIdentifiers(CatalogId("strategy-canary"), CatalogId("resolver-canary"), CatalogId("probe-canary"))
        val record = ProductSettingsMetadata(7, favorites, ids)
        favorites.clear()
        val encoded = record.encode()
        val decoded = ProductSettingsMetadata.decode(encoded)
        encoded.fill(0)
        assertEquals(7L, decoded.settingsRevision)
        assertEquals(setOf("favorite-a", "favorite-b"), decoded.favoriteIds)
        assertEquals(ids, decoded.identifiers)
        assertArrayEquals(record.encode(), decoded.encode())
        assertFalse(decoded.toString().contains("canary"))
    }
    @Test fun metadataRejectsWrongRoleVersionRevisionBoundsAndTrailingBytes() {
        val encoded = ProductSettingsMetadata(1, setOf("favorite"), SettingsIdentifiers()).encode()
        for (end in encoded.indices) assertThrows(IllegalArgumentException::class.java) { ProductSettingsMetadata.decode(encoded.copyOf(end)) }
        for (offset in listOf(4, 5)) assertThrows(IllegalArgumentException::class.java) {
            ProductSettingsMetadata.decode(encoded.clone().also { it[offset] = 99 })
        }
        assertThrows(IllegalArgumentException::class.java) { ProductSettingsMetadata.decode(encoded + 0) }
        assertThrows(IllegalArgumentException::class.java) { ProductSettingsMetadata(0, emptySet(), SettingsIdentifiers()) }
        assertThrows(IllegalArgumentException::class.java) { ProductSettingsMetadata(1, (0..1024).map { "favorite-$it" }.toSet(), SettingsIdentifiers()) }
    }
}

/** All-byte truncations cover every field boundary as well as partial field bodies. */
internal fun checkRecord(bytes: ByteArray, role: Int, maximum: Int, decodeEncode: (ByteArray) -> ByteArray) {
    assertEquals(role, bytes[5].toInt())
    assertEquals(1, bytes[4].toInt())
    assertArrayEquals(bytes, decodeEncode(bytes))
    for (end in bytes.indices) assertThrows("truncated at $end", IllegalArgumentException::class.java) { decodeEncode(bytes.copyOf(end)) }
    for (offset in 0..5) assertThrows("header $offset", IllegalArgumentException::class.java) {
        decodeEncode(bytes.clone().also { it[offset] = 0 })
    }
    assertThrows(IllegalArgumentException::class.java) { decodeEncode(bytes + 0) }
    assertThrows(IllegalArgumentException::class.java) { decodeEncode(ByteArray(maximum + 1)) }
}

internal fun checkMalformed(bytes: ByteArray, mutations: List<(ByteArray) -> Unit>, decode: (ByteArray) -> Unit) {
    mutations.forEachIndexed { index, mutate ->
        val bad = bytes.clone().also(mutate)
        assertThrows("malformed case $index", IllegalArgumentException::class.java) { decode(bad) }
    }
}
internal fun putShort(bytes: ByteArray, offset: Int, value: Int) { java.nio.ByteBuffer.wrap(bytes).putShort(offset, value.toShort()) }
internal fun putInt(bytes: ByteArray, offset: Int, value: Int) { java.nio.ByteBuffer.wrap(bytes).putInt(offset, value) }
internal fun putLong(bytes: ByteArray, offset: Int, value: Long) { java.nio.ByteBuffer.wrap(bytes).putLong(offset, value) }

internal class RecordFake : SecureBlobAccess {
    var bytes: ByteArray? = null
    var received: ByteArray? = null
    var reopened: ByteArray? = null
    var id: String? = null
    var role: SecureDataClass? = null
    var fail = false
    var stages = 0
    override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean { id = localRecordId; role = dataClass; return bytes != null }
    override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray {
        id = localRecordId; role = dataClass
        return checkNotNull(bytes).clone().also { reopened = it }
    }
    override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) {
        stages++; id = localRecordId; role = dataClass; received = exactBytes
        if (fail) throw IllegalStateException("STAGE_FAILURE")
        bytes = exactBytes.clone()
    }
    override fun delete(localRecordId: String, dataClass: SecureDataClass) { id = localRecordId; role = dataClass; bytes = null }
    override fun deleteAll() = error("OUT_OF_SCOPE")
}

internal fun checkStore(id: String, role: SecureDataClass, expected: ByteArray,
    save: (SecureBlobAccess) -> Unit, load: (SecureBlobAccess) -> ByteArray?,
    delete: (SecureBlobAccess) -> Unit, readOnlySave: (SecureBlobAccess) -> Unit, readOnlyDelete: (SecureBlobAccess) -> Unit) {
    val fake = RecordFake()
    assertNull(load(fake)); assertEquals(id, fake.id); assertEquals(role, fake.role)
    save(fake); assertEquals(id, fake.id); assertEquals(role, fake.role)
    assertArrayEquals(expected, fake.bytes); assertTrue(fake.received!!.all { it == 0.toByte() })
    assertArrayEquals(expected, load(fake)); assertTrue(fake.reopened!!.all { it == 0.toByte() })
    fake.bytes = byteArrayOf(0)
    assertThrows(IllegalArgumentException::class.java) { load(fake) }
    assertTrue(fake.reopened!!.all { it == 0.toByte() })
    fake.fail = true
    assertThrows(IllegalStateException::class.java) { save(fake) }
    assertTrue(fake.received!!.all { it == 0.toByte() })
    val calls = fake.stages
    assertThrows(IllegalStateException::class.java) { readOnlySave(fake) }
    assertThrows(IllegalStateException::class.java) { readOnlyDelete(fake) }
    assertEquals(calls, fake.stages); assertArrayEquals(byteArrayOf(0), fake.bytes)
    delete(fake); assertNull(fake.bytes); assertEquals(id, fake.id); assertEquals(role, fake.role)
}
