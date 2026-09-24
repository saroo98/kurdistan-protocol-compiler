// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.metadata

import org.junit.Assert.*
import org.junit.Test
import kotlinx.coroutines.runBlocking

class ProductOperationProjectionTest {
    private fun operation() = ProductOperationProjectionEntity("2".repeat(64), "UPDATE", "profile-a",
        "APPLIED", 0, 2, 2, 42, false)

    @Test fun operationRejectsInvalidIdentityEnumsScopeAttemptsAndTimes() {
        val good = operation()
        good.validate()
        for (bad in listOf(good.copy(operationId = "0".repeat(64)), good.copy(operationId = "A".repeat(64)),
            good.copy(kind = "UNKNOWN"), good.copy(state = "UNKNOWN"), good.copy(scopeRecordId = "private/path"),
            good.copy(attempt = -1), good.copy(attempt = 11), good.copy(settingsRevisionBefore = -1),
            good.copy(settingsRevisionAfter = -1), good.copy(startedEpochHour = -1))) {
            assertThrows(IllegalArgumentException::class.java) { bad.validate() }
        }
        good.copy(attempt = 10, scopeRecordId = null, state = "ROLLED_BACK").validate()
    }

    @Test fun catalogBindsExactOperationAndRetainsLegacyRows() {
        val legacy = byteArrayOf(0x4b, 0x50, 0x4d, 0x32, 0, 0, 0, 0)
        assertNull(ProductCatalogProjectionCodec.decode(legacy).operation)
        val encoded = ProductCatalogProjectionCodec.encode(emptyList(), operation())
        assertArrayEquals(byteArrayOf(0x50, 0x36, 0x52, 0x50, 1, 0, 0, 0, 8), encoded.copyOfRange(0, 9))
        assertEquals(operation(), ProductCatalogProjectionCodec.decode(encoded).operation)
        assertEquals(emptyList<ProfileCatalogEntity>(), ProfileCatalogProjectionCodec.decode(encoded))
        assertFalse(encoded.contentEquals(ProductCatalogProjectionCodec.encode(emptyList(), operation().copy(attempt = 1))))
        assertArrayEquals(encoded, ProductCatalogProjectionCodec.encode(ProductCatalogProjectionCodec.decode(encoded).rows,
            ProductCatalogProjectionCodec.decode(encoded).operation))
    }

    @Test fun malformedProductCatalogNeverFallsBackToLegacy() {
        val encoded = ProductCatalogProjectionCodec.encode(emptyList(), operation())
        for (bad in listOf(encoded.copyOf(encoded.size - 1), encoded + 0, encoded.clone().also { it[4] = 2 },
            encoded.clone().also { it[it.lastIndex] = 2 }, ByteArray(512 * 1024 + 1))) {
            assertThrows(IllegalArgumentException::class.java) { ProductCatalogProjectionCodec.decode(bad) }
        }
    }

    @Test fun daoReadsIndependentOperationAndRejectsMultiplicityMismatchAndStaleExpectedRow() = runBlocking {
        val witness = ProtectedProjectionEntity(storeEpoch = "1".repeat(32), operationId = "2".repeat(64),
            revision = 2, imageDigest = ProfileCatalogProjectionCodec.imageDigest(emptyList()))
        val dao = OperationDaoFixture(witness, listOf(operation()))
        assertEquals(operation(), dao.read().operation)
        dao.operations = listOf(operation(), operation().copy(operationId = "3".repeat(64)))
        assertThrows(IllegalStateException::class.java) { runBlocking { dao.read() } }
        dao.operations = listOf(operation().copy(operationId = "3".repeat(64)))
        assertThrows(IllegalStateException::class.java) { runBlocking { dao.read() } }
        dao.operations = listOf(operation())
        val next = witness.copy(operationId = "4".repeat(64), revision = 4)
        assertThrows(IllegalStateException::class.java) { runBlocking {
            dao.publish(CatalogProjection(emptyList(), witness), next, emptyList())
        } }
        assertEquals(0, dao.writes)
        dao.publish(dao.read(), next, emptyList(), emptyList(), operation().copy(operationId = next.operationId))
        assertEquals(operation().copy(operationId = next.operationId), dao.read().operation)
        assertEquals(listOf("clear-operation", "clear-bindings", "clear-rows", "put-rows", "put-bindings", "put-operation", "put-witness"), dao.actions)
    }
}

private class OperationDaoFixture(private var identity: ProtectedProjectionEntity?,
    var operations: List<ProductOperationProjectionEntity>) : ProtectedProjectionDao() {
    var writes = 0
    val actions = mutableListOf<String>()
    private fun write(name: String) { writes++; actions += name }
    override suspend fun rows() = emptyList<ProfileCatalogEntity>()
    override suspend fun bindings() = emptyList<RecipientBindingEntity>()
    override suspend fun witness() = identity
    override suspend fun operationRows() = operations.toList()
    override suspend fun putOperation(value: ProductOperationProjectionEntity) { write("put-operation"); operations = listOf(value) }
    override suspend fun clearOperation() { write("clear-operation"); operations = emptyList() }
    override suspend fun putWitness(value: ProtectedProjectionEntity) { write("put-witness"); identity = value }
    override suspend fun putRows(value: List<ProfileCatalogEntity>) { check(value.isEmpty()); write("put-rows") }
    override suspend fun putBindings(value: List<RecipientBindingEntity>) { check(value.isEmpty()); write("put-bindings") }
    override suspend fun clearBindings() { write("clear-bindings") }
    override suspend fun clearRows() { write("clear-rows") }
}
