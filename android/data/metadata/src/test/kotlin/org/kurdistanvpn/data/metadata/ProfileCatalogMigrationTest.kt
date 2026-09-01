// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.metadata

import androidx.sqlite.db.SupportSQLiteDatabase
import java.lang.reflect.Proxy
import org.junit.Assert.*
import org.junit.Test
import kotlinx.coroutines.runBlocking

class ProfileCatalogMigrationTest {
    @Test fun bindingEncodingUsesIndependentGoldenAndRejectsCardinalityOrContextConflicts() {
        val binding = RecipientBindingEntity("p", "k", "1".repeat(64), 2)
        val golden = ("4b504231000000010170016b40" + "31".repeat(64) + "0000000000000002")
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        assertArrayEquals(golden, RecipientBindingProjectionCodec.encode(listOf(binding)))
        assertEquals(listOf(binding), RecipientBindingProjectionCodec.decode(golden))
        assertEquals("17ec3ae455deaf280cce07692354b0dde06cc7f34b8c12d65ae74b0c44fbb2b9",
            RecipientBindingProjectionCodec.imageDigest(listOf(binding)))
        val bad = listOf(
            listOf(binding, binding.copy(clientKeyRecordId = "other")),
            listOf(binding, binding.copy(profileRecordId = "other")),
            listOf(binding.copy(committedRevision = 0)),
            listOf(binding.copy(committedRevision = 3)),
            listOf(binding.copy(operationId = "0".repeat(64))),
        )
        for (values in bad) assertThrows(IllegalArgumentException::class.java) { RecipientBindingProjectionCodec.encode(values) }
        assertThrows(IllegalArgumentException::class.java) { RecipientBindingProjectionCodec.decode(golden + byteArrayOf(0)) }
    }

    @Test fun combinedProjectionDigestUsesIndependentFramedGolden() {
        val row = ProfileCatalogEntity("p", "FINALIZED", 1, 1, "AVAILABLE", 2, "1".repeat(64), "NONE")
        val binding = RecipientBindingEntity("p", "k", "1".repeat(64), 2)
        // Hand-encoded KPM2/KPB1 bytes, independently hashed with .NET SHA-256.
        val rowGolden = ("4b504d320000000101700946494e414c495a454409415641494c41424c450000000100000001000000000000000240" +
            "31".repeat(64) + "044e4f4e45").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        assertArrayEquals(rowGolden, ProfileCatalogProjectionCodec.encode(listOf(row)))
        assertEquals("03a4894a4a44b6ddb1e2062abcead57c3a3646f3bc24ed2a299c0df88465bbd5",
            ProfileCatalogProjectionCodec.imageDigest(listOf(row), listOf(binding)))
        assertNotEquals(ProfileCatalogProjectionCodec.imageDigest(listOf(row)),
            ProfileCatalogProjectionCodec.imageDigest(listOf(row), listOf(binding)))
    }

    @Test fun bindingDecoderRejectsEveryTruncationAndNoncanonicalOrder() {
        val a = RecipientBindingEntity("p-a", "k-a", "1".repeat(64), 2)
        val b = a.copy(profileRecordId = "p-b", clientKeyRecordId = "k-b")
        val one = RecipientBindingProjectionCodec.encode(listOf(a))
        for (length in 0 until one.size) {
            assertThrows("prefix length=$length", IllegalArgumentException::class.java) {
                RecipientBindingProjectionCodec.decode(one.copyOf(length))
            }
        }
        val aRecord = one.copyOfRange(8, one.size)
        val bRecord = RecipientBindingProjectionCodec.encode(listOf(b)).let { it.copyOfRange(8, it.size) }
        val reordered = byteArrayOf(0x4b, 0x50, 0x42, 0x31, 0, 0, 0, 2) + bRecord + aRecord
        assertThrows(IllegalArgumentException::class.java) { RecipientBindingProjectionCodec.decode(reordered) }
        val tooMany = (1..33).map { a.copy(profileRecordId = "p-$it", clientKeyRecordId = "k-$it") }
        assertThrows(IllegalArgumentException::class.java) { RecipientBindingProjectionCodec.encode(tooMany) }
    }

    @Test fun unwitnessedBindingsAndStaleExpectedRelationshipsCannotBeAdopted() = runBlocking {
        val op = "2".repeat(64)
        val legacy = ProfileCatalogEntity("profile-a", "FINALIZED", 1, 1, "AVAILABLE")
        val committed = legacy.stampCommitted(op, 2, CatalogQuarantineReason.NONE)
        val binding = RecipientBindingEntity("profile-a", "key-a", op, 2)
        val target = ProjectionFixture(listOf(legacy), null, listOf(binding))
        assertThrows(IllegalStateException::class.java) { runBlocking { target.read() } }
        assertEquals(0, target.writes)

        val current = ProtectedProjectionEntity(1, "1".repeat(32), op, 2,
            ProfileCatalogProjectionCodec.imageDigest(listOf(committed), listOf(binding)))
        val nextOp = "3".repeat(64)
        val nextRow = committed.stampCommitted(nextOp, 4, CatalogQuarantineReason.NONE)
        val nextBinding = binding.copy(operationId = nextOp, committedRevision = 4)
        val next = current.copy(operationId = nextOp, revision = 4,
            imageDigest = ProfileCatalogProjectionCodec.imageDigest(listOf(nextRow), listOf(nextBinding)))
        val stale = ProjectionFixture(listOf(committed), current, listOf(binding))
        assertThrows(IllegalStateException::class.java) { runBlocking {
            stale.publish(CatalogProjection(listOf(committed), current), next, listOf(nextRow), listOf(nextBinding))
        } }
        assertEquals(0, stale.writes)
    }

    @Test fun bindingSubstitutionAndStaleRevisionRejectBeforeAnyProjectionWrite() = runBlocking {
        val op = "2".repeat(64)
        val row = ProfileCatalogEntity("profile-a", "FINALIZED", 1, 1, "AVAILABLE").stampCommitted(op, 2, CatalogQuarantineReason.NONE)
        val binding = RecipientBindingEntity("profile-a", "key-a", op, 2)
        val identity = ProtectedProjectionEntity(1, "1".repeat(32), op, 2,
            ProfileCatalogProjectionCodec.imageDigest(listOf(row), listOf(binding)))
        val dao = ProjectionFixture(listOf(row), identity, listOf(binding.copy(clientKeyRecordId = "key-b")))
        assertThrows(IllegalStateException::class.java) { runBlocking { dao.read() } }
        assertEquals(0, dao.writes)

        val legacy = ProfileCatalogEntity("profile-a", "FINALIZED", 1, 1, "AVAILABLE")
        for (badBinding in listOf(binding.copy(committedRevision = 4), binding.copy(operationId = "3".repeat(64)),
            binding.copy(profileRecordId = "missing-profile"))) {
            val target = ProjectionFixture(listOf(legacy), null)
            val proposed = identity.copy(imageDigest = ProfileCatalogProjectionCodec.imageDigest(listOf(row), listOf(badBinding)))
            assertThrows(IllegalStateException::class.java) { runBlocking {
                target.publish(CatalogProjection(listOf(legacy), null), proposed, listOf(row), listOf(badBinding))
            } }
            assertEquals(0, target.writes)
        }
    }

    @Test fun publicationOwnsBindingsAndClearsChildrenBeforeReplacingParentRows(): Unit = runBlocking {
        val legacy = ProfileCatalogEntity("profile-a", "FINALIZED", 1, 1, "AVAILABLE")
        val op = "2".repeat(64)
        val row = legacy.stampCommitted(op, 2, CatalogQuarantineReason.NONE)
        val binding = RecipientBindingEntity("profile-a", "key-a", op, 2)
        val supplied = mutableListOf(binding)
        val expected = CatalogProjection(listOf(legacy), null, emptyList())
        val target = ProjectionFixture(listOf(legacy), null)
        val next = ProtectedProjectionEntity(1, "1".repeat(32), op, 2,
            ProfileCatalogProjectionCodec.imageDigest(listOf(row), supplied))
        target.publish(expected, next, listOf(row), supplied)
        supplied.clear()
        assertEquals(listOf(binding), target.read().bindings)
        assertEquals(listOf("clear-bindings", "clear-rows", "put-rows", "put-bindings", "put-witness"), target.actions)
        val mutableRead = target.read().bindings as MutableList<RecipientBindingEntity>
        assertThrows(UnsupportedOperationException::class.java) { mutableRead.clear() }
    }

    @Test fun aQuarantinedOrLegacyRowNeverBecomesAuthorityEligibleThroughStatusAlone() {
        val legacy = ProfileCatalogEntity("profile-a", "FINALIZED", 1, 1, "AVAILABLE")
        assertFalse(legacy.isAuthorityEligible())
        val committed = legacy.stampCommitted("2".repeat(64), 2, CatalogQuarantineReason.NONE)
        assertTrue(committed.isAuthorityEligible())
        assertFalse(committed.copy(quarantineReason = "KEY_INVALIDATED").isAuthorityEligible())
        assertFalse(committed.copy(health = "DEGRADED").isAuthorityEligible())
        assertFalse(committed.copy(transactionState = "PREPARED").isAuthorityEligible())
        assertThrows(IllegalArgumentException::class.java) { legacy.stampCommitted("2".repeat(64), 0, CatalogQuarantineReason.NONE) }
    }

    @Test fun canonicalRowImageBindsCommittedIdentityAndQuarantineReason() {
        val row = ProfileCatalogEntity("profile-a", "FINALIZED", 1, 1, "AVAILABLE", 2, "2".repeat(64), "NONE")
        val encoded = ProfileCatalogProjectionCodec.encode(listOf(row))
        assertEquals(listOf(row), ProfileCatalogProjectionCodec.decode(encoded))
        for (changed in listOf(row.copy(committedRevision = 4), row.copy(operationId = "3".repeat(64)),
            row.copy(quarantineReason = "INCONSISTENT_STATE"))) {
            assertNotEquals(ProfileCatalogProjectionCodec.imageDigest(listOf(row)),
                ProfileCatalogProjectionCodec.imageDigest(listOf(changed)))
        }
    }

    @Test fun publicationCannotAdoptUnverifiedLegacyRowsOrUseStaleRowCommitIdentity() = runBlocking {
        val legacy = ProfileCatalogEntity("profile-a", "FINALIZED", 1, 1, "AVAILABLE")
        val op = "2".repeat(64)
        for (replacement in listOf(legacy, legacy.copy(committedRevision = 2, operationId = "3".repeat(64)),
            legacy.copy(committedRevision = 4, operationId = op))) {
            val dao = ProjectionFixture(listOf(legacy), null)
            val next = ProtectedProjectionEntity(1, "1".repeat(32), op, 2,
                ProfileCatalogProjectionCodec.imageDigest(listOf(replacement)))
            assertThrows(IllegalStateException::class.java) { runBlocking {
                dao.publish(CatalogProjection(listOf(legacy), null), next, listOf(replacement))
            } }
            assertEquals(0, dao.writes)
        }
    }

    @Test fun rowEncodingRejectsMalformedRevisionOperationAndQuarantineMetadata() {
        val legacy = ProfileCatalogEntity("profile-a", "FINALIZED", 1, 1, "AVAILABLE")
        val invalid = listOf(
            legacy.copy(quarantineReason = "NONE"),
            legacy.copy(committedRevision = -2),
            legacy.copy(committedRevision = 3, operationId = "2".repeat(64)),
            legacy.copy(committedRevision = 2, operationId = "0".repeat(64)),
            legacy.copy(committedRevision = 2, operationId = "2".repeat(32)),
            legacy.copy(quarantineReason = "unbounded arbitrary reason"),
        )
        for (row in invalid) {
            assertThrows(IllegalArgumentException::class.java) { ProfileCatalogProjectionCodec.encode(listOf(row)) }
        }
    }

    @Test fun rowSubstitutionCannotBeHiddenBehindAnUnchangedWitness() = runBlocking {
        val row = ProfileCatalogEntity("profile-a", "FINALIZED", 1, 1, "AVAILABLE")
        val old = ProtectedProjectionEntity(1, "1".repeat(32), "2".repeat(64), 2, "3".repeat(64))
        val dao = ProjectionFixture(listOf(row), old)
        assertThrows(IllegalStateException::class.java) { runBlocking {
            dao.publish(CatalogProjection(listOf(row), old), old.copy(operationId = "4".repeat(64), revision = 4,
                imageDigest = ProfileCatalogProjectionCodec.imageDigest(listOf(row))), listOf(row))
        } }
        assertEquals(0, dao.writes)
    }

    @Test fun publicationComparesActualRowsEvenDuringFirstMigrationAndNeverTrustsANewDigest() = runBlocking {
        val row = ProfileCatalogEntity("profile-a", "FINALIZED", 1, 1, "AVAILABLE")
        val committed = row.copy(committedRevision = 2, operationId = "2".repeat(64), quarantineReason = "NONE")
        val next = ProtectedProjectionEntity(1, "1".repeat(32), "2".repeat(64), 2,
            ProfileCatalogProjectionCodec.imageDigest(listOf(committed)))
        val dao = ProjectionFixture(listOf(row), null)
        assertThrows(IllegalStateException::class.java) { runBlocking {
            dao.publish(CatalogProjection(emptyList(), null), next, listOf(committed))
        } }
        assertThrows(IllegalStateException::class.java) { runBlocking {
            dao.publish(CatalogProjection(listOf(row), null), next.copy(imageDigest = "3".repeat(64)), listOf(committed))
        } }
        assertEquals(0, dao.writes)
        dao.publish(CatalogProjection(listOf(row), null), next, listOf(committed))
        assertEquals(next, dao.read().witness)
        assertEquals(listOf(committed), dao.read().rows)
    }

    @Test fun migrationPreservesLegacyFieldsAndAddsNoTrustedIdentityOrRecipientBinding() {
        val statements = mutableListOf<String>()
        val database = Proxy.newProxyInstance(SupportSQLiteDatabase::class.java.classLoader,
            arrayOf(SupportSQLiteDatabase::class.java)) { _, method, args ->
            check(method.name == "execSQL")
            statements += args!![0] as String
            null
        } as SupportSQLiteDatabase
        KurdistanMetadataDatabase.MIGRATION_1_2.migrate(database)
        assertEquals(listOf(
            "ALTER TABLE `profile_catalog` ADD COLUMN `committedRevision` INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE `profile_catalog` ADD COLUMN `operationId` TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE `profile_catalog` ADD COLUMN `quarantineReason` TEXT NOT NULL DEFAULT 'LEGACY_UNVERIFIED'",
            "CREATE TABLE IF NOT EXISTS `protected_projection` (`singleton` INTEGER NOT NULL, `storeEpoch` TEXT NOT NULL, `operationId` TEXT NOT NULL, `revision` INTEGER NOT NULL, `imageDigest` TEXT NOT NULL, PRIMARY KEY(`singleton`))",
            "CREATE TABLE IF NOT EXISTS `recipient_bindings` (`profileRecordId` TEXT NOT NULL, `clientKeyRecordId` TEXT NOT NULL, `operationId` TEXT NOT NULL, `committedRevision` INTEGER NOT NULL, PRIMARY KEY(`profileRecordId`), FOREIGN KEY(`profileRecordId`) REFERENCES `profile_catalog`(`localRecordId`) ON UPDATE RESTRICT ON DELETE RESTRICT )",
            "CREATE UNIQUE INDEX IF NOT EXISTS `index_recipient_bindings_clientKeyRecordId` ON `recipient_bindings` (`clientKeyRecordId`)",
        ), statements)
    }

    @Test fun projectionWitnessRejectsInvalidIdentityRevisionAndDigest() {
        val good = ProtectedProjectionEntity(1, "1".repeat(32), "2".repeat(64), 2, "3".repeat(64))
        good.validate()
        for (bad in listOf(good.copy(singleton = 2), good.copy(revision = 0), good.copy(revision = 3),
            good.copy(storeEpoch = "0".repeat(32)), good.copy(operationId = "bad"), good.copy(imageDigest = "arbitrary"))) {
            assertThrows(IllegalArgumentException::class.java) { bad.validate() }
        }
    }

    @Test fun catalogProjectionEncodingIsOrderIndependentAndRejectsDuplicateRows() {
        val a = ProfileCatalogEntity("profile-a", "FINALIZED", 1, 1, "AVAILABLE")
        val b = ProfileCatalogEntity("profile-b", "PREPARED", 1, 1, "QUARANTINED")
        assertArrayEquals(ProfileCatalogProjectionCodec.encode(listOf(a, b)), ProfileCatalogProjectionCodec.encode(listOf(b, a)))
        assertEquals(listOf(a, b), ProfileCatalogProjectionCodec.decode(ProfileCatalogProjectionCodec.encode(listOf(a, b))))
        assertThrows(IllegalArgumentException::class.java) { ProfileCatalogProjectionCodec.encode(listOf(a, a)) }
        assertThrows(IllegalArgumentException::class.java) { ProfileCatalogProjectionCodec.encode(listOf(a.copy(health = "UNKNOWN"))) }
    }
}

private class ProjectionFixture(private var catalog: List<ProfileCatalogEntity>,
    private var identity: ProtectedProjectionEntity?, private var relationships: List<RecipientBindingEntity> = emptyList()) : ProtectedProjectionDao() {
    var writes = 0
    val actions = mutableListOf<String>()
    override suspend fun rows() = catalog.toList()
    override suspend fun bindings() = relationships.toList()
    override suspend fun witness() = identity
    override suspend fun putWitness(value: ProtectedProjectionEntity) { writes++; actions += "put-witness"; identity = value }
    override suspend fun putRows(value: List<ProfileCatalogEntity>) { writes++; actions += "put-rows"; catalog = value.toList() }
    override suspend fun putBindings(value: List<RecipientBindingEntity>) { writes++; actions += "put-bindings"; relationships = value.toList() }
    override suspend fun clearBindings() { writes++; actions += "clear-bindings"; relationships = emptyList() }
    override suspend fun clearRows() { check(relationships.isEmpty()); writes++; actions += "clear-rows"; catalog = emptyList() }
}
