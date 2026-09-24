// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*

class ProfileProjectionStoreTest {
    @Test fun storedPreviewIdentityAssertionIsReadOnlyBoundToProfileAndClearsExactReadBuffer() {
        val source = ProfilePreviewCodec.encode(RedactedProfilePreview("synthetic", "public", "fingerprint", "lineage", 7uL, 900, false), "Legacy alias")
        var reopened: ByteArray? = null
        var reads = 0
        val blobs = object : SecureBlobReadAccess {
            override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean = error("No optional fallback")
            override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray {
                assertEquals("profile-a", localRecordId)
                assertEquals(SecureDataClass.PROFILE_PREVIEW, dataClass)
                reads++
                return source.clone().also { reopened = it }
            }
        }
        val value = StoredProfileProjection(ProfileProjection(CatalogId("profile-a"), SafeAlias("User alias"), 7uL, 900, ProjectionStatus.VERIFIED),
            DeploymentProjection(SafeAlias("User alias"), profileGeneration = 7uL, profileExpiryEpochSeconds = 900))
        ProfileProjectionStore.readOnly(blobs).requireStoredPreviewIdentity(value)
        assertEquals(1, reads)
        assertTrue(checkNotNull(reopened).all { it == 0.toByte() })
    }

    @Test fun storedPreviewIdentityRejectsMissingCorruptWrongProfileAndMismatchedFacts() {
        val source = ProfilePreviewCodec.encode(RedactedProfilePreview("synthetic", "public", "fingerprint", "lineage", 7uL, 900, false), "Legacy alias")
        val profile = ProfileProjection(CatalogId("profile-a"), SafeAlias("User alias"), 7uL, 900, ProjectionStatus.VERIFIED)
        for (scenario in listOf("missing", "corrupt", "wrong-profile", "generation", "expiry", "deployment")) {
            var reopened: ByteArray? = null
            val blobs = object : SecureBlobReadAccess {
                override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean = error("No optional fallback")
                override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray {
                    check(dataClass == SecureDataClass.PROFILE_PREVIEW)
                    val availableId = if (scenario == "wrong-profile") "profile-b" else "profile-a"
                    check(scenario != "missing" && localRecordId == availableId)
                    return (if (scenario == "corrupt") byteArrayOf(1, 2, 3) else source.clone()).also { reopened = it }
                }
            }
            val value = StoredProfileProjection(when (scenario) {
                "generation" -> profile.copy(generation = 8uL)
                "expiry" -> profile.copy(expiresAtEpochSeconds = 901)
                else -> profile
            }, if (scenario == "deployment") DeploymentProjection(SafeAlias("User alias"), profileGeneration = 8uL,
                profileExpiryEpochSeconds = 900) else null)
            assertThrows(scenario, Exception::class.java) { ProfileProjectionStore.readOnly(blobs).requireStoredPreviewIdentity(value) }
            if (scenario !in setOf("missing", "wrong-profile")) assertTrue(scenario, checkNotNull(reopened).all { it == 0.toByte() })
        }
    }
    @Test fun malformedProjectionStringsPresenceAndNumericFieldsFailClosed() {
        val bytes = StoredProfileProjection(ProfileProjection(CatalogId("p"), SafeAlias("A"), 0uL, 0, ProjectionStatus.UNAVAILABLE), null).encode()
        checkMalformed(bytes, listOf({ putShort(it, 6, 65) }, { it[8] = 'A'.code.toByte() },
            { putShort(it, 9, 385) }, { it[11] = 0xc0.toByte() }, { putLong(it, 20, -1) },
            { putShort(it, 28, 65) }, { it[30] = '?'.code.toByte() }, { it[41] = 2 })) { StoredProfileProjection.decode(it) }
    }
    @Test fun profileRoundTripPreservesEveryConstructorFieldWithoutInventingAuthority() {
        val profile = ProfileProjection(CatalogId("profile-a"), SafeAlias("سۆران"), ULong.MAX_VALUE, Long.MAX_VALUE, ProjectionStatus.VERIFIED)
        val deployment = DeploymentProjection(SafeAlias("Deployment"), ULong.MAX_VALUE, 0uL, 0,
            ProjectionStatus.VERIFIED, ProjectionStatus.UNAVAILABLE, ProjectionStatus.VERIFIED,
            UpdateProjection(ProjectionStatus.VERIFIED, UpdateCategory.AVAILABLE, 1024),
            NodeProjection(ProjectionStatus.VERIFIED, CatalogId("node"), SafeAlias("Node")),
            StrategyProjection(ProjectionStatus.VERIFIED, CatalogId("strategy"), null),
            PathProjection(ProjectionStatus.VERIFIED, null, SafeAlias("Path")),
            ExitProjection(ProjectionStatus.VERIFIED, ExitRegion.ASIA),
            HealthProjection(ProjectionStatus.VERIFIED, HealthCategory.DEGRADED))
        for (value in listOf(StoredProfileProjection(profile, deployment), StoredProfileProjection(profile, null))) {
            checkRecord(value.encode(), 19, 16384) { StoredProfileProjection.decode(it).encode() }
            val decoded = StoredProfileProjection.decode(value.encode())
            assertEquals(profile, decoded.profile); assertEquals(value.deployment, decoded.deployment)
        }
    }
    @Test fun profileWrapperContractAndIdentityBinding() {
        val value = StoredProfileProjection(ProfileProjection(CatalogId("profile-a"), SafeAlias("A"), 0uL, 0, ProjectionStatus.UNAVAILABLE), null)
        checkStore("profile-a", SecureDataClass.PROFILE_PROJECTION, value.encode(),
            { ProfileProjectionStore(it).save("profile-a", value) }, { ProfileProjectionStore(it).load("profile-a")?.encode() },
            { ProfileProjectionStore(it).delete("profile-a") }, { ProfileProjectionStore.readOnly(it).save("profile-a", value) },
            { ProfileProjectionStore.readOnly(it).delete("profile-a") })
        assertThrows(IllegalArgumentException::class.java) { ProfileProjectionStore(RecordFake()).save("profile-b", value) }
        val mismatched = RecordFake().also { it.bytes = value.encode() }
        assertThrows(IllegalArgumentException::class.java) { ProfileProjectionStore(mismatched).load("profile-b") }
        assertTrue(mismatched.reopened!!.all { it == 0.toByte() })
    }
}
