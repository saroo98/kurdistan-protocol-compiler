// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import java.lang.reflect.Modifier
import org.kurdistanvpn.core.nativeapi.DurableDirectory
import org.kurdistanvpn.core.nativeapi.DurableFileIdentity
import org.junit.Assert.*
import org.junit.Test

/** Compiled-signature checks. Kotlin external-module denials run separately in the offline guard.
 * Neither compiler visibility nor this test claims a sandbox against reflection or same-UID code. */
class ProtectedStateStructuralBoundaryTest {
    private fun type(name: String): Class<*> = Class.forName("org.kurdistanvpn.data.protectedstate.$name")
    @Test fun durableConstructionHasNoPublicSourceConstructor() {
        for (type in listOf("ProtectedStateMutationBroker", "JournalControl", "JournalDigest",
            "ProtectedStateSnapshot", "EncryptedJournalStorage", "ProtectedStateApplicationFacade").map(::type)) {
            val constructors = type.declaredConstructors.filterNot { it.isSynthetic }
            assertTrue(type.simpleName, constructors.isNotEmpty())
            assertTrue(type.simpleName, constructors.all { Modifier.isPrivate(it.modifiers) })
        }
    }

    @Test fun applicationFacadeExposesTypedOperationsNotRawWritersOrReceipts() {
        val forbidden = setOf("JournalStorage", "EncryptedJournalStorage", "ProtectedStateMutationBroker",
            "ImmutableProtectedObjectWriter", "ProtectedProjectionAccess", "ProtectedStateResetRecoveryCoordinator").map(::type).toSet()
        for (method in type("ProtectedStateApplicationFacade").declaredMethods.filter {
            Modifier.isPublic(it.modifiers) && !it.isSynthetic
        }) {
            assertFalse(method.name, method.returnType in forbidden)
            assertTrue(method.name, method.parameterTypes.none { it in forbidden })
        }
        for (field in type("ProtectedStateApplicationFacade").declaredFields.filterNot { it.isSynthetic }) {
            if (field.type in forbidden) assertTrue(field.name, Modifier.isPrivate(field.modifiers))
        }
        val productCommands = setOf("migrateProductProjectionConfirmed", "recoverProductSchemaConfirmed",
            "recoverProductOperationConfirmed", "setDeploymentDisplay", "recordUpdate", "recordProbe",
            "replaceTrustedRules", "recordUsage", "recordAppLockFailure", "recordStart", "recordCleanStop")
        val exposed = type("ProtectedStateApplicationFacade").declaredMethods.filter { it.name in productCommands && !it.isSynthetic }
        assertEquals(productCommands, exposed.map { it.name }.toSet())
        for (method in exposed) {
            // Suspend wrappers return Object on JVM; the continuation carries the typed outcome.
            assertTrue(method.name, method.genericParameterTypes.last().typeName.contains("ProtectedStateApplicationFacade\$CommandResult"))
            assertFalse(method.name, method.genericParameterTypes.any { parameter ->
                listOf("DurableMutationResult", "ProductOperationState", "SettingsOperationState", "ProfileCatalogEntity",
                    "ProductOperationProjectionEntity", "kotlinx.coroutines.flow").any { it in parameter.typeName }
            })
        }
        for (projection in listOf("ProductStorageReadProjection", "TrustedNetworkStorageSummary")) {
            val projected = type("ProtectedStateApplicationFacade\$$projection")
            assertTrue(projection, projected.declaredFields.none { it.type in forbidden })
            assertTrue(projection, projected.declaredMethods.filterNot { it.isSynthetic }.all {
                it.name.startsWith("get") || it.name == "toString"
            })
        }
        val trust = exposed.single { it.name == "replaceTrustedRules" }
        assertEquals(listOf(Long::class.javaPrimitiveType, org.kurdistanvpn.data.secure.StoredTrustedNetworks::class.java),
            trust.parameterTypes.dropLast(1))
        val command = ProductStoreCommand.ReplaceTrustedRules::class.java
        assertEquals(listOf(org.kurdistanvpn.data.secure.StoredTrustedNetworks::class.java),
            command.declaredFields.filterNot { it.isSynthetic }.map { it.type })
    }

    @Test fun readProjectionHasNoMutationMethodAndNoWritableRootCapability() {
        val methods = type("ProtectedProjectionReadAccess").declaredMethods.filterNot { it.isSynthetic }
        assertEquals(setOf("read", "readForCheckpoint"), methods.map { it.name }.toSet())
        assertEquals(0, methods.single { it.name == "read" }.parameterCount)
        assertEquals(listOf(type("ProtectedStateSnapshot")), methods.single { it.name == "readForCheckpoint" }.parameterTypes.toList())
        assertTrue(methods.all { it.returnType == type("ProjectionImages") })
        assertTrue(type("ReadOnlyCheckpointProjectionAccess").declaredFields.none {
            it.type == type("ProtectedProjectionAccess") || it.type == type("JournalStorage") ||
                it.type == type("ImmutableProtectedObjectWriter")
        })
    }

    @Test fun credentialParentOpenFlagsDoNotDependOnHiddenFrameworkFields() {
        val companion = type("ProtectedStateApplicationFacade").getField("Companion").get(null)
        val method = companion.javaClass.getDeclaredMethod("credentialParentOpenFlags", Int::class.javaPrimitiveType)
        method.isAccessible = true
        // Independent NDK asm/fcntl.h values: ARM64 and x86_64 do not share O_DIRECTORY.
        // Both combinations retain readonly, directory-only, no-follow and atomic close-on-exec.
        assertEquals(0x0008c000, method.invoke(companion, 0x00008000))
        assertEquals(0x000b0000, method.invoke(companion, 0x00020000))
        for (unsupported in listOf(0, -1, 0x00010000, 0x00028000)) {
            val failure = assertThrows(java.lang.reflect.InvocationTargetException::class.java) {
                method.invoke(companion, unsupported)
            }
            assertTrue(failure.cause is IllegalStateException)
        }
    }

    @Test fun frameworkPreparationCannotClassifyPartialMutationAsMigrationRequired() {
        val companion = type("ProtectedStateApplicationFacade").getField("Companion").get(null)
        val classify = companion.javaClass.getDeclaredMethod("frameworkPreparationFailure",
            Boolean::class.javaPrimitiveType, Throwable::class.java).apply { isAccessible = true }
        val failureType = type("ProtectedStateApplicationFacade\$Companion\$OpenFailure")
        val constructor = failureType.getDeclaredConstructor(ProtectedStateApplicationFacade.OpenResult::class.java)
            .apply { isAccessible = true }
        val migration = constructor.newInstance(ProtectedStateApplicationFacade.OpenResult.MigrationRequired) as Throwable
        val ordinary = IllegalStateException("test-only IO uncertainty")
        val result = failureType.getDeclaredMethod("getResult").apply { isAccessible = true }
        for (failure in listOf(migration, ordinary)) {
            assertSame("preflight failures retain their classification", failure, classify.invoke(companion, false, failure))
            val partial = classify.invoke(companion, true, failure)
            assertEquals(ProtectedStateApplicationFacade.OpenResult.Unproven, result.invoke(partial))
        }
    }

    @Test fun projectionRootTrustComesFromBoundIdentityNotCanonicalPathSpelling() {
        val expected = DurableDirectory(7, 1_234, DurableFileIdentity(55, 66))
        assertTrue(projectionRootIdentityMatches(true, true, 55, 66, 1_234, 448, expected))
        assertFalse(projectionRootIdentityMatches(false, true, 55, 66, 1_234, 448, expected))
        assertFalse(projectionRootIdentityMatches(true, false, 55, 66, 1_234, 448, expected))
        assertFalse(projectionRootIdentityMatches(true, true, 56, 66, 1_234, 448, expected))
        assertFalse(projectionRootIdentityMatches(true, true, 55, 67, 1_234, 448, expected))
        assertFalse(projectionRootIdentityMatches(true, true, 55, 66, 1_235, 448, expected))
        assertFalse(projectionRootIdentityMatches(true, true, 55, 66, 1_234, 493, expected))
    }

    @Test fun pathBasedProjectionOwnersUseCanonicalSpellingOnlyAfterBothNamesMatchTheBoundDirectory() {
        val directory = java.nio.file.Files.createTempDirectory("projection-alias-").toFile().canonicalFile
        try {
            val alias = java.io.File(directory, ".").absoluteFile
            assertNotEquals(alias, alias.canonicalFile)
            val expected = DurableDirectory(7, 1_234, DurableFileIdentity(55, 66))
            val matching = ProjectionRootObservation(true, true, 55, 66, 1_234, 448)
            val observed = arrayListOf<java.io.File>()

            val selected = canonicalProjectionRootForBoundIdentity(alias, expected) { candidate ->
                observed += candidate
                matching.copy(isAbsolute = candidate.isAbsolute)
            }

            assertEquals(alias.canonicalFile, selected)
            assertEquals(listOf(alias, alias.canonicalFile), observed)
            assertThrows(IllegalStateException::class.java) {
                canonicalProjectionRootForBoundIdentity(alias, expected) { candidate ->
                    if (candidate == alias.canonicalFile) matching.copy(inode = 67) else matching
                }
            }
        } finally {
            assertTrue(directory.delete())
        }
    }
}
