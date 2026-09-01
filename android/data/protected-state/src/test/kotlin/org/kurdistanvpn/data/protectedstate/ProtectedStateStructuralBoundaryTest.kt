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
    }

    @Test fun readProjectionHasNoMutationMethodAndNoWritableRootCapability() {
        val methods = type("ProtectedProjectionReadAccess").declaredMethods.filterNot { it.isSynthetic }
        assertEquals(listOf("read"), methods.map { it.name })
        assertEquals(0, methods.single().parameterCount)
        assertEquals(type("ProjectionImages"), methods.single().returnType)
        assertTrue(type("ReadOnlyCheckpointProjectionAccess").declaredFields.none {
            it.type == type("ProtectedProjectionAccess") || it.type == type("JournalStorage") ||
                it.type == type("ImmutableProtectedObjectWriter")
        })
    }

    @Test fun credentialParentOpenFlagsDoNotDependOnHiddenFrameworkFields() {
        val companion = type("ProtectedStateApplicationFacade").getField("Companion").get(null)
        val method = companion.javaClass.declaredMethods.single { it.name == "credentialParentOpenFlags" }
        assertEquals("credential-parent flags must not require a reflected framework constant", 0, method.parameterCount)
        method.isAccessible = true
        val flags = method.invoke(companion) as Int
        assertEquals("O_DIRECTORY", 0x00010000, flags and 0x00010000)
        assertEquals("O_CLOEXEC", 0x00080000, flags and 0x00080000)
        assertEquals("no write access", 0, flags and 0x00000003)
        assertEquals("no creation", 0, flags and 0x00000040)
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
