// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import java.lang.reflect.Modifier
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
}
