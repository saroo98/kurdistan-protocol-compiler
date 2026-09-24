// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.AllowedAuthenticator

class SensitiveAuthenticationPolicyTest {
    @Test fun strongOnlyNeverPermitsCredentialOrWeakBiometricsOnOlderAndroid() {
        for (sdk in listOf(26, 28, 29, 30, 36)) {
            val policy = checkNotNull(sensitiveAuthenticationPolicy(sdk, setOf(AllowedAuthenticator.STRONG_BIOMETRIC)))
            assertEquals(15, policy.mask)
            assertFalse(policy.legacyCredential)
        }
        assertNull(sensitiveAuthenticationPolicy(36, emptySet()))
    }

    @Test fun explicitlyPermittedCredentialUsesCompatiblePlatformPath() {
        assertTrue(checkNotNull(sensitiveAuthenticationPolicy(29, setOf(AllowedAuthenticator.DEVICE_CREDENTIAL))).legacyCredential)
        val current = checkNotNull(sensitiveAuthenticationPolicy(36, setOf(AllowedAuthenticator.DEVICE_CREDENTIAL)))
        assertFalse(current.legacyCredential)
        assertEquals(32768, current.mask)
    }
}
