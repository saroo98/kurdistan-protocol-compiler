// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*
import org.kurdistanvpn.runtime.api.*

class ProductConnectionPresentationTest {
    private val profile = ProfileProjection(CatalogId("profile"), SafeAlias("Profile"), 1u, 100, ProjectionStatus.VERIFIED)
    private val binding = RuntimePresentationBinding("profile", 1u, 1, 2, 3)
    private val session = "1".repeat(32)
    private val evidence = RuntimePresentationEvidence(session, binding, session, session, 2, 2)
    private val active = VpnRuntimeSnapshot(state = VpnRuntimeState.ACTIVE_KURD_LIVE,
        runtimeRequestId = session, startedAtElapsedRealtime = 1, profileGeneration = 1u,
        planDigest = "a".repeat(64), profileFingerprint = "b".repeat(64),
        strategyFingerprint = "c".repeat(64), relayFingerprint = "d".repeat(64),
        ipMode = IpMode.IPV4_ONLY, presentation = evidence)

    @Test fun connectedRequiresEveryIndependentWitnessAndFreshBinding() {
        fun state(snapshot: VpnRuntimeSnapshot, current: RuntimePresentationBinding? = binding) =
            productConnectionPresentation(snapshot, profile, current, StorageHealth.AVAILABLE, 10)
        assertTrue(state(active) is ConnectionState.Connected)
        assertTrue(state(active, binding.copy(packageRevision = 4)) is ConnectionState.SafeMode)
        assertTrue(state(active, null) is ConnectionState.SafeMode)
        assertTrue(state(active.copy(presentation = null)) is ConnectionState.SafeMode)
        for (missing in listOf(evidence.copy(nativeSessionId = null), evidence.copy(tunSessionId = null),
            evidence.copy(routeRevision = null), evidence.copy(dnsRevision = null)))
            assertTrue(state(active.copy(presentation = missing)) is ConnectionState.SafeMode)
        assertTrue(state(active.copy(presentation = evidence.copy(tunSessionId = "foreign"))) is ConnectionState.SafeMode)
        assertTrue(state(active.copy(state = VpnRuntimeState.BLOCKED, failure = "RUNTIME_PROCESS_LOST")) is ConnectionState.Recovering)
        assertTrue(state(VpnRuntimeSnapshot(state = VpnRuntimeState.CONNECTING)) is ConnectionState.Connecting)
        assertTrue(productConnectionPresentation(active, profile, binding, StorageHealth.AVAILABLE, 100) is ConnectionState.Failed)
    }
}
