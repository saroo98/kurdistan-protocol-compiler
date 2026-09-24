// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import android.net.VpnService

/** Application supplies this only in its declared VPN process. No UI or storage graph is exposed. */
interface RuntimeDependencyProvider {
    val runtimeProcessGraph: RuntimeProcessGraph
}

/** Retains the existing module-internal admitted factory and its exact service/coordinator. */
class RuntimeProcessGraph {
    internal fun acquireAdmitted(
        service: VpnService,
        admission: RuntimeStartDecision.RequestAuthority,
        onAdmitted: (RuntimeProductionPlatformOwner) -> Unit,
        setup: (RuntimeProductionPlatformOwner) -> Unit,
    ): RuntimeProductionPlatformOwner =
        RuntimeProductionPlatformOwner.acquireAdmitted(service, admission, onAdmitted, setup)
}
