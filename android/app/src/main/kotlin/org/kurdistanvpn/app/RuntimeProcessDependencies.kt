// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.kurdistanvpn.runtime.android.RuntimeDependencyProvider
import org.kurdistanvpn.runtime.android.RuntimeProcessGraph

internal class RuntimeProcessDependencies : RuntimeDependencyProvider {
    override val runtimeProcessGraph = RuntimeProcessGraph()
}
