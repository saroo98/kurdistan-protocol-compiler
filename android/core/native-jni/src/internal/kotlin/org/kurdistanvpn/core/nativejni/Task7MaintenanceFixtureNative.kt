// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import org.kurdistanvpn.core.nativeapi.ProductionNativeMaintenance

/** Internal fixed component cases over an already adopted concrete parent. */
class Task7MaintenanceFixtureNative {
    init { System.loadLibrary("kurdistan_jni") }
    fun run(session: ProductionNativeMaintenance, caseId: Int, output: LongArray): Int {
        require((caseId in 1..3 || caseId in 301..302) && output.size == 24)
        if (session !is ProductionNativeMaintenanceV1) return 2
        return nativeRun(session, caseId, output)
    }
    private external fun nativeRun(session: ProductionNativeMaintenanceV1, caseId: Int, output: LongArray): Int
}
