// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import org.kurdistanvpn.core.nativeapi.NativeProductResult
import org.kurdistanvpn.runtime.android.RuntimeVerifiedUpdate

/** A cancelled dispatcher return cannot abandon owned artifact bytes between producer and caller. */
suspend fun deliverRuntimeUpdate(block: suspend () -> NativeProductResult<RuntimeVerifiedUpdate?>): NativeProductResult<RuntimeVerifiedUpdate?> {
    var owned: RuntimeVerifiedUpdate? = null
    var delivered = false
    try {
        val result = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            block().also { owned = (it as? NativeProductResult.Success)?.value }
        }
        delivered = true
        return result
    } finally { if (!delivered) owned?.close() }
}
