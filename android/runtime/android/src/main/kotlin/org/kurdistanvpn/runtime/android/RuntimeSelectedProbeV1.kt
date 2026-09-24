// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.runtime.android

import org.kurdistanvpn.core.model.ProbePreferences
import org.kurdistanvpn.core.model.ProbeMethod
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.NativeProbeResult
import org.kurdistanvpn.core.nativeapi.NativeProductResult
import org.kurdistanvpn.core.nativeapi.NativeProbeRequest
import org.kurdistanvpn.core.nativeapi.NativeProbeMethod

/** Process-local selected-probe capability supplied only by its existing service owner. */
interface RuntimeSelectedProbeV1 {
    fun runSelected(preferences: ProbePreferences): NativeProductResult<NativeProbeResult>
}

/** Syntax and bounded request only. This does not confer catalogue membership or runtime authority. */
fun selectedProbeRequestV1(preferences: ProbePreferences): NativeProductResult<NativeProbeRequest> {
    val unavailable = NativeProductResult.Failure(ProductFailureCode.PROFILE_INCOMPATIBLE)
    if (preferences.method != ProbeMethod.TCP_CONNECT) return unavailable
    val name = preferences.signedTargetId?.value ?: return unavailable
    if (!name.startsWith("probe-")) return unavailable
    val decimal = name.substring(6)
    if (decimal.isEmpty() || decimal.length > 5 || decimal[0] !in '1'..'9' ||
        decimal.any { it !in '0'..'9' }) return unavailable
    val target = decimal.toIntOrNull()?.takeIf { it in 1..65535 } ?: return unavailable
    if (preferences.timeoutSeconds !in 1..30) return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
    val timeout = Math.multiplyExact(preferences.timeoutSeconds, 1000)
    return NativeProductResult.Success(NativeProbeRequest(target, NativeProbeMethod.TCP_CONNECT, timeout, timeout, 1))
}
