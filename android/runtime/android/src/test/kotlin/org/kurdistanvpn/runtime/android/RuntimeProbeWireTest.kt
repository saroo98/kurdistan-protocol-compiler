// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.runtime.android

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*

class RuntimeProbeWireTest {
    @Test fun resultPreservesMissingLatencyAndActualPathWithoutInventingSuccess() {
        val result = NativeProbeResult(NativeProbePath.DISCONNECTED_TCP_CONNECT, NativeProbeMethod.TCP_CONNECT,
            1, 0, 1, 0, null, null, 1000, NativeProbeStability.NOT_ENOUGH_SAMPLES, NativeProbeCompletion.COMPLETE)
        assertEquals(NativeProductResult.Success(result), RuntimeProbeWire.decode(RuntimeProbeWire.encode(NativeProductResult.Success(result))))
        val failure = NativeProductResult.Failure(ProductFailureCode.PROFILE_REVOKED)
        assertEquals(failure, RuntimeProbeWire.decode(RuntimeProbeWire.encode(failure)))
        assertThrows(IllegalArgumentException::class.java) { RuntimeProbeWire.decode(LongArray(1000)) }
        val malformed = RuntimeProbeWire.encode(NativeProductResult.Success(result))
        malformed[4] = Long.MAX_VALUE
        assertThrows(IllegalArgumentException::class.java) { RuntimeProbeWire.decode(malformed) }
    }
}
