// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import org.kurdistanvpn.core.model.ProductSettings
import org.kurdistanvpn.core.nativeapi.NativeProductResult

object ProductionSettingsEncodingV1 {
    fun encode(settings:ProductSettings, output:ByteBuffer):NativeProductResult<Int> =
        ProductionOpeningCodecV1.encodeSettings(settings,output)
}
