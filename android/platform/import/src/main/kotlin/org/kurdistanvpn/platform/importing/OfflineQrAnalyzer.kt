// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.platform.importing

import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.BarcodeFormat

class OfflineQrAnalyzer(
    private val onDecoded: (String) -> Unit,
) : ImageAnalysis.Analyzer {
    private val reader = MultiFormatReader().apply {
        setHints(
            mapOf(
                DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
                DecodeHintType.TRY_HARDER to true,
            ),
        )
    }

    override fun analyze(image: ImageProxy) {
        var bytes: ByteArray? = null
        try {
            val plane = image.planes.firstOrNull() ?: return
            val sourceBuffer = plane.buffer
            val start = sourceBuffer.position()
            val frame = ByteArray(Math.multiplyExact(image.width, image.height))
            bytes = frame
            for (row in 0 until image.height) {
                for (column in 0 until image.width) {
                    frame[row * image.width + column] = sourceBuffer.get(
                        start + row * plane.rowStride + column * plane.pixelStride,
                    )
                }
            }
            val source = PlanarYUVLuminanceSource(
                frame,
                image.width,
                image.height,
                0,
                0,
                image.width,
                image.height,
                false,
            )
            val decoded = runCatching {
                reader.decodeWithState(BinaryBitmap(HybridBinarizer(source))).text
            }.getOrNull()
            if (!decoded.isNullOrBlank()) onDecoded(decoded)
        } finally {
            bytes?.fill(0)
            reader.reset()
            image.close()
        }
    }
}
