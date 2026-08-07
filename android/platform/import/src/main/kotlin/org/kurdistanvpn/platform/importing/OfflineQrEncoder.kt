// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.platform.importing

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.util.Base64
import org.kurdistanvpn.core.model.QrDisplayMatrix

object OfflineQrEncoder {
    private const val PREFIX = "KURD-RECIPIENT/1/"
    private const val MAX_REQUEST_BYTES = 512

    fun recipientRequest(request: ByteArray): QrDisplayMatrix {
        require(request.size in 1..MAX_REQUEST_BYTES)
        val payload = PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(request)
        val matrix = QRCodeWriter().encode(
            payload,
            BarcodeFormat.QR_CODE,
            0,
            0,
            mapOf(
                EncodeHintType.CHARACTER_SET to "UTF-8",
                EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
                EncodeHintType.MARGIN to 2,
            ),
        )
        return QrDisplayMatrix(
            width = matrix.width,
            modules = BooleanArray(matrix.width * matrix.height) { index ->
                matrix[index % matrix.width, index / matrix.width]
            },
        )
    }
}
