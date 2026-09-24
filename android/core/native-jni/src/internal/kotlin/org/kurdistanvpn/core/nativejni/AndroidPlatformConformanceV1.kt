// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer

/** Internal-only typed VM probes. A real service owner supplies any nonzero owner identity. */
object AndroidPlatformConformanceV1 {
    init { System.loadLibrary("kurdistan_bridge"); System.loadLibrary("kurdistan_jni") }
    fun copyLayout(output: LongArray): Int { require(output.size == 12); return nativeCopyLayout(output) }
    fun rejectUnownedCancellation(): Int = nativeRejectUnownedCancellation()
    /** Capture bytes are sensitive. The fixture owns and must wipe all five destinations. */
    fun copyCapture(owner: Long, verify: ByteBuffer, activation: ByteBuffer, recipient: ByteBuffer,
        privateRecipient: ByteBuffer, settings: ByteBuffer, written: IntArray): Int {
        require(owner != 0L && written.size == 5)
        for (span in arrayOf(verify, activation, recipient, privateRecipient, settings))
            require(span.isDirect && !span.isReadOnly && span.position() == 0 && span.limit() == span.capacity())
        return nativeCopyCapture(owner, verify, activation, recipient, privateRecipient, settings, written)
    }
    private external fun nativeCopyLayout(output: LongArray): Int
    private external fun nativeRejectUnownedCancellation(): Int
    private external fun nativeCopyCapture(owner: Long, verify: ByteBuffer, activation: ByteBuffer, recipient: ByteBuffer,
        privateRecipient: ByteBuffer, settings: ByteBuffer, written: IntArray): Int
}
