// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer

/** Internal-only fixed fixture controls. No production authority can be supplied. */
class Task7InstalledFixtureNative {
    init { System.loadLibrary("kurdistan_jni") }
    fun issueForPublicEnrollment(directory: String, request: ByteArray): ByteArray {
        require(request.size in 1..65536)
        val output = ByteBuffer.allocateDirect(1_052_763)
        val length = IntArray(1)
        try {
            check(nativeIssue(directory, request, output, length) == 0) { "TASK7_ISSUANCE_UNAVAILABLE" }
            check(length[0] in 1..output.capacity())
            return ByteArray(length[0]).also { output.get(it) }
        } finally { for (i in 0 until output.capacity()) output.put(i, 0); length.fill(0) }
    }
    fun startRelay(directory: String, level: Int, fixtureMode: Int = 0): Int {
        if (fixtureMode !in 0..2 || level !in setOf(0, 16, 32, 64) || (fixtureMode != 0 && level != 0)) return 1
        return nativeStart(directory, level, fixtureMode)
    }
    fun snapshot(): LongArray = LongArray(16).also { check(nativeSnapshot(it) == 0) }
    fun cancel() = nativeCancel()
    fun finish(): Int = nativeFinish()
    private external fun nativeIssue(directory: String, request: ByteArray, output: ByteBuffer, length: IntArray): Int
    private external fun nativeStart(directory: String, level: Int, fixtureMode: Int): Int
    private external fun nativeSnapshot(output: LongArray): Int
    private external fun nativeCancel(): Int
    private external fun nativeFinish(): Int
}
