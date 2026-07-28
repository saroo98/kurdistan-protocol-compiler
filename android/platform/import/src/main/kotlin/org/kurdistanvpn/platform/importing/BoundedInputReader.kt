// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.platform.importing

import java.io.InputStream

object BoundedInputReader {
    fun read(
        input: InputStream,
        maximum: Int,
        requireNonEmpty: Boolean = true,
    ): ByteArray {
        require(maximum > 0)
        var working = ByteArray(minOf(maximum, 8192))
        var total = 0
        try {
            while (true) {
                if (total == working.size) {
                    if (total == maximum) {
                        require(input.read() < 0) { "input exceeds maximum" }
                        break
                    }
                    val expanded = ByteArray(minOf(maximum, Math.multiplyExact(working.size, 2)))
                    working.copyInto(expanded, endIndex = total)
                    working.fill(0)
                    working = expanded
                }
                val count = input.read(working, total, working.size - total)
                if (count < 0) break
                require(count > 0) { "input stream made no progress" }
                total = Math.addExact(total, count)
            }
            require(!requireNonEmpty || total > 0)
            return working.copyOf(total)
        } finally {
            working.fill(0)
        }
    }
}
