// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kurdistanvpn.core.model.DiagnosticComponent
import org.kurdistanvpn.core.model.DiagnosticEvent
import org.kurdistanvpn.core.model.DiagnosticLogLevel
import org.kurdistanvpn.runtime.api.VpnRuntimeState

class Phase9ExportWireTest {
    @Test
    fun backupPreviewAcceptsLiteralLegacyGoldenWithAllFiveKinds() {
        val encoded = hexBytes("4b425631000f00010002000300040005")

        assertEquals(15 to 1, Phase9ExportWire.backupPreview(encoded))
    }

    @Test
    fun backupPreviewAcceptsLiteralV2GoldenWithAllFiveKinds() {
        val encoded = hexBytes("4b425632001f00010002000400080010")

        assertEquals(31 to 1, Phase9ExportWire.backupPreview(encoded))
    }

    @Test
    fun backupPreviewAcceptsZeroAndEachKindAtTheRecordLimit() {
        val cases = listOf(
            "4b425631000000000000000000000000" to (0 to 0),
            "4b425631008000800000000000000000" to (128 to 128),
            "4b425631008000000080000000000000" to (128 to 0),
            "4b425631008000000000008000000000" to (128 to 0),
            "4b425631008000000000000000800000" to (128 to 0),
            "4b425631008000000000000000000080" to (128 to 0),
        )

        for ((hex, expected) in cases) {
            for (version in listOf('1', '2')) {
                val encoded = hexBytes(hex).apply { this[3] = version.code.toByte() }
                assertEquals("version $version: $hex", expected, Phase9ExportWire.backupPreview(encoded))
            }
        }
    }

    @Test
    fun backupPreviewRejectsEveryTruncatedLengthAndTrailingBytes() {
        for (hex in listOf("4b425631000f00010002000300040005", "4b425632001f00010002000400080010")) {
            val encoded = hexBytes(hex)
            for (length in 0 until encoded.size) {
                assertThrows("truncated length $length", IllegalArgumentException::class.java) {
                    Phase9ExportWire.backupPreview(encoded.copyOf(length))
                }
            }
            for (suffix in listOf(byteArrayOf(0), byteArrayOf(1), encoded)) {
                assertThrows("trailing bytes", IllegalArgumentException::class.java) {
                    Phase9ExportWire.backupPreview(encoded + suffix)
                }
            }
        }
    }

    @Test
    fun backupPreviewRejectsUnknownVersionsAndMalformedMagic() {
        val encoded = hexBytes("4b425631000f00010002000300040005")
        for (version in 0..255) {
            if (version == '1'.code || version == '2'.code) continue
            assertThrows("version $version", IllegalArgumentException::class.java) {
                Phase9ExportWire.backupPreview(encoded.copyOf().apply { this[3] = version.toByte() })
            }
        }
        for (index in 0..2) {
            for (value in listOf(0, 0x80, 0xff)) {
                assertThrows("magic byte $index", IllegalArgumentException::class.java) {
                    Phase9ExportWire.backupPreview(encoded.copyOf().apply { this[index] = value.toByte() })
                }
            }
        }
    }

    @Test
    fun backupPreviewRejectsInconsistentTotalOrAnyKindCount() {
        for (hex in listOf("4b425631000f00010002000300040005", "4b425632001f00010002000400080010")) {
            val encoded = hexBytes(hex)
            for (index in listOf(5, 7, 9, 11, 13, 15)) {
                for (delta in listOf(-1, 1)) {
                    val malformed = encoded.copyOf().apply { this[index] = (this[index] + delta).toByte() }
                    assertThrows("count byte $index, delta $delta", IllegalArgumentException::class.java) {
                        Phase9ExportWire.backupPreview(malformed)
                    }
                }
            }
        }
    }

    @Test
    fun backupPreviewRejectsTotalsAboveLimitAndUnsignedCountOverflow() {
        val cases = listOf(
            "4b425631008100810000000000000000", // 129 records, matching native count
            "4b4256310081007f0002000000000000", // 129 spread across valid individual counts
            "4b425631010001000000000000000000", // 256 must not decode as little-endian 1
            "4b425631ffffffff0000000000000000", // unsigned 65535, not a negative count
            "4b4256310000ffff0001000000000000", // sum must not wrap at uint16
        )
        for (hex in cases) {
            for (version in listOf('1', '2')) {
                val encoded = hexBytes(hex).apply { this[3] = version.code.toByte() }
                assertThrows("version $version: $hex", IllegalArgumentException::class.java) {
                    Phase9ExportWire.backupPreview(encoded)
                }
            }
        }
        for (index in listOf(6, 8, 10, 12, 14)) {
            val encoded = hexBytes("4b425631000000000000000000000000").apply {
                this[index] = 0xff.toByte()
                this[index + 1] = 0xff.toByte()
            }
            assertThrows("unsigned kind at byte $index", IllegalArgumentException::class.java) {
                Phase9ExportWire.backupPreview(encoded)
            }
        }
    }

    @Test
    fun runtimeStatusCorrelationRejectsDelayedOrMissingSessionIdentity() {
        val current = "0123456789abcdef0123456789abcdef"
        val stale = "fedcba9876543210fedcba9876543210"
        val query = "11111111111111111111111111111111"
        val otherQuery = "22222222222222222222222222222222"

        assertFalse(selectRuntimeStatus(null, null, stale, null).accept)
        assertFalse(selectRuntimeStatus(null, query, stale, null).accept)
        assertFalse(selectRuntimeStatus(null, query, stale, otherQuery).accept)

        val rebound = selectRuntimeStatus(null, query, current, query)
        assertTrue(rebound.accept)
        assertTrue(rebound.consumeQuery)
        assertEquals(current, rebound.bindRequestId)

        assertTrue(selectRuntimeStatus(current, null, current, null).accept)
        assertFalse(selectRuntimeStatus(current, null, stale, null).accept)
        assertFalse(selectRuntimeStatus(current, null, null, null).accept)
    }

    @Test
    fun terminalIdleReleasesCorrelationBeforeAnOlderStoppingBroadcastCanArrive() {
        val current = "0123456789abcdef0123456789abcdef"
        val stale = "fedcba9876543210fedcba9876543210"

        assertEquals(
            current,
            activeRequestIdAfterRuntimeStatus(
                current,
                current,
                VpnRuntimeState.STOPPING,
            ),
        )
        assertEquals(
            null,
            activeRequestIdAfterRuntimeStatus(
                current,
                current,
                VpnRuntimeState.IDLE,
            ),
        )
        assertEquals(
            current,
            activeRequestIdAfterRuntimeStatus(
                current,
                stale,
                VpnRuntimeState.IDLE,
            ),
        )
    }

    @Test
    fun diagnosticRequestNeverAddsCountsToNonCountCategories() {
        for (profileCount in listOf(0, 1, 8, Int.MAX_VALUE)) {
            val encoded = Phase9ExportWire.diagnosticRequest(profileCount)
            assertEquals(22, encoded.size)
            assertEquals(0, encoded[15].toInt())
            assertEquals(0, encoded[18].toInt())
            assertEquals(0, encoded[21].toInt())
        }
    }

    @Test
    fun diagnosticRequestUsesOnlyAbsentOrAdmittedProfileLifecycleValues() {
        assertEquals(4, Phase9ExportWire.diagnosticRequest(0)[17].toInt())
        assertEquals(5, Phase9ExportWire.diagnosticRequest(1)[17].toInt())
    }

    @Test
    fun diagnosticRequestAggregatesOnlyVocabularySafeFailureCategories() {
        val encoded = Phase9ExportWire.diagnosticRequest(
            1,
            listOf(
                DiagnosticEvent(1, DiagnosticLogLevel.WARNING, DiagnosticComponent.STORAGE, "SETTINGS_PERSIST_FAILED", 1),
                DiagnosticEvent(2, DiagnosticLogLevel.ERROR, DiagnosticComponent.STORAGE, "KEY_INVALIDATED", 2),
                DiagnosticEvent(3, DiagnosticLogLevel.INFO, DiagnosticComponent.RUNTIME, "SESSION_STARTED", 3),
                DiagnosticEvent(4, DiagnosticLogLevel.ERROR, DiagnosticComponent.RUNTIME, "UNMAPPED_FAILURE", 4),
            ),
        )

        assertEquals(25, encoded.size)
        assertEquals(4, encoded[12].toInt())
        assertEquals(6, encoded[22].toInt())
        assertEquals(16, encoded[23].toInt())
        assertEquals(3, encoded[24].toInt())
    }

    private fun hexBytes(hex: String): ByteArray =
        hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
