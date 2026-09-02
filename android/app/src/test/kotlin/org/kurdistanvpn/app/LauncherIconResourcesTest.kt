package org.kurdistanvpn.app

import java.awt.image.BufferedImage
import java.io.File
import java.security.MessageDigest
import javax.imageio.ImageIO
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LauncherIconResourcesTest {
    private val repositoryRoot: File by lazy {
        generateSequence(File(System.getProperty("user.dir")).canonicalFile) { it.parentFile }
            .firstOrNull {
                File(it, "android/app/src/main/AndroidManifest.xml").isFile &&
                    File(it, "brand/kurdistan-vpn/v1/compact-transparent.png").isFile
            }
            ?: error("repository root containing Android and canonical brand inputs was not found")
    }

    @Test
    fun manifestChangesOnlyLauncherIconReferences() {
        val manifest = source("AndroidManifest.xml").readText().replace("\r\n", "\n")

        assertTrue(manifest.contains("android:icon=\"@mipmap/ic_kurdistan_vpn\""))
        assertTrue(manifest.contains("android:roundIcon=\"@mipmap/ic_kurdistan_vpn\""))

        val normalized = manifest
            .replace(Regex("android:icon=\"[^\"]+\""), "android:icon=\"@ICON@\"")
            .replace(Regex("android:roundIcon=\"[^\"]+\""), "android:roundIcon=\"@ROUND_ICON@\"")
        assertEquals(
            "9fc330d4e6b6f392b4508290713fbeb26e75d546552664a0f1ead86fe14ed797",
            sha256(normalized.toByteArray(Charsets.UTF_8)),
        )
    }

    @Test
    fun adaptiveResourcesUseTheCanonicalForegroundAndSystemMonochromeLayer() {
        for (version in listOf("mipmap-anydpi-v26", "mipmap-anydpi-v33")) {
            for (name in listOf("ic_kurdistan_vpn.xml", "ic_kurdistan_vpn_round.xml")) {
                val text = resource("$version/$name").readText()
                assertTrue(text.contains("<adaptive-icon"))
                assertTrue(text.contains("android:drawable=\"@color/launcher_icon_background\""))
                assertTrue(text.contains("android:drawable=\"@drawable/ic_kurdistan_vpn_foreground\""))
                if (version.endsWith("v33")) {
                    assertTrue(text.contains("<monochrome"))
                } else {
                    assertFalse(text.contains("<monochrome"))
                }
            }
        }

        val colors = resource("values/launcher_icon_colors.xml").readText()
        assertTrue(colors.contains("name=\"launcher_icon_background\">#F8FAFC</color>"))
        assertFalse(resource("drawable/ic_kurdistan_vpn.xml").exists())
    }

    @Test
    fun generatedForegroundIsPaddedInsideTheAdaptiveIconSafeZone() {
        val image: BufferedImage? = ImageIO.read(
            resource("drawable-nodpi/ic_kurdistan_vpn_foreground.png"),
        )
        assertNotNull(image)
        image ?: return

        assertEquals(432, image.width)
        assertEquals(432, image.height)

        var minX = image.width
        var minY = image.height
        var maxX = -1
        var maxY = -1
        for (y in 0 until image.height) {
            for (x in 0 until image.width) {
                if ((image.getRGB(x, y) ushr 24) != 0) {
                    minX = minOf(minX, x)
                    minY = minOf(minY, y)
                    maxX = maxOf(maxX, x)
                    maxY = maxOf(maxY, y)
                }
            }
        }

        assertTrue("foreground must contain visible pixels", maxX >= minX && maxY >= minY)
        assertTrue("foreground exceeds the adaptive safe-zone left edge", minX >= 84)
        assertTrue("foreground exceeds the adaptive safe-zone top edge", minY >= 84)
        assertTrue("foreground exceeds the adaptive safe-zone right edge", maxX < 348)
        assertTrue("foreground exceeds the adaptive safe-zone bottom edge", maxY < 348)
    }

    private fun source(name: String): File =
        File(repositoryRoot, "android/app/src/main/$name")

    private fun resource(path: String): File =
        File(repositoryRoot, "android/app/src/main/res/$path")

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it) }
}
