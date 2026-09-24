// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.os.Build
import java.io.File
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.core.nativejni.Task7InstalledFixtureNative

/** Owned-emulator CLI fixture, independent of the UI process. Never packaged in release. */
object Task14RelayHost {
    @JvmStatic fun main(args: Array<String>) {
        check(Build.FINGERPRINT.contains("generic") || Build.MODEL.contains("sdk")) { "EMULATOR_ONLY" }
        require(args.size == 1 || args.size == 2 && args[1] == "recover")
        val directory = File(args[0]).canonicalFile
        require(directory.name == "task12-installed-proxy-v1" && directory.parentFile.name == "files")
        check(directory.isDirectory)
        NativeBridge()
        val relay = Task7InstalledFixtureNative()
        check(relay.startRelay(directory.path, 0) == 0) { "FIXTURE_RELAY_START_FAILED" }
        try {
            println("TASK14_RELAY_READY")
            System.out.flush()
            // Bounded host lifetime. EOF or an explicit stop line also shuts down the fixture.
            val stop = java.util.concurrent.CountDownLatch(1)
            Thread { System.`in`.read(); stop.countDown() }.apply { isDaemon = true; start() }
            if (args.size == 1) stop.await(10, java.util.concurrent.TimeUnit.MINUTES)
            else {
                // Each fixture accepts one tunnel. Reopen only after its real joined
                // cleanup, so provider-death recovery can establish a fresh session.
                val until = android.os.SystemClock.elapsedRealtime() + 60_000
                var sessions = 1
                while (stop.count > 0 && android.os.SystemClock.elapsedRealtime() < until) {
                    if (relay.snapshot()[11] == 1L) {
                        check(relay.finish() == 0)
                        check(++sessions <= 5) { "FIXTURE_RETRY_BUDGET" }
                        check(relay.startRelay(directory.path, 0) == 0)
                    }
                    stop.await(10, java.util.concurrent.TimeUnit.MILLISECONDS)
                }
            }
        } finally {
            relay.cancel()
            val deadline = android.os.SystemClock.elapsedRealtime() + 5000
            while (relay.snapshot()[11] != 1L && android.os.SystemClock.elapsedRealtime() < deadline)
                Thread.sleep(10)
            check(relay.finish() == 0) { "FIXTURE_RELAY_CLEANUP_UNPROVEN" }
            println("TASK14_RELAY_STOPPED")
        }
    }

}
