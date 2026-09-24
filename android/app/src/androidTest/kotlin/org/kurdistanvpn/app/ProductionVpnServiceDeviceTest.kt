// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.content.*
import android.os.*
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.net.DatagramSocket
import java.net.DatagramPacket
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.nativejni.Task7InstalledFixtureNative
import org.kurdistanvpn.runtime.android.*
import org.kurdistanvpn.runtime.api.*

/** Owned local relay and exact prepared emulator fixture only. Never run on a user's phone. */
class ProductionVpnServiceDeviceTest {
    @Test fun admittedProductSessionSurvivesObserverReplacementAndStopsCleanly() {
        check(Build.FINGERPRINT.contains("generic") || Build.MODEL.contains("sdk")) { "EMULATOR_ONLY" }
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        Task7InstalledDriverClient().use { it.prepareFreshFixtureOrVerifyExactPreparedState() }
        val relay = Task7InstalledFixtureNative()
        assertEquals(0, relay.startRelay(File(context.filesDir, "task7-installed-v1").absolutePath, 0))
        val ready = CountDownLatch(1)
        var binder: IBinder? = null
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) { binder = service; ready.countDown() }
            override fun onServiceDisconnected(name: ComponentName?) = Unit
        }
        val bound = context.bindService(Intent(RuntimeControlBinder.ACTION_BIND)
            .setComponent(ComponentName(context, KurdVpnService::class.java)), connection, Context.BIND_AUTO_CREATE)
        try {
            assertTrue(bound && ready.await(10, TimeUnit.SECONDS))
            val control = IRuntimeControl.Stub.asInterface(checkNotNull(binder))
            val version = RuntimeStatusWire.VERSION
            val request = KurdVpnService.newRequestId()
            KurdVpnService.start(context, request)
            var snapshot = VpnRuntimeSnapshot()
            val deadline = SystemClock.elapsedRealtime() + 30_000
            do {
                snapshot = RuntimeStatusWire.decode(control.queryStatus(version))
                if (snapshot.state in setOf(VpnRuntimeState.ACTIVE_KURD_LIVE, VpnRuntimeState.BLOCKED, VpnRuntimeState.FAILED)) break
                SystemClock.sleep(25)
            } while (SystemClock.elapsedRealtime() < deadline)
            assertEquals("Product start: ${snapshot.state}/${snapshot.failure}/${snapshot.packetDisposition}", VpnRuntimeState.ACTIVE_KURD_LIVE, snapshot.state)
            assertEquals(request, snapshot.runtimeRequestId)
            assertEquals(32, snapshot.profileFingerprint?.length)
            assertTrue(snapshot.profileGeneration > 0uL)
            killSeparateObserver(context, request)
            assertEquals(VpnRuntimeState.ACTIVE_KURD_LIVE, RuntimeStatusWire.decode(control.queryStatus(version)).state)
            val connectivity = context.getSystemService(ConnectivityManager::class.java)
            var network: android.net.Network? = null
            val networkDeadline = SystemClock.elapsedRealtime() + 5_000
            do {
                @Suppress("DEPRECATION")
                val candidates = connectivity.allNetworks.filter {
                    connectivity.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
                }
                assertTrue(candidates.size <= 1)
                network = candidates.singleOrNull()
                if (network == null) SystemClock.sleep(25)
            } while (network == null && SystemClock.elapsedRealtime() < networkDeadline)
            val vpn = checkNotNull(network)
            val links = checkNotNull(connectivity.getLinkProperties(vpn))
            val address = links.linkAddresses.single { it.address.address.size == 4 }.address
            val destination = links.dnsServers.single { it.address.size == 4 }
            DatagramSocket(null).use { socket ->
                val bindDeadline = SystemClock.elapsedRealtime() + 5_000
                while (true) {
                    try { vpn.bindSocket(socket); break }
                    catch (failure: java.net.SocketException) {
                        if (SystemClock.elapsedRealtime() >= bindDeadline) throw failure
                        SystemClock.sleep(25)
                    }
                }
                socket.bind(InetSocketAddress(address, 0))
                socket.soTimeout = 5_000
                val requestBytes = byteArrayOf(75, 55, 84, 49, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                socket.send(DatagramPacket(requestBytes, 16, destination, 28472))
                val response = DatagramPacket(ByteArray(17), 17)
                socket.receive(response)
                assertEquals(16, response.length)
                assertEquals(destination, response.address)
                assertEquals(28472, response.port)
                assertArrayEquals(byteArrayOf(75, 55, 82, 49, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), response.data.copyOf(16))
            }
            repeat(2) {
                val observed = CountDownLatch(1)
                val observer = object : IRuntimeObserver.Stub() {
                    override fun onStatus(bytes: ByteArray?) {
                        if (bytes != null && RuntimeStatusWire.decode(bytes).runtimeRequestId == request) observed.countDown()
                    }
                }
                assertTrue(control.registerObserver(version, observer))
                try { assertTrue(observed.await(5, TimeUnit.SECONDS)) }
                finally { control.unregisterObserver(version, observer) }
                assertEquals(VpnRuntimeState.ACTIVE_KURD_LIVE, RuntimeStatusWire.decode(control.queryStatus(version)).state)
            }
            snapshot = RuntimeStatusWire.decode(control.queryStatus(version))
            assertTrue(snapshot.packetsRead > 0 && snapshot.packetsWritten > 0)
            val notification = context.getSystemService(android.app.NotificationManager::class.java)
                .activeNotifications.single { it.id == 1001 }.notification
            assertTrue(notification.extras.getBoolean(android.app.Notification.EXTRA_SHOW_CHRONOMETER))
            val recoveryObserver = object : IRuntimeObserver.Stub() {
                override fun onStatus(bytes: ByteArray?) = Unit
            }
            assertTrue(control.registerObserver(version, recoveryObserver))
            try {
                assertTrue(control.requestAction(version, 1, RuntimeAction.RECOVER_INTERNET.wireCode, recoveryObserver))
            } finally { control.unregisterObserver(version, recoveryObserver) }
            val stopDeadline = SystemClock.elapsedRealtime() + 10_000
            do {
                snapshot = RuntimeStatusWire.decode(control.queryStatus(version))
                if (snapshot.state == VpnRuntimeState.IDLE) break
                SystemClock.sleep(25)
            } while (SystemClock.elapsedRealtime() < stopDeadline)
            assertEquals(VpnRuntimeState.IDLE, snapshot.state)
            assertNull(snapshot.runtimeRequestId)
            assertEquals(0uL, snapshot.profileGeneration)
        } finally {
            KurdVpnService.stop(context)
            if (bound) context.unbindService(connection)
            relay.cancel()
            val deadline = SystemClock.elapsedRealtime() + 5_000
            while (relay.snapshot()[11] != 1L && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(10)
            assertEquals(1L, relay.snapshot()[11])
            assertEquals(0, relay.finish())
        }
    }

    private fun killSeparateObserver(context: Context, request: String) {
        val ready = CountDownLatch(1)
        var remote: IBinder? = null
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) { remote = service; ready.countDown() }
            override fun onServiceDisconnected(name: ComponentName?) = Unit
        }
        val bound = context.bindService(Intent().setComponent(ComponentName(context.packageName,
            "org.kurdistanvpn.app.InternalRuntimeObserverService")), connection, Context.BIND_AUTO_CREATE)
        try {
            assertTrue("Internal observer helper must be installed", bound && ready.await(5, TimeUnit.SECONDS))
            val binder = checkNotNull(remote)
            val deadline = SystemClock.elapsedRealtime() + 5_000
            var pid = 0
            do {
                val input = Parcel.obtain(); val output = Parcel.obtain()
                try {
                    assertTrue(binder.transact(1, input, output, 0))
                    val candidate = output.readInt()
                    if (output.readString() == request) pid = candidate
                } finally { input.recycle(); output.recycle() }
                if (pid == 0) SystemClock.sleep(25)
            } while (pid == 0 && SystemClock.elapsedRealtime() < deadline)
            assertTrue(pid > 0 && pid != android.os.Process.myPid())
            val died = CountDownLatch(1)
            binder.linkToDeath({ died.countDown() }, 0)
            android.os.Process.killProcess(pid)
            assertTrue("Observer process death must be real", died.await(5, TimeUnit.SECONDS))
        } finally { if (bound) context.unbindService(connection) }
    }
}
