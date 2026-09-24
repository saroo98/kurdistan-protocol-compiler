// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.Parcel
import androidx.test.platform.app.InstrumentationRegistry
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.runtime.android.IRuntimeControl
import org.kurdistanvpn.runtime.android.IRuntimeObserver
import org.kurdistanvpn.runtime.android.KurdVpnService
import org.kurdistanvpn.runtime.android.RuntimeControlBinder
import org.kurdistanvpn.runtime.api.RuntimeStatusWire
import org.kurdistanvpn.runtime.api.VpnRuntimeState

/** Observation only: no profile mutation, authority acquisition, VPN consent or traffic. */
class RuntimeControlDeviceTest {
    @Test fun quiescenceBindingRecoversOnlyFromIdleDeathAndRejectsRetiredCallbacks() {
        val base = InstrumentationRegistry.getInstrumentation().targetContext
        val name = ComponentName(base, KurdVpnService::class.java)
        val connections = mutableListOf<ServiceConnection>()
        val peers = mutableListOf<IBinder>()
        val alive = mutableListOf<Boolean>()
        val deaths = mutableListOf<IBinder.DeathRecipient?>()
        val calls = mutableListOf<Pair<Int, Int>>()
        var unbindings = 0
        val context = object : android.content.ContextWrapper(base) {
            override fun bindService(intent: Intent, peer: ServiceConnection, flags: Int): Boolean {
                assertEquals(org.kurdistanvpn.runtime.android.RuntimeMutationQuiescenceWire.ACTION, intent.action)
                val index = connections.size
                connections.add(peer); alive.add(true); deaths.add(null)
                val endpoint = object : android.os.Binder() {
                    override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
                        data.enforceInterface(org.kurdistanvpn.runtime.android.RuntimeMutationQuiescenceWire.DESCRIPTOR)
                        assertEquals(1, data.readInt()); assertNotNull(data.readStrongBinder())
                        assertEquals(32, checkNotNull(data.readString()).length); assertTrue(data.readLong() > 0)
                        assertEquals(0, data.dataAvail())
                        calls.add(index to code)
                        checkNotNull(reply).writeNoException(); reply.writeInt(1)
                        return true
                    }
                }
                val binder = java.lang.reflect.Proxy.newProxyInstance(IBinder::class.java.classLoader, arrayOf(IBinder::class.java)) { _, method, args ->
                    when (method.name) {
                        "isBinderAlive" -> alive[index]
                        "linkToDeath" -> { deaths[index] = args!![0] as IBinder.DeathRecipient; null }
                        "unlinkToDeath" -> true
                        else -> method.invoke(endpoint, *(args ?: emptyArray()))
                    }
                } as IBinder
                peers.add(binder); peer.onServiceConnected(name, binder)
                return true
            }
            override fun unbindService(peer: ServiceConnection) { unbindings++ }
        }
        val type = Class.forName("org.kurdistanvpn.app.VpnMutationQuiescenceClient")
        val client = type.getDeclaredConstructor(Context::class.java).apply { isAccessible = true }.newInstance(context)
        val acquire = type.getDeclaredMethod("acquire").apply { isAccessible = true }
        fun lease() = acquire.invoke(client) as AutoCloseable?
        try {
            checkNotNull(lease()).close()
            alive[0] = false; checkNotNull(deaths[0]).binderDied()
            connections[0].onServiceDisconnected(name)
            assertEquals("Idle death alone must not start a new VPN process", 1, connections.size)
            val renewed = lease()
            assertNotNull("A requested mutation must obtain a fresh binding and proof after idle death", renewed)
            checkNotNull(renewed).close()
            assertEquals(2, connections.size); assertEquals(1, unbindings)
            connections[0].onServiceConnected(name, peers[0])
            connections[0].onBindingDied(name)
            connections[0].onNullBinding(name)
            checkNotNull(deaths[0]).binderDied()
            checkNotNull(lease()).close()
            assertEquals("Retired callbacks cannot replace or poison the current peer", 2, connections.size)
            assertEquals(listOf(0 to 1, 0 to 2, 1 to 1, 1 to 2, 1 to 1, 1 to 2), calls)
            val held = checkNotNull(lease())
            alive[1] = false; checkNotNull(deaths[1]).binderDied()
            assertNull("Death with an outstanding lease must still fail closed", lease())
            held.close()
            assertNull(lease()); assertEquals(2, connections.size)
        } finally {
            (type.getDeclaredField("ipc").apply { isAccessible = true }.get(client) as java.util.concurrent.ExecutorService).shutdownNow()
        }
    }

    @Test fun servicePromotionFailureRetainsItsCategoryAfterCleanup() {
        org.junit.Assume.assumeTrue(android.os.Build.VERSION.SDK_INT >= 31)
        val base = InstrumentationRegistry.getInstrumentation().targetContext
        assertNull(android.net.VpnService.prepare(base))
        for ((failure, expected) in listOf(
            android.app.ForegroundServiceStartNotAllowedException("fixture") to "FOREGROUND_START_BLOCKED",
            SecurityException("fixture") to "RUNTIME_PERMISSION_DENIED",
            IllegalStateException("fixture") to "RUNTIME_START_FAILED",
        )) {
            // Exercise the real Service callback, replacing only its remote framework boundary.
            val service = KurdVpnService()
            android.content.ContextWrapper::class.java.getDeclaredMethod("attachBaseContext", Context::class.java)
                .apply { isAccessible = true }.invoke(service, base)
            val managerType = Class.forName("android.app.IActivityManager")
            val manager = java.lang.reflect.Proxy.newProxyInstance(managerType.classLoader, arrayOf(managerType)) { _, method, args ->
                when (method.name) {
                    "setServiceForeground" -> if ((args?.get(2) as? Int) != 0) throw failure else null
                    "stopServiceToken" -> true
                    "asBinder" -> android.os.Binder()
                    else -> throw AssertionError("Unexpected framework operation: ${method.name}")
                }
            }
            android.app.Service::class.java.getDeclaredField("mActivityManager").apply { isAccessible = true }.set(service, manager)
            android.app.Service::class.java.getDeclaredField("mClassName").apply { isAccessible = true }.set(service, KurdVpnService::class.java.name)
            android.app.Service::class.java.getDeclaredField("mToken").apply { isAccessible = true }.set(service, android.os.Binder())
            val intent = Intent(RuntimeControlBinder.ACTION_BIND).setComponent(ComponentName(base, KurdVpnService::class.java))
            val control = IRuntimeControl.Stub.asInterface(checkNotNull(service.onBind(intent)))
            try {
                assertEquals(android.app.Service.START_NOT_STICKY, service.onStartCommand(null, 0, 1))
                val until = android.os.SystemClock.elapsedRealtime() + 5000
                var snapshot = RuntimeStatusWire.decode(control.queryStatus(RuntimeStatusWire.VERSION))
                while (snapshot.state == VpnRuntimeState.STOPPING && android.os.SystemClock.elapsedRealtime() < until) {
                    android.os.SystemClock.sleep(10)
                    snapshot = RuntimeStatusWire.decode(control.queryStatus(RuntimeStatusWire.VERSION))
                }
                assertEquals(VpnRuntimeState.BLOCKED, snapshot.state)
                assertEquals(expected, snapshot.failure)
            } finally { service.onDestroy() }
        }
    }
    @Test fun automaticStartReportsPlatformDenialWithoutMisclassifyingInternalFailure() = kotlinx.coroutines.runBlocking {
        org.junit.Assume.assumeTrue(android.os.Build.VERSION.SDK_INT >= 31)
        val base = InstrumentationRegistry.getInstrumentation().targetContext
        assertNull("Owned emulator must have fixture VPN consent", android.net.VpnService.prepare(base))
        for ((failure, expected) in listOf(
            android.app.ForegroundServiceStartNotAllowedException("fixture") to "FOREGROUND_START_BLOCKED",
            SecurityException("fixture") to "RUNTIME_PERMISSION_DENIED",
            IllegalStateException("fixture") to "RUNTIME_START_FAILED",
        )) {
            lateinit var connection: ServiceConnection
            var launches = 0
            val context = object : android.content.ContextWrapper(base) {
                override fun bindService(intent: Intent, peer: ServiceConnection, flags: Int): Boolean {
                    connection = peer; return true
                }
                override fun unbindService(peer: ServiceConnection) = Unit
                override fun startForegroundService(intent: Intent): ComponentName? { launches++; throw failure }
            }
            val binder = RuntimeControlBinder(base.applicationInfo.uid,
                { org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot() }, action = { false })
            val controller = VpnRuntimeController(context)
            try {
                connection.onServiceConnected(ComponentName(base, KurdVpnService::class.java), binder)
                kotlinx.coroutines.withTimeout(5000) {
                    while (!controller.controlReady.value) kotlinx.coroutines.delay(10)
                }
                controller.startOnForegroundLaunch { true }
                assertEquals(1, launches)
                assertEquals(expected, controller.snapshot.value.failure)
            } finally { controller.close(); binder.close() }
        }
    }
    @Test fun disconnectedBindingInvalidatesLiveDisplayUntilAFreshSnapshotArrives() = kotlinx.coroutines.runBlocking {
        val base = InstrumentationRegistry.getInstrumentation().targetContext
        lateinit var connection: ServiceConnection
        var bindings = 0
        var unbindings = 0
        var launches = 0
        val context = object : android.content.ContextWrapper(base) {
            override fun bindService(intent: Intent, peer: ServiceConnection, flags: Int): Boolean {
                assertEquals(Context.BIND_AUTO_CREATE, flags)
                connection = peer; bindings++; return true
            }
            override fun unbindService(peer: ServiceConnection) { unbindings++ }
            override fun stopService(intent: Intent) = true
            override fun startForegroundService(intent: Intent): ComponentName? {
                assertNull(intent.action)
                assertNull(intent.extras)
                launches++
                return intent.component
            }
        }
        val live = org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot(VpnRuntimeState.ACTIVE_KURD_LIVE,
            runtimeRequestId = "1".repeat(32), startedAtElapsedRealtime = 1,
            profileGeneration = 1uL, planDigest = "2".repeat(64), profileFingerprint = "3".repeat(32),
            strategyFingerprint = "4".repeat(32), relayFingerprint = "5".repeat(32), bytesSent = 123)
        val old = RuntimeControlBinder(base.applicationInfo.uid, { live }, action = { false })
        val fresh = RuntimeControlBinder(base.applicationInfo.uid, { org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot() }, action = { false })
        val name = ComponentName(base, KurdVpnService::class.java)
        val controller = VpnRuntimeController(context)
        try {
            connection.onServiceConnected(name, old)
            kotlinx.coroutines.withTimeout(5000) {
                while (!controller.controlReady.value) kotlinx.coroutines.delay(10)
            }
            assertEquals(VpnRuntimeState.ACTIVE_KURD_LIVE, controller.snapshot.value.state)
            connection.onServiceDisconnected(name)
            assertEquals("One fresh binding after unexpected loss", 2, bindings)
            assertEquals(1, unbindings)
            connection.onServiceDisconnected(name)
            assertEquals("Duplicate loss must not cause a retry loop", 2, bindings)
            assertEquals(VpnRuntimeState.BLOCKED, controller.snapshot.value.state)
            assertEquals("RUNTIME_PROCESS_LOST", controller.snapshot.value.failure)
            assertNull(controller.snapshot.value.planDigest)
            assertEquals(0L, controller.snapshot.value.bytesSent)
            connection.onServiceConnected(name, fresh)
            kotlinx.coroutines.withTimeout(5000) {
                while (!controller.controlReady.value) kotlinx.coroutines.delay(10)
            }
            old.publish()
            kotlinx.coroutines.delay(100)
            assertEquals(VpnRuntimeState.RECONNECTING, controller.snapshot.value.state)
            assertEquals("One fresh automatic request, never a manual replay", 1, launches)
            fresh.publish()
            kotlinx.coroutines.delay(100)
            assertEquals("Idle observations must not loop automatic requests", 1, launches)
        } finally { controller.close(); old.close(); fresh.close() }
        connection.onServiceDisconnected(name)
        assertEquals("Closed controller must never rebind", 2, bindings)
        assertEquals("Every binding is released", 2, unbindings)
        val stopped = VpnRuntimeController(context)
        val secondLive = RuntimeControlBinder(base.applicationInfo.uid, { live }, action = { false })
        val secondIdle = RuntimeControlBinder(base.applicationInfo.uid, { org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot() }, action = { false })
        try {
            connection.onServiceConnected(name, secondLive)
            kotlinx.coroutines.withTimeout(5000) { while (!stopped.controlReady.value) kotlinx.coroutines.delay(10) }
            connection.onServiceDisconnected(name)
            stopped.stop()
            connection.onServiceConnected(name, secondIdle)
            kotlinx.coroutines.withTimeout(5000) { while (!stopped.controlReady.value) kotlinx.coroutines.delay(10) }
            kotlinx.coroutines.delay(100)
            assertEquals("Stop must cancel pending process recovery", 1, launches)
            assertEquals(VpnRuntimeState.IDLE, stopped.snapshot.value.state)
        } finally { stopped.close(); secondLive.close(); secondIdle.close() }
        assertEquals(4, unbindings)
    }
    @Test fun credentialPipeRequiresRegisteredSequenceAndCarriesOnlyOneExpiringLease() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val secret = ByteArray(60) { 120 }.also { it[16] = 58 }
        val control = RuntimeControlBinder(context.applicationInfo.uid, { org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot() },
            proxyCredentials = { secret.copyOf() }, action = { false })
        val observer = object : IRuntimeObserver.Stub() { override fun onStatus(status: ByteArray?) = Unit }
        try {
            val version = RuntimeStatusWire.VERSION
            assertNull(control.requestProxyCredentials(version, 1, observer))
            assertTrue(control.registerObserver(version, observer))
            val pipe = checkNotNull(control.requestProxyCredentials(version, 1, observer))
            val bytes = ByteArray(org.kurdistanvpn.runtime.api.ProxyCredentialLeaseWire.SIZE)
            try {
                android.os.ParcelFileDescriptor.AutoCloseInputStream(pipe).use { input ->
                    java.io.DataInputStream(input).readFully(bytes)
                    assertEquals(-1, input.read())
                }
                val decoded = org.kurdistanvpn.runtime.api.ProxyCredentialLeaseWire.decode(bytes, android.os.SystemClock.elapsedRealtime())
                try { assertArrayEquals(secret, decoded) } finally { decoded.fill(0) }
            } finally { bytes.fill(0) }
            assertNull(control.requestProxyCredentials(version, 1, observer))
            control.unregisterObserver(version, observer)
            assertNull(control.requestProxyCredentials(version, 2, observer))
        } finally { secret.fill(0); control.close() }
    }
    @Test fun controlBindingObservesIdleWithoutStartingATunnelAndRejectsDuplicateObserver() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val ready = CountDownLatch(1)
        var binder: IBinder? = null
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) { binder = service; ready.countDown() }
            override fun onNullBinding(name: ComponentName?) { ready.countDown() }
            override fun onServiceDisconnected(name: ComponentName?) = Unit
        }
        val bound = context.bindService(Intent(RuntimeControlBinder.ACTION_BIND)
            .setComponent(ComponentName(context, KurdVpnService::class.java)), connection, Context.BIND_AUTO_CREATE)
        try {
            assertTrue(bound)
            assertTrue("Control binding timed out", ready.await(10, TimeUnit.SECONDS))
            assertNotNull("Runtime control is not exposed", binder)
            val control = IRuntimeControl.Stub.asInterface(binder)
            val observed = CountDownLatch(1)
            val observer = object : IRuntimeObserver.Stub() {
                override fun onStatus(status: ByteArray?) {
                    if (status != null && RuntimeStatusWire.decode(status).state == VpnRuntimeState.IDLE) observed.countDown()
                }
            }
            val version = RuntimeStatusWire.VERSION
            assertTrue(control.registerObserver(version, observer))
            try {
                assertFalse(control.registerObserver(version, observer))
                assertTrue(control.requestAction(version, 1, 8, observer))
                assertFalse(control.requestAction(version, 1, 8, observer))
                assertFalse(control.requestAction(version, 2, 99, observer))
                assertTrue(control.requestAction(version, 2, 8, observer))
                assertThrows(IllegalStateException::class.java) { control.queryStatus(version + 1) }
                val oversized = Parcel.obtain()
                val reply = Parcel.obtain()
                try {
                    oversized.writeByteArray(ByteArray(8193))
                    assertFalse(binder!!.transact(IBinder.FIRST_CALL_TRANSACTION, oversized, reply, 0))
                } finally { oversized.recycle(); reply.recycle() }
                assertEquals(VpnRuntimeState.IDLE, RuntimeStatusWire.decode(control.queryStatus(version)).state)
                assertTrue(observed.await(10, TimeUnit.SECONDS))
            } finally { control.unregisterObserver(version, observer) }
            assertEquals(VpnRuntimeState.IDLE, RuntimeStatusWire.decode(control.queryStatus(version)).state)
            // A replacement app observer gets the existing snapshot without a START action.
            val replacementStatus = CountDownLatch(1)
            val replacement = object : IRuntimeObserver.Stub() {
                override fun onStatus(status: ByteArray?) {
                    if (status != null && RuntimeStatusWire.decode(status).state == VpnRuntimeState.IDLE)
                        replacementStatus.countDown()
                }
            }
            assertTrue(control.registerObserver(version, replacement))
            try {
                assertTrue(replacementStatus.await(10, TimeUnit.SECONDS))
                assertFalse(control.requestAction(version, 3, 8, observer))
                assertTrue(control.requestAction(version, 1, 8, replacement))
                assertEquals(VpnRuntimeState.IDLE, RuntimeStatusWire.decode(control.queryStatus(version)).state)
            } finally { control.unregisterObserver(version, replacement) }
        } finally { if (bound) context.unbindService(connection) }
    }

    @Test fun uidCheckRunsBeforeUnmarshallingAndNeverCallsAnOwner() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val control = RuntimeControlBinder(context.applicationInfo.uid + 1,
            { throw AssertionError("Foreign UID reached snapshot owner") },
            action = { throw AssertionError("Foreign UID reached action owner") })
        val data = Parcel.obtain(); val reply = Parcel.obtain()
        try {
            data.writeInt(-1)
            assertFalse(control.asBinder().transact(IBinder.FIRST_CALL_TRANSACTION, data, reply, 0))
        } finally { data.recycle(); reply.recycle(); control.close() }
    }

    @Test fun lateIdleSnapshotDoesNotEraseLocalConsentFailure() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        VpnRuntimeController(context).use { controller ->
            controller.stageManualStart()
            controller.permissionRejected()
            kotlinx.coroutines.runBlocking { kotlinx.coroutines.delay(1000) }
            assertEquals(VpnRuntimeState.FAILED, controller.snapshot.value.state)
            assertEquals("CONSENT_REJECTED", controller.snapshot.value.failure)
        }
    }
}
