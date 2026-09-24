// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.app.ActivityManager
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.os.IBinder
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kurdistanvpn.runtime.android.KurdVpnService
import org.kurdistanvpn.runtime.android.RuntimeMutationQuiescenceWire
import org.kurdistanvpn.runtime.api.VpnRuntimeContract
import org.kurdistanvpn.runtime.api.VpnRuntimeState

/** Sends only Stop commands with a test-owned same-UID binding, never runtime authority. */
class StoppedRuntimeServiceDeviceTest {
    @Test
    fun repeatedStopRetiresForegroundWhileQuiescenceBindingRemains() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val component = ComponentName(context, KurdVpnService::class.java)
        val connected = CompletableDeferred<org.kurdistanvpn.runtime.android.IRuntimeControl>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                if (name == component && service?.isBinderAlive == true) connected.complete(org.kurdistanvpn.runtime.android.IRuntimeControl.Stub.asInterface(service))
                else connected.completeExceptionally(AssertionError("Test quiescence binding was not established"))
            }
            override fun onServiceDisconnected(name: ComponentName?) = Unit
        }
        // Foreground Activity ownership is explicit, with no presentation or resource assertions.
        ActivityScenario.launch(MainActivity::class.java).use {
            var bound = false
            try {
                bound = context.bindService(Intent(org.kurdistanvpn.runtime.android.RuntimeControlBinder.ACTION_BIND).setComponent(component),
                    connection, Context.BIND_AUTO_CREATE)
                assertTrue("Test-owned quiescence binding must be accepted", bound)
                val control = runBlocking { withTimeout(10_000) { connected.await() } }
                repeat(20) { iteration ->
                    KurdVpnService.stop(context)
                    runBlocking {
                        withTimeout(10_000) {
                            awaitIdle(control)
                        }
                        awaitBoundAndStopped(context, component, iteration)
                    }
                }
            } finally {
                if (bound) context.unbindService(connection)
            }
        }
    }

    private suspend fun awaitIdle(control: org.kurdistanvpn.runtime.android.IRuntimeControl) {
        while (true) {
            val snapshot = org.kurdistanvpn.runtime.api.RuntimeStatusWire.decode(control.queryStatus(org.kurdistanvpn.runtime.api.RuntimeStatusWire.VERSION))
            assertEquals("Stop must not read TUN traffic", 0L, snapshot.packetsRead)
            assertEquals("Stop must not write TUN traffic", 0L, snapshot.packetsWritten)
            assertEquals("Stop must not acquire authority", null, snapshot.planDigest)
            if (snapshot.state == VpnRuntimeState.IDLE) {
                assertEquals(null, snapshot.failure)
                return
            }
            delay(10)
        }
    }

    @Suppress("DEPRECATION") // The API still exposes this application's own service ownership.
    private suspend fun awaitBoundAndStopped(context: Context, component: ComponentName, iteration: Int) {
        val manager = context.getSystemService(ActivityManager::class.java)
        var observed = "not observed"
        try {
            withTimeout(10_000) {
                while (true) {
                    val service = manager.getRunningServices(Int.MAX_VALUE).singleOrNull { it.service == component }
                    observed = service?.let { "started=${it.started}, foreground=${it.foreground}, clients=${it.clientCount}" }
                        ?: "absent despite retained test binding"
                    if (service != null && !service.started && !service.foreground && service.clientCount > 0) return@withTimeout
                    delay(10)
                }
            }
        } catch (failure: Throwable) {
            throw AssertionError("Stop $iteration did not retire foreground ownership: $observed", failure)
        }
    }

}
