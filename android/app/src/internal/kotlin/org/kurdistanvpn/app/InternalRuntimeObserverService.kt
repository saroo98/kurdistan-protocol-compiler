// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.app.Service
import android.content.*
import android.os.*
import org.kurdistanvpn.runtime.android.*
import org.kurdistanvpn.runtime.api.*

/** Internal APK only: a real independently killable observer, never a runtime owner. */
class InternalRuntimeObserverService : Service() {
    @Volatile private var request: String? = null
    @Volatile private var control: IRuntimeControl? = null
    private val checkingRecovery = java.util.concurrent.atomic.AtomicBoolean(false)
    private var bound = false
    private val observer = object : IRuntimeObserver.Stub() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (Binder.getCallingUid() != applicationInfo.uid || data.dataSize() > 8192) return false
            return super.onTransact(code, data, reply, flags)
        }
        override fun onStatus(status: ByteArray?) {
            if (status == null) return
            val value = RuntimeStatusWire.decode(status)
            request = value.runtimeRequestId.takeIf { value.state == VpnRuntimeState.ACTIVE_KURD_LIVE }
        }
    }
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val value = IRuntimeControl.Stub.asInterface(service) ?: return
            if (value.registerObserver(RuntimeStatusWire.VERSION, observer)) control = value
        }
        override fun onServiceDisconnected(name: ComponentName?) { control = null; request = null }
    }
    private val status = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != 1 || Binder.getCallingUid() != applicationInfo.uid || data.dataSize() != 0 ||
                reply == null || flags and IBinder.FLAG_ONEWAY != 0) return false
            reply.writeInt(android.os.Process.myPid()); reply.writeString(request)
            return true
        }
    }
    override fun onCreate() {
        super.onCreate()
        bound = bindService(Intent(RuntimeControlBinder.ACTION_BIND)
            .setComponent(ComponentName(this, KurdVpnService::class.java)), connection, BIND_AUTO_CREATE)
    }
    override fun onBind(intent: Intent?): IBinder = status
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val runId = intent?.getStringExtra("run_id")?.takeIf { it.matches(Regex("[0-9a-f]{32}")) }
        val startupOnly = intent?.action == "org.kurdistanvpn.internal.VERIFY_STANDALONE_START"
        if ((!startupOnly && intent?.action != "org.kurdistanvpn.internal.VERIFY_PROVIDER_RECOVERY") ||
            runId == null ||
            !(Build.FINGERPRINT.contains("generic") || Build.MODEL.contains("sdk")) ||
            !java.io.File(filesDir, "task12-installed-proxy-v1").isDirectory ||
            !checkingRecovery.compareAndSet(false, true)) return START_NOT_STICKY
        Thread {
            val result = java.io.File(filesDir, "task14-provider-recovery-$runId.txt")
            try {
                result.writeText("WAITING: connecting initial fixture session\n")
                val deadline = SystemClock.elapsedRealtime() + 60_000
                var lastStage: String? = null
                fun active(previous: String?): Pair<IRuntimeControl, VpnRuntimeSnapshot> {
                    while (SystemClock.elapsedRealtime() < deadline) {
                        val channel = control
                        val state = channel?.let { RuntimeStatusWire.decode(it.queryStatus(RuntimeStatusWire.VERSION)) }
                        val stage = "${state?.state}/${state?.failure}/${state?.packetDisposition}"
                        if (startupOnly && stage != lastStage) {
                            result.appendText("STAGE: $stage\n")
                            lastStage = stage
                        }
                        if (channel != null && state?.state == VpnRuntimeState.ACTIVE_KURD_LIVE &&
                            state.runtimeRequestId != previous) return channel to state
                        SystemClock.sleep(25)
                    }
                    error("RECOVERY_TIMEOUT")
                }
                while (control == null && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(25)
                val before = active(null)
                if (!startupOnly) check(before.second.alwaysOn == true && before.second.lockdown == true)
                fixtureTraffic(before.first, 2)
                result.appendText("READY: initial local traffic verified\n")
                val after = if (startupOnly) before else active(before.second.runtimeRequestId)
                if (!startupOnly) {
                    check(after.second.alwaysOn == true && after.second.lockdown == true)
                    fixtureTraffic(after.first, 3)
                    result.appendText("RECOVERED: fresh request and local traffic verified; lockdown retained\n")
                }
                check(after.first.requestAction(RuntimeStatusWire.VERSION, 4, RuntimeAction.STOP.wireCode, observer))
                while (SystemClock.elapsedRealtime() < deadline &&
                    RuntimeStatusWire.decode(after.first.queryStatus(RuntimeStatusWire.VERSION)).state != VpnRuntimeState.IDLE)
                    SystemClock.sleep(25)
                check(RuntimeStatusWire.decode(after.first.queryStatus(RuntimeStatusWire.VERSION)).state == VpnRuntimeState.IDLE)
                val listening = runCatching { java.net.Socket("127.0.0.1", 10808).close() }.isSuccess
                check(!listening)
                result.appendText("PASS: Stop reached Idle and closed the proxy listener\n")
            } catch (failure: Throwable) {
                result.appendText("FAIL: ${failure.javaClass.simpleName}; line=${failure.stackTrace.firstOrNull()?.lineNumber}\n")
            } finally { checkingRecovery.set(false); stopSelf(startId) }
        }.apply { name = "recovery-fixture-observer"; isDaemon = true; start() }
        return START_NOT_STICKY
    }

    /** Synthetic profile maps this SOCKS destination exclusively to its loopback echo fixture. */
    private fun fixtureTraffic(channel: IRuntimeControl, sequence: Long) {
        val encoded = ByteArray(ProxyCredentialLeaseWire.SIZE)
        val credentials = try {
            ParcelFileDescriptor.AutoCloseInputStream(checkNotNull(channel.requestProxyCredentials(
                RuntimeStatusWire.VERSION, sequence, observer))).use {
                java.io.DataInputStream(it).readFully(encoded)
                check(it.read() == -1)
            }
            ProxyCredentialLeaseWire.decode(encoded, SystemClock.elapsedRealtime())
        } finally { encoded.fill(0) }
        try {
            java.net.Socket("127.0.0.1", 10808).use { socket ->
                socket.soTimeout = 5000
                val authentication = byteArrayOf(5, 1, 2, 1, 16) + credentials.copyOfRange(0, 16) +
                    byteArrayOf(43) + credentials.copyOfRange(17, 60)
                try { socket.getOutputStream().write(authentication) } finally { authentication.fill(0) }
                socket.getOutputStream().write(byteArrayOf(5, 1, 0, 1, 8, 8, 8, 8, 1, -69))
                val input = java.io.DataInputStream(socket.getInputStream())
                val reply = ByteArray(14); input.readFully(reply)
                check(reply.contentEquals(byteArrayOf(5, 2, 1, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0)))
                val expected = ByteArray(16) { it.toByte() }
                socket.getOutputStream().write(expected)
                val actual = ByteArray(16); input.readFully(actual)
                check(expected.contentEquals(actual))
            }
        } finally { credentials.fill(0) }
    }
    override fun onDestroy() {
        try { control?.unregisterObserver(RuntimeStatusWire.VERSION, observer) }
        finally { if (bound) unbindService(connection); super.onDestroy() }
    }
}
