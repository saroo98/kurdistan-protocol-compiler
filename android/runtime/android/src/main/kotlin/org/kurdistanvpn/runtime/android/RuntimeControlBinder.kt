// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.RemoteCallbackList
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import org.kurdistanvpn.runtime.api.RuntimeStatusWire
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot

/** Only safe observation and action metadata. Authority remains in the existing one-use pipe owner. */
class RuntimeControlBinder(
    private val appUid: Int,
    private val snapshot: () -> VpnRuntimeSnapshot,
    private val proxyCredentials: () -> ByteArray? = { null },
    private val settingsTransition: (Int, String?, IBinder) -> String? = { _, _, _ -> null },
    private val observerLost: (IBinder) -> Unit = {},
    private val probe: (String, String, Int, Int, IBinder) -> LongArray = { _, _, _, _, _ ->
        RuntimeProbeWire.encode(org.kurdistanvpn.core.nativeapi.NativeProductResult.Failure(
            org.kurdistanvpn.core.model.ProductFailureCode.PROFILE_INCOMPATIBLE)) },
    private val cancelProbe: (String, IBinder) -> Boolean = { _, _ -> false },
    private val update: (String, String, android.os.ParcelFileDescriptor, IBinder) -> LongArray = { _, _, _, _ ->
        RuntimeUpdateWire.encode(org.kurdistanvpn.core.nativeapi.NativeProductResult.Failure(
            org.kurdistanvpn.core.model.ProductFailureCode.PROFILE_INCOMPATIBLE)) },
    private val action: (Int) -> Boolean,
) : IRuntimeControl.Stub(), AutoCloseable {
    private val admission = RuntimeControlAdmission(appUid)
    private data class Registration(val pid: Int, val token: IBinder)
    private val callbacks = object : RemoteCallbackList<IRuntimeObserver>() {
        override fun onCallbackDied(callback: IRuntimeObserver, cookie: Any?) {
            (cookie as? Registration)?.let { admission.remove(it.pid, it.token); observerLost(it.token) }
        }
    }
    private val deliveries = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(1),
        { job -> Thread(job, "kurd-runtime-status").apply { isDaemon = true } },
        ThreadPoolExecutor.DiscardOldestPolicy())

    override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
        // Check before generated AIDL code allocates or unmarshals client-controlled fields.
        if (!admission.allowed(Binder.getCallingUid(), Binder.getCallingPid(), RuntimeStatusWire.VERSION,
                data.dataSize()) || flags and IBinder.FLAG_ONEWAY != 0) return false
        return super.onTransact(code, data, reply, flags)
    }

    private fun requireCaller(version: Int) {
        check(admission.allowed(Binder.getCallingUid(), Binder.getCallingPid(), version, 0)) {
            "RUNTIME_CONTROL_REJECTED"
        }
    }

    override fun registerObserver(version: Int, observer: IRuntimeObserver?): Boolean {
        requireCaller(version)
        val peer = observer ?: return false
        val token = peer.asBinder()
        val pid = Binder.getCallingPid()
        synchronized(callbacks) {
            if (!token.isBinderAlive || !admission.register(pid, token)) return false
            if (!callbacks.register(peer, Registration(pid, token))) {
                admission.remove(pid, token); return false
            }
        }
        publish()
        return true
    }

    override fun unregisterObserver(version: Int, observer: IRuntimeObserver?) {
        requireCaller(version)
        observer?.let { peer -> synchronized(callbacks) {
            if (admission.remove(Binder.getCallingPid(), peer.asBinder())) {
                callbacks.unregister(peer); observerLost(peer.asBinder())
            }
        } }
    }

    override fun queryStatus(version: Int): ByteArray {
        requireCaller(version)
        return RuntimeStatusWire.encode(snapshot())
    }

    override fun requestProbe(version: Int, sequence: Long, operationId: String?, profileId: String?,
        targetId: Int, timeoutSeconds: Int, observer: IRuntimeObserver?): LongArray {
        requireCaller(version)
        require(operationId != null && operationId.matches(Regex("[0-9a-f-]{36}")))
        require(profileId != null)
        org.kurdistanvpn.core.model.CatalogId(profileId)
        require(targetId in 1..65535 && timeoutSeconds in 1..30 && observer != null)
        check(admission.consume(Binder.getCallingPid(), observer.asBinder(), sequence))
        return probe(operationId, profileId, targetId, timeoutSeconds, observer.asBinder())
    }

    override fun cancelProbe(version: Int, sequence: Long, operationId: String?, observer: IRuntimeObserver?): Boolean {
        requireCaller(version)
        if (operationId == null || !operationId.matches(Regex("[0-9a-f-]{36}")) || observer == null ||
            !admission.consume(Binder.getCallingPid(), observer.asBinder(), sequence)) return false
        return cancelProbe(operationId, observer.asBinder())
    }

    override fun requestUpdate(version: Int, sequence: Long, operationId: String?, profileId: String?,
        output: android.os.ParcelFileDescriptor?, observer: IRuntimeObserver?): LongArray {
        try {
            requireCaller(version)
            require(operationId != null && operationId.matches(Regex("[0-9a-f-]{36}")) && profileId != null)
            org.kurdistanvpn.core.model.CatalogId(profileId)
            require(output != null && observer != null)
            check(admission.consume(Binder.getCallingPid(), observer.asBinder(), sequence))
            return update(operationId, profileId, output, observer.asBinder())
        } finally { output?.close() }
    }

    override fun requestAction(version: Int, sequence: Long, requestedAction: Int, observer: IRuntimeObserver?): Boolean {
        requireCaller(version)
        if (org.kurdistanvpn.runtime.api.RuntimeAction.fromWire(requestedAction) == null || observer == null ||
            !admission.consume(Binder.getCallingPid(), observer.asBinder(), sequence)) return false
        return action(requestedAction)
    }

    override fun requestProxyCredentials(version: Int, sequence: Long, observer: IRuntimeObserver?): android.os.ParcelFileDescriptor? {
        requireCaller(version)
        if (observer == null || !admission.consume(Binder.getCallingPid(), observer.asBinder(), sequence)) return null
        val secret = proxyCredentials() ?: return null
        try {
            val encoded = org.kurdistanvpn.runtime.api.ProxyCredentialLeaseWire.encode(secret, android.os.SystemClock.elapsedRealtime())
            try {
                val pipe = android.os.ParcelFileDescriptor.createReliablePipe()
                try {
                    // Fixed72bytes fit into an empty pipe without a worker or unbounded queue.
                    android.os.ParcelFileDescriptor.AutoCloseOutputStream(pipe[1]).use { it.write(encoded) }
                    return pipe[0]
                } catch (failure: Throwable) {
                    pipe.forEach { try { it.close() } catch (_: Throwable) { } }
                    throw failure
                }
            } finally { encoded.fill(0) }
        } finally { secret.fill(0) }
    }

    override fun settingsTransition(version: Int, sequence: Long, operation: Int, token: String?, observer: IRuntimeObserver?): String? {
        requireCaller(version)
        if (operation !in SETTINGS_PREPARE..SETTINGS_FINISH || observer == null ||
            (if (operation == SETTINGS_PREPARE) token != null else token == null || !token.matches(Regex("[0-9a-f]{32}"))) ||
            !admission.consume(Binder.getCallingPid(), observer.asBinder(), sequence)) return null
        return settingsTransition(operation, token, observer.asBinder())
    }

    fun publish() {
        deliveries.execute {
            val status = try { RuntimeStatusWire.encode(snapshot()) } catch (_: IllegalArgumentException) { return@execute }
            synchronized(callbacks) {
                val count = callbacks.beginBroadcast()
                try {
                    repeat(count) { i ->
                        try { callbacks.getBroadcastItem(i).onStatus(status) }
                        catch (_: android.os.RemoteException) { /* Death removes observation, never the tunnel. */ }
                    }
                } finally { callbacks.finishBroadcast() }
            }
        }
    }

    override fun close() {
        admission.close()
        synchronized(callbacks) { callbacks.kill() }
        deliveries.shutdownNow()
    }

    companion object {
        const val SETTINGS_PREPARE = 1
        const val SETTINGS_RESUME = 2
        const val SETTINGS_STOP = 3
        const val SETTINGS_FINISH = 4
        const val ACTION_BIND = "org.kurdistanvpn.runtime.action.BIND_CONTROL_V1"
    }
}

/** Bounded process registrations. Observation ownership is never tunnel ownership. */
internal class RuntimeControlAdmission(private val appUid: Int) : AutoCloseable {
    private data class Peer(val token: Any, var sequence: Long = 0)
    private val peers = mutableMapOf<Int, Peer>()
    private var closed = false

    @Synchronized fun allowed(uid: Int, pid: Int, version: Int, parcelBytes: Int): Boolean =
        !closed && uid == appUid && pid > 0 && version == RuntimeStatusWire.VERSION && parcelBytes in 0..8192

    @Synchronized fun register(pid: Int, token: Any): Boolean {
        if (closed || pid <= 0 || peers.size >= 4 || peers.containsKey(pid) ||
            peers.values.any { it.token == token }) return false
        peers[pid] = Peer(token)
        return true
    }

    @Synchronized fun consume(pid: Int, token: Any, sequence: Long): Boolean {
        if (closed) return false
        val peer = peers[pid] ?: return false
        if (peer.token != token || sequence <= peer.sequence) return false
        peer.sequence = sequence
        return true
    }

    @Synchronized fun remove(pid: Int, token: Any): Boolean {
        if (peers[pid]?.token != token) return false
        peers.remove(pid)
        return true
    }

    @Synchronized override fun close() { closed = true; peers.clear() }
}
