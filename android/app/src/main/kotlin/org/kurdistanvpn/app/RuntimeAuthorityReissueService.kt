// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.app.ActivityManager
import android.app.Service
import android.content.ComponentName
import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import android.os.UserManager
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.Executors
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import org.kurdistanvpn.core.nativeapi.DurableFilePrimitives
import org.kurdistanvpn.runtime.android.*

/** Implemented once by the real Application owner, never by a mutable global test override. */
interface RuntimeAuthorityReissueOwner {
    val runtimeAuthorityReissue: RuntimeAuthorityReissueIpcAdapter
    val runtimeAuthorityPipePrimitives: DurableFilePrimitives
}

/** Manifest must be explicit, unexported, default-process and non-Direct-Boot. Bound only. */
class RuntimeAuthorityReissueService : Service() {
    @Volatile private var owner: RuntimeAuthorityReissueOwner? = null
    private val peers = mutableMapOf<IBinder, IBinder.DeathRecipient>()
    private val worker = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, SynchronousQueue(),
        { job -> Thread(job, "authority-reissue").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
    private val clock = Executors.newSingleThreadScheduledExecutor { job -> Thread(job, "authority-expiry").apply { isDaemon = true } }
    private val binder = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code !in RuntimeAuthorityReissueWire.HELLO..RuntimeAuthorityReissueWire.RELEASE_LEASE)
                return super.onTransact(code, data, reply, flags)
            val uid = getCallingUid().toLong()
            val pid = getCallingPid()
            if (reply == null || flags and IBinder.FLAG_ONEWAY != 0 || uid != applicationInfo.uid.toLong() ||
                pid <= 0 || pid == Process.myPid() || data.dataSize() > RuntimeAuthorityReissueWire.MAX_PARCEL_BYTES) return false
            var cap: ParcelFileDescriptor? = null
            var frame: ParcelFileDescriptor? = null
            var capOwner: RuntimeAuthorityPipeOwner? = null
            var frameOwner: RuntimeAuthorityPipeOwner? = null
            return try {
                data.enforceInterface(RuntimeAuthorityReissueWire.DESCRIPTOR)
                require(data.readInt() == RuntimeAuthorityReissueWire.VERSION)
                val root = checkNotNull(owner)
                val callback = checkNotNull(data.readStrongBinder())
                val adapter = root.runtimeAuthorityReissue
                when (code) {
                    RuntimeAuthorityReissueWire.HELLO -> {
                        val epoch = RuntimeAuthorityReissueWire.id(data)
                        require(data.dataAvail() == 0 && callback.isBinderAlive)
                        var death: IBinder.DeathRecipient? = null
                        synchronized(peers) {
                            if (!peers.containsKey(callback)) {
                                check(peers.size < 256)
                                death = IBinder.DeathRecipient { adapter.peerDied(callback); synchronized(peers) { peers.remove(callback) } }
                                callback.linkToDeath(death, 0); peers[callback] = death
                            }
                        }
                        val accepted = adapter.bind(epoch, uid, pid, callback) { notifyInvalidated(callback, adapter.providerEpoch, epoch) }
                        if (!accepted && death != null) synchronized(peers) { peers.remove(callback); callback.unlinkToDeath(death, 0) }
                        reply.writeNoException(); reply.writeInt(if (accepted) 1 else 0)
                        if (accepted) { reply.writeString(adapter.providerEpoch); reply.writeInt(Process.myPid()); reply.writeInt(Process.myUid()) }
                    }
                    RuntimeAuthorityReissueWire.OFFER -> {
                        require(synchronized(peers) { peers.containsKey(callback) })
                        val start = RuntimeAuthorityReissueWire.readStart(data); require(data.dataAvail() == 0)
                        val offer = if (unlockedAndPrepared()) adapter.offer(start, uid, pid, callback) else null
                        reply.writeNoException(); reply.writeInt(if (offer != null) 1 else 0)
                        offer?.let { RuntimeAuthorityReissueWire.writeOffer(reply, it) }
                    }
                    RuntimeAuthorityReissueWire.RESPONSE -> {
                        require(synchronized(peers) { peers.containsKey(callback) })
                        val requestId = RuntimeAuthorityReissueWire.id(data)
                        val purpose = RuntimeAuthorityReissueWire.purpose(data)
                        val descriptorId = RuntimeAuthorityReissueWire.id(data)
                        val deadline = data.readLong()
                        cap = data.readTypedObject(ParcelFileDescriptor.CREATOR)
                        frame = data.readTypedObject(ParcelFileDescriptor.CREATOR)
                        require(data.dataAvail() == 0 && deadline > SystemClock.elapsedRealtime() &&
                            deadline - SystemClock.elapsedRealtime() <= 60_000 && unlockedAndPrepared() &&
                            adapter.expectedDeadline(requestId, uid, pid, callback) == deadline)
                        val c = checkNotNull(cap).also { cap = null }
                        capOwner = RuntimeAuthorityPipeOwner.take(c, root.runtimeAuthorityPipePrimitives, uid, 0, deadline) { callback.isBinderAlive }
                        val f = checkNotNull(frame).also { frame = null }
                        frameOwner = RuntimeAuthorityPipeOwner.take(f, root.runtimeAuthorityPipePrimitives, uid, 1, deadline) { callback.isBinderAlive }
                        val input = checkNotNull(capOwner); val output = checkNotNull(frameOwner)
                        worker.execute { adapter.respond(requestId, purpose, descriptorId, uid, pid, callback, input, output) }
                        capOwner = null; frameOwner = null
                        reply.writeNoException(); reply.writeInt(1)
                    }
                    RuntimeAuthorityReissueWire.CANCEL -> {
                        val start = RuntimeAuthorityReissueWire.readStart(data)
                        require(data.dataAvail() == 0)
                        val status = adapter.cancelStart(start, uid, pid, callback)
                        reply.writeNoException(); reply.writeInt(status)
                    }
                    else -> {
                        val id = RuntimeAuthorityReissueWire.id(data)
                        val purpose = if (code == RuntimeAuthorityReissueWire.RESPONSE_READY) RuntimeAuthorityReissueWire.purpose(data) else null
                        require(data.dataAvail() == 0)
                        val status = when (code) {
                            RuntimeAuthorityReissueWire.RESPONSE_READY -> adapter.responseStatus(id, checkNotNull(purpose), uid, pid, callback)
                            RuntimeAuthorityReissueWire.COMPLETE -> if (unlockedAndPrepared() && adapter.complete(id, uid, pid, callback)) 1 else 0
                            RuntimeAuthorityReissueWire.RELEASE_LEASE -> if (adapter.releaseLease(id, uid, pid, callback)) 1 else 0
                            else -> 0
                        }
                        reply.writeNoException(); reply.writeInt(status)
                    }
                }
                true
            } catch (failure: Throwable) {
                if (failure is RuntimeAuthorityCleanupUnprovenException) owner?.runtimeAuthorityReissue?.transportCleanupFailed()
                reply.setDataSize(0); reply.writeNoException(); reply.writeInt(0); true
            } finally {
                listOfNotNull(capOwner, frameOwner, cap, frame).forEach {
                    try { it.close() } catch (_: Throwable) { owner?.runtimeAuthorityReissue?.transportCleanupFailed() }
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        if (isExpectedProcess()) owner = application as? RuntimeAuthorityReissueOwner
        clock.scheduleAtFixedRate({
            try { owner?.runtimeAuthorityReissue?.expire() }
            catch (_: Throwable) { owner?.runtimeAuthorityReissue?.transportCleanupFailed() }
        }, 100, 100, TimeUnit.MILLISECONDS)
    }
    override fun onBind(intent: Intent?): IBinder? = try {
        val expected = ComponentName(this, RuntimeAuthorityReissueService::class.java)
        val info = packageManager.getServiceInfo(expected, 0)
        if (owner == null || !unlockedAndPrepared() || intent?.component != expected || intent.action != RuntimeAuthorityReissueWire.ACTION ||
            intent.data != null || intent.clipData != null || intent.selector != null || !intent.categories.isNullOrEmpty() ||
            intent.flags != 0 || intent.extras?.isEmpty == false || info.exported || info.directBootAware ||
            info.processName != applicationInfo.processName || info.applicationInfo.uid != applicationInfo.uid) null else binder
    } catch (_: Throwable) { null }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int { stopSelf(startId); return START_NOT_STICKY }
    override fun onUnbind(intent: Intent?): Boolean { detachPeers(); return false }
    override fun onDestroy() {
        detachPeers(); worker.shutdownNow(); clock.shutdownNow(); owner = null
        super.onDestroy()
    }
    private fun detachPeers() {
        val snapshot = synchronized(peers) { peers.toMap().also { peers.clear() } }
        snapshot.forEach { (binder, death) ->
            owner?.runtimeAuthorityReissue?.connectionClosed(binder)
            try { binder.unlinkToDeath(death, 0) } catch (_: Throwable) { }
        }
    }
    private fun isExpectedProcess(): Boolean = try {
        val processes = getSystemService(ActivityManager::class.java).runningAppProcesses
        processes?.singleOrNull { it.pid == Process.myPid() && it.uid == Process.myUid() }?.processName == applicationInfo.processName
    } catch (_: Throwable) { false }
    private fun unlockedAndPrepared(): Boolean = try {
        getSystemService(UserManager::class.java).isUserUnlocked && VpnService.prepare(this) == null
    } catch (_: Throwable) { false }
    private fun notifyInvalidated(callback: IBinder, providerEpoch: String, consumerEpoch: String) {
        val data = Parcel.obtain(); val reply = Parcel.obtain()
        try {
            data.writeInterfaceToken(RuntimeAuthorityReissueWire.CALLBACK); data.writeInt(RuntimeAuthorityReissueWire.VERSION)
            data.writeString(providerEpoch); data.writeString(consumerEpoch)
            check(callback.transact(RuntimeAuthorityReissueWire.INVALIDATED, data, reply, 0)); reply.readException()
            require(reply.readInt() == 1 && reply.dataAvail() == 0)
        } finally { reply.recycle(); data.recycle() }
    }
}
