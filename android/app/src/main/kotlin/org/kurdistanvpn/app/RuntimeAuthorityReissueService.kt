// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.app.ActivityManager
import android.app.Service
import android.content.ComponentName
import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.DeadObjectException
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import android.os.UserManager
import java.util.concurrent.ArrayBlockingQueue
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

// One sequential successor may arrive after RESPONSE_READY but before its worker returns.
internal fun newAuthorityResponseWorker() = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue<Runnable>(1),
    { job -> Thread(job, "authority-reissue").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())

/** Manifest must be explicit, unexported, default-process and non-Direct-Boot. Bound only. */
class RuntimeAuthorityReissueService : Service() {
    @Volatile private var owner: RuntimeAuthorityReissueOwner? = null
    private val peers = mutableMapOf<IBinder, IBinder.DeathRecipient>()
    private val worker = newAuthorityResponseWorker()
    private val clock = Executors.newSingleThreadScheduledExecutor { job -> Thread(job, "authority-expiry").apply { isDaemon = true } }
    private val binder = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            val production = RuntimeProductionReissueWireV1.acceptsOpcode(code)
            if (!production && code !in RuntimeAuthorityReissueWire.HELLO..RuntimeAuthorityReissueWire.RELEASE_LEASE)
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
                data.enforceInterface(if (production) RuntimeProductionReissueWireV1.DESCRIPTOR else RuntimeAuthorityReissueWire.DESCRIPTOR)
                val version = if (production) 3 else 2
                require(data.readInt() == version)
                val root = checkNotNull(owner)
                val callback = checkNotNull(data.readStrongBinder())
                val adapter = root.runtimeAuthorityReissue
                if (code != RuntimeAuthorityReissueWire.HELLO && code != RuntimeProductionReissueWireV1.HELLO)
                    require(adapter.acceptsProtocol(uid, pid, callback, version))
                when (code) {
                    RuntimeAuthorityReissueWire.HELLO, RuntimeProductionReissueWireV1.HELLO -> {
                        val epoch = RuntimeAuthorityReissueWire.id(data)
                        if (production) require(data.readInt() == RuntimeProductionReissueWireV1.CAPTURE_FORMAT_KCT1)
                        require(data.dataAvail() == 0 && callback.isBinderAlive)
                        var death: IBinder.DeathRecipient? = null
                        synchronized(peers) {
                            if (!peers.containsKey(callback)) {
                                check(peers.size < 256)
                                death = IBinder.DeathRecipient {
                                    // Death and onUnbind can arrive together. Only the callback
                                    // that removes this peer owns its terminal cleanup.
                                    val claimed = synchronized(peers) { peers.remove(callback) != null }
                                    if (claimed) adapter.peerDied(callback)
                                }
                                callback.linkToDeath(death, 0); peers[callback] = death
                            }
                        }
                        val notify = { notifyInvalidated(callback, adapter.providerEpoch, epoch, production) }
                        val accepted = if (production) adapter.bindProduction(epoch, uid, pid, callback, notify)
                            else adapter.bind(epoch, uid, pid, callback, notify)
                        if (!accepted && death != null) synchronized(peers) { peers.remove(callback); callback.unlinkToDeath(death, 0) }
                        reply.writeNoException(); reply.writeInt(if (accepted) 1 else 0)
                        if (accepted) {
                            reply.writeString(adapter.providerEpoch); reply.writeInt(Process.myPid()); reply.writeInt(Process.myUid())
                            if (production) { reply.writeInt(3); reply.writeInt(1) }
                        }
                    }
                    RuntimeAuthorityReissueWire.OFFER, RuntimeProductionReissueWireV1.OFFER -> {
                        require(synchronized(peers) { peers.containsKey(callback) })
                        val start = RuntimeAuthorityReissueWire.readStart(data); require(data.dataAvail() == 0)
                        val offer = if (unlockedAndPrepared()) adapter.offer(start, uid, pid, callback) else null
                        reply.writeNoException(); reply.writeInt(if (offer != null) 1 else 0)
                        offer?.let {
                            RuntimeAuthorityReissueWire.writeOffer(reply, it)
                            if (production) {
                                reply.writeInt(1)
                                RuntimeProductionReissueWireV1.writePresentation(reply, it.presentation)
                            }
                        }
                    }
                    RuntimeAuthorityReissueWire.RESPONSE, RuntimeProductionReissueWireV1.RESPONSE -> {
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
                    RuntimeAuthorityReissueWire.CANCEL, RuntimeProductionReissueWireV1.CANCEL, RuntimeProductionReissueWireV1.CANCEL_RETIRED -> {
                        val start = RuntimeAuthorityReissueWire.readStart(data)
                        require(data.dataAvail() == 0)
                        val status = adapter.cancelStart(start, uid, pid, callback, code == RuntimeProductionReissueWireV1.CANCEL_RETIRED)
                        reply.writeNoException(); reply.writeInt(status)
                    }
                    RuntimeProductionReissueWireV1.REGISTERED_CURRENT, RuntimeProductionReissueWireV1.PREPUBLICATION_CURRENT -> {
                        val offer = RuntimeProductionAuthorityOfferV1(RuntimeAuthorityReissueWire.readOffer(data))
                        require(data.readInt() == 1)
                        val deadline = data.readLong()
                        require(data.dataAvail() == 0 && RuntimeProductionReissueWireV1.validObservationDeadline(SystemClock.elapsedRealtime(), deadline))
                        val current = unlockedAndPrepared() && if (code == RuntimeProductionReissueWireV1.PREPUBLICATION_CURRENT)
                            adapter.prepublicationCurrent(offer, deadline, uid, pid, callback)
                            else adapter.registeredCurrent(offer, deadline, uid, pid, callback)
                        reply.writeNoException(); reply.writeInt(if (current) 1 else 0)
                    }
                    else -> {
                        val id = RuntimeAuthorityReissueWire.id(data)
                        val purpose = if (code == RuntimeAuthorityReissueWire.RESPONSE_READY || code == RuntimeProductionReissueWireV1.RESPONSE_READY)
                            RuntimeAuthorityReissueWire.purpose(data) else null
                        require(data.dataAvail() == 0)
                        var publicationDeadline: Long? = null
                        val status = when (code) {
                            RuntimeAuthorityReissueWire.RESPONSE_READY, RuntimeProductionReissueWireV1.RESPONSE_READY -> adapter.responseStatus(id, checkNotNull(purpose), uid, pid, callback)
                            RuntimeAuthorityReissueWire.COMPLETE -> if (unlockedAndPrepared() && adapter.complete(id, uid, pid, callback)) 1 else 0
                            RuntimeProductionReissueWireV1.COMPLETE -> {
                                if (unlockedAndPrepared()) publicationDeadline = adapter.completeProduction(id, uid, pid, callback)
                                if (publicationDeadline != null) 1 else 0
                            }
                            RuntimeAuthorityReissueWire.RELEASE_LEASE -> if (adapter.releaseLease(id, uid, pid, callback)) 1 else 0
                            RuntimeProductionReissueWireV1.RELEASE_LEASE -> adapter.releaseProductionLease(id, uid, pid, callback)
                            else -> 0
                        }
                        reply.writeNoException()
                        if (code == RuntimeAuthorityReissueWire.COMPLETE || code == RuntimeProductionReissueWireV1.COMPLETE) {
                            RuntimeProductionReissueWireV1.writeCompletionReply(code == RuntimeProductionReissueWireV1.COMPLETE,
                                status, publicationDeadline ?: 0L, reply::writeInt, reply::writeLong)
                        } else reply.writeInt(status)
                    }
                }
                true
            } catch (failure: Throwable) {
                if (failure is RuntimeAuthorityCleanupUnprovenException) owner?.runtimeAuthorityReissue?.transportCleanupFailed()
                reply.setDataSize(0); reply.writeNoException(); reply.writeInt(0)
                if (code == RuntimeProductionReissueWireV1.COMPLETE) reply.writeLong(0)
                true
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
        // Detached authority rejects queued work; let it run to close its adopted pipes.
        detachPeers(); worker.shutdown(); clock.shutdownNow(); owner = null
        super.onDestroy()
    }
    private fun detachPeers() {
        val snapshot = synchronized(peers) { peers.toMap().also { peers.clear() } }
        snapshot.forEach { (binder, death) ->
            owner?.runtimeAuthorityReissue?.let { adapter ->
                if (binder.isBinderAlive) adapter.connectionClosed(binder) else adapter.peerDied(binder)
            }
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
    private fun notifyInvalidated(callback: IBinder, providerEpoch: String, consumerEpoch: String, production: Boolean) {
        // A confirmed dead peer cannot retain runtime resources. A live peer still
        // owes the cleanup acknowledgement, including after a transaction error.
        if (!callback.isBinderAlive) return
        val data = Parcel.obtain(); val reply = Parcel.obtain()
        try {
            data.writeInterfaceToken(if (production) RuntimeProductionReissueWireV1.CALLBACK else RuntimeAuthorityReissueWire.CALLBACK)
            data.writeInt(if (production) 3 else 2)
            data.writeString(providerEpoch); data.writeString(consumerEpoch)
            check(callback.transact(RuntimeAuthorityReissueWire.INVALIDATED, data, reply, 0)); reply.readException()
            val status = reply.readInt()
            require(reply.dataAvail() == 0)
            if (production && status == 2) throw RuntimeAuthorityPeerCleanupPendingException()
            require(status == 1)
        } catch (failure: DeadObjectException) {
            if (callback.isBinderAlive) throw failure
        } finally { reply.recycle(); data.recycle() }
    }
}
