// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.io.Closeable
import java.io.IOException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import org.kurdistanvpn.core.nativeapi.DurableCode
import org.kurdistanvpn.core.nativeapi.DurableFilePrimitives
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.LockSupport
import org.kurdistanvpn.runtime.api.*

/** Lifecycle metadata only. No profile identifier, credential, runtime wire, or MAC key. */
data class RuntimeReissueStart(val consumerEpoch: String, val requestId: String, val generation: Long,
    val trigger: RuntimeAuthorityTrigger, val retryAttempt: Int, val deadlineElapsedMillis: Long) {
    init {
        require(RuntimeAuthorityLimits.validId(consumerEpoch) && RuntimeAuthorityLimits.validId(requestId))
        require(generation > 0 && retryAttempt in 0..RuntimeAuthorityLimits.MAX_RETRIES && deadlineElapsedMillis > 0)
        require((trigger == RuntimeAuthorityTrigger.NETWORK_RETRY) == (retryAttempt > 0))
    }
    fun isLiveAt(now: Long) = now >= 0 && now < deadlineElapsedMillis &&
        deadlineElapsedMillis - now <= RuntimeAuthorityLimits.MAX_LIFETIME_MILLIS
}

/** The provider admits these logical role IDs once; each response owns fresh physical pipes. */
data class RuntimeAuthorityOffer(val start: RuntimeReissueStart, val providerEpoch: String, val revision: Long,
    val signedRetryBudget: Int, val payloadLength: Int, val capabilityChannelId: String, val frameChannelId: String) {
    init {
        require(RuntimeAuthorityLimits.validId(providerEpoch) && providerEpoch != start.consumerEpoch)
        require(RuntimeAuthorityLimits.validRevision(revision) && signedRetryBudget in 0..RuntimeAuthorityLimits.MAX_RETRIES)
        require(start.retryAttempt <= signedRetryBudget && payloadLength in 1..RuntimeAuthorityLimits.MAX_PAYLOAD_BYTES)
        require(RuntimeAuthorityLimits.validId(capabilityChannelId) && RuntimeAuthorityLimits.validId(frameChannelId) &&
            capabilityChannelId != frameChannelId)
    }
    fun request(purpose: RuntimeAuthorityPurpose, descriptor: RuntimeDescriptorBinding) = RuntimeAuthorityRequest(
        start.consumerEpoch, providerEpoch, start.requestId, start.generation, purpose, start.trigger, revision,
        start.deadlineElapsedMillis, capabilityChannelId, frameChannelId, descriptor, signedRetryBudget, start.retryAttempt)
}

/** Observed by a pipe owner while its descriptor cannot be closed or transferred. */
data class RuntimePipeIdentity(val device: Long, val inode: Long, val ownerUid: Long, val mode: Long, val accessMode: Int) {
    fun requirePipe(uid: Long, access: Int) {
        require(device >= 0 && inode > 0 && ownerUid == uid && uid in 0..0xffff_fffeL)
        require(mode == 0x1180L && accessMode == access && access in 0..1)
    }
    fun descriptor(id: String, length: Int) = RuntimeDescriptorBinding(id, device, inode, ownerUid, mode, length.toLong(), 0)
}
interface RuntimeReissueReadPipe : Closeable {
    val identity: RuntimePipeIdentity
    fun read(target: ByteArray, offset: Int, count: Int): Int
}
interface RuntimeReissueWritePipe : Closeable {
    val identity: RuntimePipeIdentity
    fun write(source: ByteArray, offset: Int, count: Int): Int
    /** Production reliable pipes report categorical failure to their peer, never raw exceptions. */
    fun abort() { close() }
}
class RuntimeAuthorityCleanupUnprovenException : IOException("AUTHORITY_CLEANUP_UNPROVEN")

internal object RuntimePipeAcquisition {
    fun <T : RuntimeReissueWritePipe> validateOwned(owner: T, validation: () -> Unit): T {
        try { validation(); return owner }
        catch (failure: Throwable) {
            try { owner.abort() } catch (_: Throwable) { throw RuntimeAuthorityCleanupUnprovenException() }
            throw failure
        }
    }
}
internal object RuntimeReissueInvalidation {
    fun apply(guard: RuntimeActivationGuard, callback: () -> Unit) {
        guard.markCancellation()
        try { callback() } finally {
            if (guard.cancel() != RuntimeCleanupState.CLEAN) throw RuntimeAuthorityCleanupUnprovenException()
        }
    }
}

/** Exact framing and progress checks shared by the production provider and consumer. */
object RuntimeReissuePipeIo {
    fun readExact(pipe: RuntimeReissueReadPipe, length: Int, live: () -> Boolean): ByteArray {
        require(length in 1..RuntimeAuthorityLimits.MAX_FRAME_BYTES)
        val identity = pipe.identity
        identity.requirePipe(identity.ownerUid, 0)
        val owned = ByteArray(length)
        val tail = ByteArray(1)
        var transferred = false
        try {
            var offset = 0
            while (offset < length) {
                check(live())
                val count = pipe.read(owned, offset, length - offset)
                require(count in 1..(length - offset))
                offset += count
            }
            check(live()); require(pipe.read(tail, 0, 1) == -1)
            check(live()); require(pipe.identity == identity)
            transferred = true
            return owned
        } finally { tail.fill(0); if (!transferred) owned.fill(0) }
    }
    fun writeExact(pipe: RuntimeReissueWritePipe, source: ByteArray, live: () -> Boolean) {
        val owned = source.copyOf()
        try {
            require(owned.size in 1..RuntimeAuthorityLimits.MAX_FRAME_BYTES)
            val identity = pipe.identity
            identity.requirePipe(identity.ownerUid, 1)
            var offset = 0
            while (offset < owned.size) {
                check(live())
                val count = pipe.write(owned, offset, owned.size - offset)
                require(count in 1..(owned.size - offset)); offset += count
            }
            check(live()); require(pipe.identity == identity)
        } finally { owned.fill(0) }
    }
}

/** Only the verifier owns its transferred key. Neither a key getter nor a rearm API exists. */
class RuntimeReissueClientExchange(val request: RuntimeAuthorityRequest, transferredKey: ByteArray) : Closeable {
    private val verifier = RuntimeAuthorityFrameCodec.verifier(transferredKey, request)
    fun consume(frame: ByteArray, observed: RuntimeDescriptorBinding, nowElapsedMillis: Long) =
        verifier.verifyAndConsume(frame, observed, nowElapsedMillis)
    override fun close() { verifier.close() }
}

/** Versioned bounded scalar protocol. File descriptors are written separately, never byte arrays. */
object RuntimeAuthorityReissueWire {
    const val ACTION = "org.kurdistanvpn.runtime.action.BIND_REISSUE"
    const val DESCRIPTOR = "org.kurdistanvpn.runtime.android.AuthorityReissueV2"
    const val CALLBACK = "org.kurdistanvpn.runtime.android.AuthorityReissueLifetimeV2"
    const val VERSION = 2
    const val HELLO = 1
    const val OFFER = 2
    const val RESPONSE = 3
    const val RESPONSE_READY = 4
    const val COMPLETE = 5
    const val CANCEL = 6
    const val RELEASE_LEASE = 7
    const val INVALIDATED = 1
    const val MAX_PARCEL_BYTES = 4096
    fun id(parcel: Parcel): String = checkNotNull(parcel.readString()).also { require(RuntimeAuthorityLimits.validId(it)) }
    fun writeStart(parcel: Parcel, start: RuntimeReissueStart) {
        parcel.writeString(start.consumerEpoch); parcel.writeString(start.requestId); parcel.writeLong(start.generation)
        parcel.writeInt(start.trigger.wire); parcel.writeInt(start.retryAttempt); parcel.writeLong(start.deadlineElapsedMillis)
    }
    fun readStart(parcel: Parcel): RuntimeReissueStart {
        val epoch = id(parcel); val request = id(parcel); val generation = parcel.readLong(); val trigger = parcel.readInt()
        return RuntimeReissueStart(epoch, request, generation, RuntimeAuthorityTrigger.entries.single { it.wire == trigger },
            parcel.readInt(), parcel.readLong())
    }
    fun writeOffer(parcel: Parcel, offer: RuntimeAuthorityOffer) {
        writeStart(parcel, offer.start); parcel.writeString(offer.providerEpoch); parcel.writeLong(offer.revision)
        parcel.writeInt(offer.signedRetryBudget); parcel.writeInt(offer.payloadLength)
        parcel.writeString(offer.capabilityChannelId); parcel.writeString(offer.frameChannelId)
    }
    fun readOffer(parcel: Parcel): RuntimeAuthorityOffer {
        val start = readStart(parcel)
        return RuntimeAuthorityOffer(start, id(parcel), parcel.readLong(), parcel.readInt(), parcel.readInt(), id(parcel), id(parcel))
    }
    fun purpose(parcel: Parcel): RuntimeAuthorityPurpose {
        val value = parcel.readInt()
        return RuntimeAuthorityPurpose.entries.single { it.wire == value }
    }
}

/** Same-UID, private VpnService bind protocol for a broker mutation quiescence lease.
 * It carries only a bounded lease id and a lifetime Binder, never runtime authority material. */
object RuntimeMutationQuiescenceWire {
    const val ACTION = "org.kurdistanvpn.runtime.action.BIND_MUTATION_QUIESCENCE"
    const val DESCRIPTOR = "org.kurdistanvpn.runtime.android.MutationQuiescenceV1"
    const val VERSION = 1
    const val ACQUIRE = 1
    const val RELEASE = 2
    const val MAX_PARCEL_BYTES = 512
    /** Bounds only the synchronous admission exchange, never the subsequently held mutation lease. */
    const val MAX_ADMISSION_MILLIS = 2_000L
    fun acceptsAdmissionDeadline(now: Long, deadline: Long): Boolean =
        now >= 0 && deadline > now && deadline - now <= MAX_ADMISSION_MILLIS
    fun leaseId(parcel: Parcel): String = checkNotNull(parcel.readString()).also { require(RuntimeAuthorityLimits.validId(it)) }
}

/** Takes ownership before the first fallible validation. API26 fcntl uses the audited native
 * primitive; all policy, deadlines, byte bounds and ownership remain here. No FD is detached. */
class RuntimeAuthorityPipeOwner private constructor(private var descriptor: ParcelFileDescriptor?,
    private val primitives: DurableFilePrimitives, private val uid: Long, private val access: Int,
    private val deadline: Long, private val live: () -> Boolean) : RuntimeReissueReadPipe, RuntimeReissueWritePipe {
    private val lock = Any()
    private var initial: RuntimePipeIdentity? = null
    private var closeUnproven = false
    override val identity: RuntimePipeIdentity get() = synchronized(lock) { observe() }
    private fun observe(): RuntimePipeIdentity {
        val fd = checkNotNull(descriptor)
        check(!closeUnproven && fd.canDetectErrors())
        val result = primitives.prepareBorrowedPipe(fd.fd.toLong(), uid, access)
        check(result.code == DurableCode.OK)
        val observation = checkNotNull(result.observation)
        val value = RuntimePipeIdentity(observation.identity.device, observation.identity.inode,
            observation.uid, observation.mode.toLong(), observation.access)
        value.requirePipe(uid, access); check(observation.nonblocking)
        initial?.let { require(it == value) }
        return value.also { initial = it }
    }
    fun <T> withDescriptor(block: (ParcelFileDescriptor) -> T): T = synchronized(lock) {
        observe(); block(checkNotNull(descriptor))
    }
    override fun read(target: ByteArray, offset: Int, count: Int): Int = io(target, offset, count, false)
    override fun write(source: ByteArray, offset: Int, count: Int): Int = io(source, offset, count, true)
    private fun io(bytes: ByteArray, offset: Int, count: Int, writing: Boolean): Int {
        require(offset >= 0 && count > 0 && offset <= bytes.size - count && (if (writing) 1 else 0) == access)
        var interrupted = 0
        while (true) {
            check(live() && SystemClock.elapsedRealtime() < deadline)
            val result: Int? = synchronized(lock) {
                observe()
                val pfd = checkNotNull(descriptor)
                try {
                    val remaining = deadline - SystemClock.elapsedRealtime()
                    check(remaining > 0)
                    val poll = StructPollfd().apply { fd = pfd.fileDescriptor; events = (if (writing) OsConstants.POLLOUT else OsConstants.POLLIN).toShort() }
                    if (Os.poll(arrayOf(poll), minOf(remaining, 100).toInt()) == 0) null
                    else {
                        require(poll.revents.toInt() and OsConstants.POLLNVAL == 0)
                        val amount = if (writing) Os.write(pfd.fileDescriptor, bytes, offset, count)
                            else Os.read(pfd.fileDescriptor, bytes, offset, count)
                        if (!writing && amount == 0) { pfd.checkError(); -1 } else amount
                    }
                } catch (failure: ErrnoException) {
                    when (failure.errno) {
                        OsConstants.EINTR -> { check(++interrupted <= 32); null }
                        OsConstants.EAGAIN -> null
                        else -> throw failure
                    }
                }
            }
            if (result != null) return result
        }
    }
    override fun close() = release(false)
    override fun abort() = release(true)
    private fun release(error: Boolean) = synchronized(lock) {
        check(!closeUnproven)
        val owned = descriptor ?: return@synchronized
        descriptor = null // Never retry close, including after EINTR or uncertain native completion.
        try { if (error) owned.closeWithError("AUTHORITY_HANDOFF_REJECTED") else owned.close() }
        catch (failure: Throwable) { closeUnproven = true; throw failure }
    }
    companion object {
        fun take(descriptor: ParcelFileDescriptor, primitives: DurableFilePrimitives, uid: Long,
            access: Int, deadline: Long, live: () -> Boolean): RuntimeAuthorityPipeOwner {
            val owner = RuntimeAuthorityPipeOwner(descriptor, primitives, uid, access, deadline, live)
            return RuntimePipeAcquisition.validateOwned(owner) {
                require(deadline > SystemClock.elapsedRealtime()); owner.identity
            }
        }
    }
}

/** VPN-process consumer. Binder transports scalar lifecycle metadata and FD capabilities only.
 * The coordinator remains the sole start/TUN owner. No store, provider, or network is opened. */
class RuntimeAuthorityReissueClient(private val context: Context, private val component: ComponentName,
    private val consumerEpoch: String, private val primitives: DurableFilePrimitives,
    private val ownership: RuntimeActivationGuard, private val onInvalidated: () -> Unit) : Closeable {
    private val lock = Any()
    private val worker = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(1),
        { job -> Thread(job, "authority-client").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
    private val timer = Executors.newSingleThreadScheduledExecutor { job -> Thread(job, "authority-client-expiry").apply { isDaemon = true } }
    private var closed = false
    private var binding = false
    private var contextBound = false
    private var remote: IBinder? = null
    private var providerEpoch: String? = null
    private var providerPid: Int? = null
    private var start: RuntimeReissueStart? = null
    private var cancelOutstanding: RuntimeReissueStart? = null
    private var offer: RuntimeAuthorityOffer? = null
    private var nextPurpose = RuntimeAuthorityPurpose.FULL_AUTHORITY
    private var busy = false
    private var inFlight = 0
    private var active = false
    private var providerInvalidating = false
    private var cleanupUnproven = false
    private val owned = mutableListOf<Closeable>()
    private var boundCallback: ((Boolean) -> Unit)? = null
    private var responseCallback: ((RuntimeFrameVerification) -> Unit)? = null
    private var deadlineTask: ScheduledFuture<*>? = null
    private val remoteDeath = IBinder.DeathRecipient { connectionFailed() }
    private val lifetime = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != RuntimeAuthorityReissueWire.INVALIDATED) return super.onTransact(code, data, reply, flags)
            if (reply == null || flags and IBinder.FLAG_ONEWAY != 0 || getCallingUid() != context.applicationInfo.uid ||
                data.dataSize() > RuntimeAuthorityReissueWire.MAX_PARCEL_BYTES) return false
            return try {
                data.enforceInterface(RuntimeAuthorityReissueWire.CALLBACK)
                require(data.readInt() == RuntimeAuthorityReissueWire.VERSION)
                val provider = RuntimeAuthorityReissueWire.id(data); val consumer = RuntimeAuthorityReissueWire.id(data)
                require(data.dataAvail() == 0 && consumer == consumerEpoch)
                synchronized(lock) { require(provider == providerEpoch && getCallingPid() == providerPid) }
                // Mark cancellation synchronously. Guard teardown may acknowledge provider cleanup.
                // Provider callbacks hold no IPC/policy monitor; cleanup cannot acquire the journal
                // writer. The durable mutation lock remains held until its transaction completes.
                synchronized(lock) { providerInvalidating = true }
                try {
                    abortCurrent(notify = true, sendCancel = false)
                    check(ownership.cleanupState() == RuntimeCleanupState.CLEAN)
                    synchronized(lock) { check(!cleanupUnproven) }
                } finally { synchronized(lock) { providerInvalidating = false } }
                reply.writeNoException(); reply.writeInt(1); true
            } catch (_: Throwable) { reply.setDataSize(0); reply.writeNoException(); reply.writeInt(0); true }
        }
    }
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            if (name != component || service == null) { connectionFailed(); return }
            try { worker.execute { handshake(service) } } catch (_: Throwable) { connectionFailed() }
        }
        override fun onServiceDisconnected(name: ComponentName?) { connectionFailed() }
        override fun onBindingDied(name: ComponentName?) { connectionFailed() }
        override fun onNullBinding(name: ComponentName?) { connectionFailed() }
    }
    init { require(RuntimeAuthorityLimits.validId(consumerEpoch) && component.packageName == context.packageName) }

    fun bind(onBound: (Boolean) -> Unit): Boolean {
        synchronized(lock) {
            if (closed || binding || remote != null) return false
            binding = true; boundCallback = onBound
        }
        return try {
            val info = context.packageManager.getServiceInfo(component, 0)
            require(info.name == component.className && info.applicationInfo.uid == context.applicationInfo.uid &&
                !info.exported && !info.directBootAware && info.processName == context.applicationInfo.processName)
            val intent = Intent(RuntimeAuthorityReissueWire.ACTION).setComponent(component)
            val accepted = context.bindService(intent, connection, Context.BIND_AUTO_CREATE)
            if (!accepted) connectionFailed()
            else {
                val late = synchronized(lock) {
                    if (closed) true else {
                        contextBound = true
                        if (remote == null) deadlineTask = timer.schedule({ connectionFailed() }, RuntimeAuthorityTimeoutPolicy.BIND_MILLIS, TimeUnit.MILLISECONDS)
                        false
                    }
                }
                if (late) context.unbindService(connection)
            }
            accepted
        } catch (_: Throwable) { connectionFailed(); false }
    }

    /** Called once for each coordinator-issued generation. Failure never reconstructs an old arm. */
    fun request(value: RuntimeReissueStart, onResult: (RuntimeFrameVerification) -> Unit): Boolean {
        synchronized(lock) {
            if (closed || cleanupUnproven || remote == null || start != null || cancelOutstanding != null || busy || inFlight != 0 || value.consumerEpoch != consumerEpoch ||
                !value.isLiveAt(SystemClock.elapsedRealtime())) return false
            start = value; busy = true; active = false; responseCallback = onResult; nextPurpose = RuntimeAuthorityPurpose.FULL_AUTHORITY
            deadlineTask?.cancel(false)
            deadlineTask = timer.schedule({ abortCurrent(true, true) },
                value.deadlineElapsedMillis - SystemClock.elapsedRealtime(), TimeUnit.MILLISECONDS)
        }
        return submit(value) {
            val received = rpc(RuntimeAuthorityReissueWire.OFFER, { RuntimeAuthorityReissueWire.writeStart(it, value) }) { reply ->
                check(reply.readInt() == 1); RuntimeAuthorityReissueWire.readOffer(reply)
            }
            synchronized(lock) {
                check(live(value)); require(received.start == value && received.providerEpoch == providerEpoch)
                offer = received
            }
            exchange(value, received, RuntimeAuthorityPurpose.FULL_AUTHORITY)
        }
    }

    fun checkLease(purpose: RuntimeAuthorityPurpose, onResult: (RuntimeFrameVerification) -> Unit): Boolean {
        val current: RuntimeReissueStart
        val admitted: RuntimeAuthorityOffer
        synchronized(lock) {
            current = start ?: return false; admitted = offer ?: return false
            if (!live(current) || busy || purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY || purpose != nextPurpose) return false
            busy = true; responseCallback = onResult
        }
        return submit(current) { exchange(current, admitted, purpose) }
    }

    /** Required provider acknowledgement precedes local ACTIVE. The provider retains the final
     * revision lease until RELEASE_LEASE, death, or its bounded expiry. */
    fun prepareActivationCommit(onComplete: (Boolean) -> Unit): Boolean {
        val current = synchronized(lock) {
            val value = start ?: return false
            if (!live(value) || busy || active || nextPurpose != RuntimeAuthorityPurpose.FULL_AUTHORITY || offer == null) return false
            busy = true; value
        }
        return try {
            worker.execute {
                val accepted = try { simple(RuntimeAuthorityReissueWire.COMPLETE, current.requestId) } catch (_: Throwable) { false }
                val committed = synchronized(lock) {
                    if (accepted && live(current)) { active = true; busy = false; deadlineTask?.cancel(false); deadlineTask = null; true }
                    else false
                }
                if (!committed) abortCurrent(true, true)
                try { onComplete(committed) } catch (_: Throwable) { abortCurrent(true, true) }
            }
            true
        } catch (_: Throwable) { abortCurrent(true, true); false }
    }

    /** Post-commit cleanup only; this call cannot supply authority or authorize activation. */
    fun releaseActivationLease(onReleased: (Boolean) -> Unit): Boolean {
        val current = synchronized(lock) {
            val value = start ?: return false
            if (!active || !live(value) || busy) return false
            busy = true; value
        }
        return try {
            worker.execute {
                val released = try { simple(RuntimeAuthorityReissueWire.RELEASE_LEASE, current.requestId) }
                    catch (_: Throwable) { false }
                synchronized(lock) { busy = false }
                if (!released) abortCurrent(true, true)
                try { onReleased(released) } catch (_: Throwable) { abortCurrent(true, true) }
            }
            true
        } catch (_: Throwable) { abortCurrent(true, true); false }
    }
    fun observedProviderEpoch(): String? = synchronized(lock) { providerEpoch.takeIf { !closed && remote?.isBinderAlive == true } }
    fun cancel() { abortCurrent(false, true) }

    private fun handshake(service: IBinder) {
        val acquired = ownership.acquire { try {
            service.linkToDeath(remoteDeath, 0)
            val data = Parcel.obtain(); val reply = Parcel.obtain()
            val epoch: String; val pid: Int
            try {
                header(data); data.writeString(consumerEpoch)
                check(service.transact(RuntimeAuthorityReissueWire.HELLO, data, reply, 0)); reply.readException()
                check(reply.dataSize() <= RuntimeAuthorityReissueWire.MAX_PARCEL_BYTES && reply.readInt() == 1)
                epoch = RuntimeAuthorityReissueWire.id(reply); pid = reply.readInt(); val uid = reply.readInt()
                require(epoch != consumerEpoch && pid > 0 && pid != android.os.Process.myPid() && uid == context.applicationInfo.uid && reply.dataAvail() == 0)
            } finally { reply.recycle(); data.recycle() }
            val callback = synchronized(lock) {
                check(!closed && binding && remote == null && service.isBinderAlive)
                remote = service; providerEpoch = epoch; providerPid = pid
                deadlineTask?.cancel(false); deadlineTask = null
                boundCallback.also { boundCallback = null }
            }
            callback?.invoke(true)
        } catch (_: Throwable) {
            try { service.unlinkToDeath(remoteDeath, 0) } catch (_: Throwable) { }
            connectionFailed()
        } }
        if (!acquired) connectionFailed()
    }

    private fun submit(current: RuntimeReissueStart, operation: () -> RuntimeVerifiedAuthority): Boolean {
        synchronized(lock) { inFlight++ }
        return try {
            worker.execute {
                var authority: RuntimeVerifiedAuthority? = null
                var callback: ((RuntimeFrameVerification) -> Unit)? = null
                try {
                    val acquired = ownership.acquire {
                        authority = operation()
                        check(closeExchangeOwners())
                        callback = synchronized(lock) {
                            check(live(current)); busy = false
                            responseCallback.also { responseCallback = null }
                        }
                        check(callback != null)
                    }
                    if (!acquired) abortCurrent(true, true)
                    else {
                        // Deliver outside acquisition ownership. A synchronous callback may
                        // proceed to final publication, which requires zero in-flight acquisitions.
                        val delivered = checkNotNull(authority)
                        check(ownership.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, delivered) === delivered)
                        authority = null
                        checkNotNull(callback)(RuntimeFrameVerification.Verified(delivered))
                    }
                } catch (_: Throwable) { abortCurrent(true, true) }
                finally { authority?.close(); synchronized(lock) { inFlight-- } }
            }
            true
        } catch (_: Throwable) {
            synchronized(lock) { inFlight-- }
            abortCurrent(false, true); false
        }
    }

    private fun exchange(current: RuntimeReissueStart, admitted: RuntimeAuthorityOffer,
        purpose: RuntimeAuthorityPurpose): RuntimeVerifiedAuthority {
        val capability = newPipe(current)
        val frames = newPipe(current)
        val descriptorId = UUID.randomUUID().toString().replace("-", "")
        val length = RuntimeAuthorityFrameCodec.encodedLength(if (purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY) admitted.payloadLength else 0)
        val expected = admitted.request(purpose, frames.first.identity.descriptor(descriptorId, length))
        val key = ByteArray(32)
        var bytes: ByteArray? = null
        var verified: RuntimeVerifiedAuthority? = null
        val recipient: RuntimeReissueClientExchange
        try {
            SecureRandom().nextBytes(key)
            recipient = RuntimeReissueClientExchange(expected, key.copyOf())
            adopt(current, recipient)
            RuntimeReissuePipeIo.writeExact(capability.second, key) { synchronized(lock) { live(current) } }
            capability.second.close()
            val accepted = rpc(RuntimeAuthorityReissueWire.RESPONSE, { parcel ->
                parcel.writeString(current.requestId); parcel.writeInt(purpose.wire); parcel.writeString(descriptorId)
                parcel.writeLong(current.deadlineElapsedMillis)
                capability.first.withDescriptor { parcel.writeTypedObject(it, 0) }
                frames.second.withDescriptor { parcel.writeTypedObject(it, 0) }
            }) { it.readInt() == 1 }
            check(accepted)
            capability.first.close(); frames.second.close()
            key.fill(0)
            bytes = RuntimeReissuePipeIo.readExact(frames.first, length) { synchronized(lock) { live(current) } }
            check(awaitReady(current, purpose))
            val result = recipient.consume(bytes, frames.first.identity.descriptor(descriptorId, length), SystemClock.elapsedRealtime())
            check(result is RuntimeFrameVerification.Verified)
            verified = result.authority
            synchronized(lock) {
                check(live(current)); nextPurpose = when (purpose) {
                    RuntimeAuthorityPurpose.FULL_AUTHORITY -> RuntimeAuthorityPurpose.PRE_TUN
                    RuntimeAuthorityPurpose.PRE_TUN -> RuntimeAuthorityPurpose.PRE_ACTIVE
                    RuntimeAuthorityPurpose.PRE_ACTIVE -> RuntimeAuthorityPurpose.FULL_AUTHORITY
                }
            }
            return verified.also { verified = null }
        } finally { key.fill(0); bytes?.fill(0); verified?.close() }
    }

    private fun awaitReady(current: RuntimeReissueStart, purpose: RuntimeAuthorityPurpose): Boolean {
        repeat(100) {
            check(synchronized(lock) { live(current) })
            val status = rpc(RuntimeAuthorityReissueWire.RESPONSE_READY, {
                it.writeString(current.requestId); it.writeInt(purpose.wire)
            }) { it.readInt() }
            if (status == 1) return true
            if (status != 2) return false
            LockSupport.parkNanos(1_000_000)
        }
        return false
    }
    private fun newPipe(current: RuntimeReissueStart): Pair<RuntimeAuthorityPipeOwner, RuntimeAuthorityPipeOwner> {
        val raw = ParcelFileDescriptor.createReliablePipe()
        var read: ParcelFileDescriptor? = raw[0]; var write: ParcelFileDescriptor? = raw[1]
        try {
            val r = checkNotNull(read).also { read = null }
            val input = RuntimeAuthorityPipeOwner.take(r, primitives, context.applicationInfo.uid.toLong(), 0,
                RuntimeAuthorityTimeoutPolicy.pipeDeadline(current.deadlineElapsedMillis, SystemClock.elapsedRealtime())) { synchronized(lock) { live(current) } }
            adopt(current, input)
            val w = checkNotNull(write).also { write = null }
            val output = RuntimeAuthorityPipeOwner.take(w, primitives, context.applicationInfo.uid.toLong(), 1,
                RuntimeAuthorityTimeoutPolicy.pipeDeadline(current.deadlineElapsedMillis, SystemClock.elapsedRealtime())) { synchronized(lock) { live(current) } }
            adopt(current, output)
            return input to output
        } catch (failure: RuntimeAuthorityCleanupUnprovenException) {
            synchronized(lock) { cleanupUnproven = true }
            throw failure
        } finally {
            listOfNotNull(read, write).forEach { try { it.close() } catch (_: Throwable) { synchronized(lock) { cleanupUnproven = true } } }
        }
    }
    private fun adopt(current: RuntimeReissueStart, resource: Closeable) {
        synchronized(lock) { if (live(current)) { owned += resource; return } }
        try { resource.close() } catch (_: Throwable) { synchronized(lock) { cleanupUnproven = true } }
        error("cancelled acquisition")
    }
    private fun closeExchangeOwners(): Boolean {
        val resources = synchronized(lock) { owned.asReversed().toList().also { owned.clear() } }
        var clean = true
        resources.forEach { try { it.close() } catch (_: Throwable) { clean = false } }
        synchronized(lock) { cleanupUnproven = cleanupUnproven || !clean; return !cleanupUnproven }
    }
    private fun live(value: RuntimeReissueStart): Boolean = !closed && !cleanupUnproven && start == value &&
        remote?.isBinderAlive == true && (active || value.isLiveAt(SystemClock.elapsedRealtime()))
    private fun header(data: Parcel) {
        data.writeInterfaceToken(RuntimeAuthorityReissueWire.DESCRIPTOR); data.writeInt(RuntimeAuthorityReissueWire.VERSION); data.writeStrongBinder(lifetime)
    }
    private fun <T> rpc(code: Int, write: (Parcel) -> Unit, read: (Parcel) -> T): T {
        val binder = synchronized(lock) { check(!closed); checkNotNull(remote) }
        val data = Parcel.obtain(); val reply = Parcel.obtain()
        return try {
            header(data); write(data); require(data.dataSize() <= RuntimeAuthorityReissueWire.MAX_PARCEL_BYTES)
            check(binder.transact(code, data, reply, 0)); reply.readException()
            require(reply.dataSize() <= RuntimeAuthorityReissueWire.MAX_PARCEL_BYTES)
            read(reply).also { require(reply.dataAvail() == 0) }
        } finally { reply.recycle(); data.recycle() }
    }
    private fun simple(code: Int, requestId: String) = rpc(code, { it.writeString(requestId) }) { it.readInt() == 1 }
    private fun cancelRemotely(value: RuntimeReissueStart): Boolean {
        repeat(100) {
            val status = rpc(RuntimeAuthorityReissueWire.CANCEL, { RuntimeAuthorityReissueWire.writeStart(it, value) }) { it.readInt() }
            if (status == 1) {
                synchronized(lock) { if (cancelOutstanding == value) cancelOutstanding = null }
                return true
            }
            if (status != 2) return false
            LockSupport.parkNanos(1_000_000)
        }
        return false
    }
    private fun abortCurrent(notify: Boolean, sendCancel: Boolean) {
        if (notify) ownership.markCancellation()
        val old: RuntimeReissueStart?
        val callback: ((RuntimeFrameVerification) -> Unit)?
        synchronized(lock) {
            old = start; start = null; offer = null; active = false
            if (old != null) cancelOutstanding = old
            deadlineTask?.cancel(false); deadlineTask = null
            callback = responseCallback; responseCallback = null
        }
        val clean = closeExchangeOwners()
        synchronized(lock) { busy = false }
        var callbackFailed = false
        try { callback?.invoke(RuntimeFrameVerification.Rejected(RuntimeFrameRejection.TERMINAL)) }
        catch (_: Throwable) { callbackFailed = true; synchronized(lock) { cleanupUnproven = true } }
        if (sendCancel && old != null && !closed) {
            try { timer.execute {
                val cancelled = try { cancelRemotely(old) } catch (_: Throwable) { false }
                if (!cancelled) {
                    synchronized(lock) { cleanupUnproven = true }
                    try { RuntimeReissueInvalidation.apply(ownership, onInvalidated) } catch (_: Throwable) { }
                }
            } }
            catch (_: Throwable) { }
        }
        if ((notify || !clean || callbackFailed) && old != null) {
            try { RuntimeReissueInvalidation.apply(ownership, onInvalidated) }
            catch (_: Throwable) { synchronized(lock) { cleanupUnproven = true } }
        }
    }
    private fun connectionFailed() {
        val callback = synchronized(lock) { boundCallback.also { boundCallback = null } }
        abortCurrent(true, false)
        try { callback?.invoke(false) } catch (_: Throwable) { }
        try { close() } catch (_: Throwable) { }
    }
    override fun close() {
        val previous = synchronized(lock) { start ?: cancelOutstanding }
        abortCurrent(false, false)
        if (previous != null && synchronized(lock) { !closed && !providerInvalidating && remote?.isBinderAlive == true }) {
            val clean = try { cancelRemotely(previous) } catch (_: Throwable) { false }
            if (!clean) synchronized(lock) { cleanupUnproven = true }
        }
        val binder: IBinder?
        val unbind: Boolean
        synchronized(lock) {
            if (closed) { if (cleanupUnproven) throw IOException("AUTHORITY_CLEANUP_UNPROVEN"); return }
            closed = true; binder = remote; remote = null; providerEpoch = null; providerPid = null
            unbind = contextBound; contextBound = false; binding = false
        }
        if (binder != null) try { binder.unlinkToDeath(remoteDeath, 0) } catch (_: Throwable) { }
        if (unbind) try { context.unbindService(connection) } catch (_: Throwable) { synchronized(lock) { cleanupUnproven = true } }
        worker.shutdownNow(); timer.shutdownNow()
        synchronized(lock) { if (cleanupUnproven) throw IOException("AUTHORITY_CLEANUP_UNPROVEN") }
    }
}
