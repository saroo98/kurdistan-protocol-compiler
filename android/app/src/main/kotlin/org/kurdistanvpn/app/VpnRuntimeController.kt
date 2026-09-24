// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.content.ComponentName
import android.content.ServiceConnection
import android.content.Context
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.net.ConnectivityManager
import android.net.VpnService
import org.kurdistanvpn.runtime.android.IRuntimeControl
import org.kurdistanvpn.runtime.android.IRuntimeObserver
import org.kurdistanvpn.runtime.android.RuntimeControlBinder
import org.kurdistanvpn.runtime.api.RuntimeStatusWire
import org.kurdistanvpn.runtime.api.RuntimeAction
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.async
import org.kurdistanvpn.runtime.android.KurdVpnService
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeState
import org.kurdistanvpn.runtime.api.validatedForDisplay

/** UI lifecycle staging only. No authority or retry budget is retained in the app process. */
internal class ManualStartAdmission : AutoCloseable {
    private var generation = 0L
    private var staged: Long? = null
    private var closed = false
    @Synchronized fun stage(): Long {
        check(!closed && generation < Long.MAX_VALUE) { "MANUAL_START_UNAVAILABLE" }
        return (++generation).also { staged = it }
    }
    @Synchronized fun consume(): Long? = staged.also { staged = null }.takeIf { !closed }
    @Synchronized fun isCurrent(value: Long): Boolean = !closed && value > 0 && generation == value
    @Synchronized fun cancel() {
        staged = null
        if (generation == Long.MAX_VALUE) closed = true else generation++
    }
    @Synchronized override fun close() { closed = true; staged = null }
}

/** One decision per Activity/ViewModel lifetime, not every resume or settings edit. */
internal class ForegroundLaunchAdmission {
    private var consumed = false
    fun consume(resumed: Boolean, enabled: Boolean, paused: Boolean): Boolean {
        if (!resumed || consumed) return false
        consumed = true
        return enabled && !paused
    }
}

class VpnRuntimeController(private val context: Context) : AutoCloseable {
    private val startScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val admission = ManualStartAdmission()
    private val startLock = Any()
    private var pendingStart: Job? = null
    private var closed = false
    @Volatile private var activeRequestId: String? = null
    private var screenManaged = false
    private var screens = 0
    private var settingsOwners = 0
    internal fun retainSettingsOwner() = synchronized(startLock) { check(!closed); settingsOwners++ }
    internal fun releaseSettingsOwner() = synchronized(startLock) {
        check(settingsOwners > 0); settingsOwners--; closeIfUnowned()
    }
    private var recoveryPending = false
    internal val isClosed: Boolean get() = synchronized(startLock) { closed }

    internal fun attachScreen() = synchronized(startLock) {
        check(!closed)
        screenManaged = true
        screens++
    }

    internal fun detachScreen() = synchronized(startLock) {
        check(screens > 0)
        screens--
        if (screens == 0) {
            cancelPendingStart()
            closeIfUnowned()
        }
    }

    private fun closeIfUnowned() {
        if (synchronized(startLock) { !screenManaged || screens > 0 || closed }) return
        // Binder status callbacks must not synchronously unregister themselves.
        startScope.launch(Dispatchers.Main.immediate) {
            synchronized(startLock) {
                val value = mutableSnapshot.value
                val session = value.state in setOf(VpnRuntimeState.CONNECTING, VpnRuntimeState.ACTIVE_KURD_LIVE,
                    VpnRuntimeState.DEGRADED, VpnRuntimeState.FALLING_BACK, VpnRuntimeState.RECONNECTING,
                    VpnRuntimeState.STOPPING, VpnRuntimeState.RECOVERING) ||
                    value.state == VpnRuntimeState.BLOCKED && value.failure == "RUNTIME_PROCESS_LOST"
                if (screens == 0 && settingsOwners == 0 && !session) close()
            }
        }
    }
    private val mutableSnapshot = MutableStateFlow(VpnRuntimeSnapshot())
    val snapshot: StateFlow<VpnRuntimeSnapshot> = mutableSnapshot.asStateFlow()
    @Volatile private var control: IRuntimeControl? = null
    private val mutableControlReady = MutableStateFlow(false)
    internal val controlReady = mutableControlReady.asStateFlow()
    private var bound = false
    private var actionSequence = 0L
    private var binding: IBinder? = null
    @Volatile private var observer: IRuntimeObserver? = null
    private fun observerFor(service: IBinder) = object : IRuntimeObserver.Stub() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (Binder.getCallingUid() != context.applicationInfo.uid || data.dataSize() > 8192) return false
            return super.onTransact(code, data, reply, flags)
        }
        override fun onStatus(status: ByteArray?) {
            if (Binder.getCallingUid() != context.applicationInfo.uid || status == null) return
            synchronized(startLock) {
                if (!closed && binding === service) {
                    val value = try { RuntimeStatusWire.decode(status) } catch (_: IllegalArgumentException) { return }
                    acceptServiceSnapshot(value)
                }
            }
        }
    }
    private var connection: ServiceConnection = newConnection()
    private fun newConnection(): ServiceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            if (service == null) return
            synchronized(startLock) {
                if (closed || connection !== this) return
                binding = service
            }
            startScope.launch {
                val remote = IRuntimeControl.Stub.asInterface(service)
                val peer = observerFor(service)
                var registered = false
                var adopted = false
                try {
                    if (!remote.registerObserver(RuntimeStatusWire.VERSION, peer)) return@launch
                    registered = true
                    val value = RuntimeStatusWire.decode(remote.queryStatus(RuntimeStatusWire.VERSION))
                    synchronized(startLock) {
                        if (!closed && binding === service) {
                            control = remote
                            observer = peer
                            actionSequence = 0
                            acceptServiceSnapshot(value)
                            mutableControlReady.value = true
                            adopted = true
                        }
                    }
                    if (adopted && value.state == VpnRuntimeState.IDLE) recoverLostSession(service)
                } catch (_: android.os.RemoteException) { }
                catch (_: IllegalArgumentException) { }
                catch (_: IllegalStateException) { }
                finally {
                    if (registered && !adopted) {
                        try { remote.unregisterObserver(RuntimeStatusWire.VERSION, peer) }
                        catch (_: android.os.RemoteException) { }
                        catch (_: IllegalStateException) { }
                    }
                }
            }
        }
        override fun onServiceDisconnected(name: ComponentName?) {
            synchronized(startLock) {
                if (connection !== this) return
                val reconnect = !closed && bound && binding != null
                bindingLost()
                // Some platform VPN cleanup paths leave the started service without a
                // process. One fresh observation binding can recreate it; never replay
                // manual authority or retry duplicate loss callbacks before a new Binder arrives.
                if (reconnect) {
                    context.unbindService(this)
                    bound = false
                    connection = newConnection()
                    try { bindControl() }
                    catch (_: SecurityException) { authorityRejected("RUNTIME_PERMISSION_REVOKED") }
                }
            }
        }
        override fun onBindingDied(name: ComponentName?) {
            synchronized(startLock) {
                if (connection !== this) return
                bindingLost()
                if (bound) { context.unbindService(this); bound = false }
                if (!closed) { connection = newConnection(); bindControl() }
            }
        }
    }

    init { bindControl() }

    private fun recoverLostSession(service: IBinder) {
        startScope.launch(Dispatchers.Main.immediate) {
            synchronized(startLock) {
                if (closed || binding !== service || !recoveryPending) return@synchronized
                recoveryPending = false // one attempt per observed active-process loss
                try {
                    if (VpnService.prepare(context) != null) {
                        authorityRejected("CONSENT_REJECTED")
                    } else {
                        acceptSnapshot(VpnRuntimeSnapshot(VpnRuntimeState.RECONNECTING))
                        // No private marker, request ID or cached authority. The existing
                        // automatic path must reconstruct and validate current permission.
                        context.startForegroundService(Intent(context, KurdVpnService::class.java))
                    }
                } catch (failure: Exception) { authorityRejected(startFailure(failure)) }
            }
        }
    }

    private fun bindingLost() = synchronized(startLock) {
        if (mutableSnapshot.value.state in setOf(VpnRuntimeState.ACTIVE_KURD_LIVE, VpnRuntimeState.DEGRADED))
            recoveryPending = true
        binding = null
        control = null
        observer = null
        mutableControlReady.value = false
        if (!closed && mutableSnapshot.value.state in setOf(VpnRuntimeState.ACTIVE_KURD_LIVE,
                VpnRuntimeState.DEGRADED, VpnRuntimeState.CONNECTING, VpnRuntimeState.RECONNECTING,
                VpnRuntimeState.FALLING_BACK, VpnRuntimeState.STOPPING, VpnRuntimeState.RECOVERING)) {
            activeRequestId = null
            acceptSnapshot(VpnRuntimeSnapshot(state = VpnRuntimeState.BLOCKED, failure = "RUNTIME_PROCESS_LOST"))
        }
    }

    private fun bindControl() {
        bound = context.bindService(Intent(RuntimeControlBinder.ACTION_BIND)
            .setComponent(ComponentName(context, KurdVpnService::class.java)),
            connection, Context.BIND_AUTO_CREATE)
    }

    fun prepareIntent(): Intent? {
        val intent = VpnService.prepare(context)
        mutableSnapshot.value = VpnRuntimeSnapshot(
            if (intent == null) VpnRuntimeState.PREPARING else VpnRuntimeState.AWAITING_VPN_CONSENT)
        return intent
    }
    fun permissionRejected() = authorityRejected("CONSENT_REJECTED")
    fun notificationPermissionRejected() = authorityRejected("NOTIFICATION_PERMISSION_REJECTED")

    internal suspend fun startOnForegroundLaunch(isResumed: () -> Boolean) {
        val current = try { querySettingsStatus() } catch (_: Exception) { return }
        kotlinx.coroutines.withContext(Dispatchers.Main.immediate) {
            if (!isResumed() || current.state != VpnRuntimeState.IDLE || control == null || closed) return@withContext
            try {
                if (VpnService.prepare(context) != null) return@withContext
                if (android.os.Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(
                        android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) return@withContext
                // Unmarked start invokes the existing automatic bootstrap validation, never manual consent authority.
                context.startForegroundService(Intent(context, KurdVpnService::class.java))
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (failure: Exception) { authorityRejected(startFailure(failure)) }
        }
    }

    fun stageManualStart() {
        synchronized(startLock) {
            recoveryPending = false
            pendingStart?.cancel(); pendingStart = null
            admission.stage()
        }
        mutableSnapshot.value = VpnRuntimeSnapshot(VpnRuntimeState.PREPARING)
    }

    fun authorityRejected(category: String) {
        synchronized(startLock) { recoveryPending = false }
        cancelPendingStart()
        activeRequestId = null
        acceptSnapshot(VpnRuntimeSnapshot(state = VpnRuntimeState.FAILED,
            failure = category.takeIf { it.length <= 64 && it.all { ch -> ch in 'A'..'Z' || ch == '_' || ch in '0'..'9' } }
                ?: "RUNTIME_START_REJECTED"))
    }

    fun startStaged() {
        val generation = admission.consume()
        if (generation == null) { authorityRejected("MISSING_USER_START"); return }
        mutableSnapshot.value = VpnRuntimeSnapshot(VpnRuntimeState.PREPARING)
        val job = startScope.launch(start = CoroutineStart.LAZY) {
            try {
                val connectivity = context.getSystemService(ConnectivityManager::class.java)
                val ready = VpnNetworkTeardownBarrier.awaitNoRegisteredVpn(
                    timeoutMillis = VPN_NETWORK_TEARDOWN_TIMEOUT_MILLIS,
                    pollMillis = VPN_NETWORK_POLL_MILLIS,
                    vpnTransportSnapshot = { VpnNetworkTeardownBarrier.snapshot(connectivity) })
                synchronized(startLock) {
                    if (!admission.isCurrent(generation)) return@synchronized
                    if (!ready) {
                        acceptSnapshot(VpnRuntimeSnapshot(state = VpnRuntimeState.FAILED, failure = "VPN_NETWORK_TEARDOWN_TIMEOUT"))
                    } else if (VpnService.prepare(context) != null) {
                        acceptSnapshot(VpnRuntimeSnapshot(state = VpnRuntimeState.FAILED, failure = "CONSENT_REJECTED"))
                    } else {
                        val requestId = KurdVpnService.newRequestId()
                        activeRequestId = requestId
                        mutableSnapshot.value = VpnRuntimeSnapshot(VpnRuntimeState.CONNECTING, runtimeRequestId = requestId)
                        KurdVpnService.start(context, requestId)
                    }
                }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (failure: Throwable) {
                if (admission.isCurrent(generation)) acceptSnapshot(VpnRuntimeSnapshot(
                    state = VpnRuntimeState.FAILED, failure = startFailure(failure)))
            } finally {
                synchronized(startLock) { if (admission.isCurrent(generation)) pendingStart = null }
            }
        }
        synchronized(startLock) {
            if (!admission.isCurrent(generation)) { job.cancel(); return }
            pendingStart = job
        }
        job.start()
    }

    private fun startFailure(failure: Throwable): String =
        org.kurdistanvpn.runtime.android.runtimeStartFailure(context, failure)

    fun stop() = stop(RuntimeAction.STOP)
    fun recoverInternet() = stop(RuntimeAction.RECOVER_INTERNET)

    internal fun readProxyCredentials(deliver: (ByteArray?) -> Unit) {
        startScope.launch(Dispatchers.IO) {
            var secret: ByteArray? = null
            val wire = ByteArray(org.kurdistanvpn.runtime.api.ProxyCredentialLeaseWire.SIZE)
            try {
                val remote = control
                val pipe = remote?.requestProxyCredentials(RuntimeStatusWire.VERSION,
                    synchronized(startLock) { ++actionSequence }, observer)
                if (pipe != null) android.os.ParcelFileDescriptor.AutoCloseInputStream(pipe).use {
                    java.io.DataInputStream(it).readFully(wire)
                    check(it.read() == -1)
                    secret = org.kurdistanvpn.runtime.api.ProxyCredentialLeaseWire.decode(wire, android.os.SystemClock.elapsedRealtime())
                }
            } catch (_: Exception) { secret?.fill(0); secret = null }
            finally { wire.fill(0) }
            try { kotlinx.coroutines.withContext(Dispatchers.Main) { deliver(secret) } }
            finally { secret?.fill(0) }
        }
    }

    internal fun rotateProxyCredentials(deliver: (Boolean) -> Unit) {
        startScope.launch(Dispatchers.IO) {
            val rotated = try { control?.requestAction(RuntimeStatusWire.VERSION,
                synchronized(startLock) { ++actionSequence }, RuntimeAction.ROTATE_PROXY_CREDENTIALS.wireCode, observer) == true }
                catch (_: Exception) { false }
            kotlinx.coroutines.withContext(Dispatchers.Main) { deliver(rotated) }
        }
    }

    internal fun restartProxy() {
        startScope.launch(Dispatchers.IO) {
            val accepted = try { control?.requestAction(RuntimeStatusWire.VERSION,
                synchronized(startLock) { ++actionSequence }, RuntimeAction.RESTART_PROXY.wireCode, observer) == true }
                catch (_: android.os.RemoteException) { false }
                catch (_: IllegalStateException) { false }
            if (!accepted) kotlinx.coroutines.withContext(Dispatchers.Main) {
                acceptSnapshot(mutableSnapshot.value.copy(failure = "PROXY_LISTENER_FAILED"))
            }
        }
    }

    private data class ProbeCall(val id: String, val remote: IRuntimeControl, val peer: IRuntimeObserver, val sequence: Long)
    private var pendingProbe: ProbeCall? = null

    internal suspend fun runSelectedProbe(profileId: org.kurdistanvpn.core.model.CatalogId,
        preferences: org.kurdistanvpn.core.model.ProbePreferences):
        org.kurdistanvpn.core.nativeapi.NativeProductResult<org.kurdistanvpn.core.nativeapi.NativeProbeResult> =
        kotlinx.coroutines.withContext(Dispatchers.IO) {
            fun rejected(code: org.kurdistanvpn.core.model.ProductFailureCode) =
                org.kurdistanvpn.core.nativeapi.NativeProductResult.Failure(code)
            val validated = org.kurdistanvpn.runtime.android.selectedProbeRequestV1(preferences)
            if (validated is org.kurdistanvpn.core.nativeapi.NativeProductResult.Failure) return@withContext validated
            val request = (validated as org.kurdistanvpn.core.nativeapi.NativeProductResult.Success).value
            val call = synchronized(startLock) {
                if (pendingProbe != null) return@withContext rejected(org.kurdistanvpn.core.model.ProductFailureCode.OPERATION_ALREADY_ACTIVE)
                val remote = control
                val peer = observer
                if (closed || remote == null || peer == null) return@withContext rejected(org.kurdistanvpn.core.model.ProductFailureCode.OPERATION_INTERRUPTED)
                ProbeCall(java.util.UUID.randomUUID().toString(), remote, peer, ++actionSequence).also { pendingProbe = it }
            }
            try {
                org.kurdistanvpn.runtime.android.RuntimeProbeWire.decode(call.remote.requestProbe(RuntimeStatusWire.VERSION,
                    call.sequence, call.id, profileId.value, request.targetId, preferences.timeoutSeconds, call.peer))
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { rejected(org.kurdistanvpn.core.model.ProductFailureCode.OPERATION_INTERRUPTED) }
            finally { synchronized(startLock) { if (pendingProbe === call) pendingProbe = null } }
        }

    internal suspend fun cancelSelectedProbe(): Boolean = kotlinx.coroutines.withContext(Dispatchers.IO) {
        val call = synchronized(startLock) { pendingProbe } ?: return@withContext true
        try { call.remote.cancelProbe(RuntimeStatusWire.VERSION, synchronized(startLock) { ++actionSequence }, call.id, call.peer) }
        catch (_: Exception) { false }
    }

    internal suspend fun checkSignedUpdate(profileId: org.kurdistanvpn.core.model.CatalogId):
        org.kurdistanvpn.core.nativeapi.NativeProductResult<org.kurdistanvpn.runtime.android.RuntimeVerifiedUpdate?> =
        deliverRuntimeUpdate update@{
            fun rejected(code: org.kurdistanvpn.core.model.ProductFailureCode) =
                org.kurdistanvpn.core.nativeapi.NativeProductResult.Failure(code)
            val call = synchronized(startLock) {
                if (pendingProbe != null) return@update rejected(org.kurdistanvpn.core.model.ProductFailureCode.OPERATION_ALREADY_ACTIVE)
                val remote = control
                val peer = observer
                if (closed || remote == null || peer == null) return@update rejected(org.kurdistanvpn.core.model.ProductFailureCode.OPERATION_INTERRUPTED)
                ProbeCall(java.util.UUID.randomUUID().toString(), remote, peer, ++actionSequence).also { pendingProbe = it }
            }
            var readOwner: org.kurdistanvpn.runtime.android.RuntimeAuthorityPipeOwner? = null
            var output: android.os.ParcelFileDescriptor? = null
            var artifact: ByteArray? = null
            var transferred = false
            try {
                val pipe = android.os.ParcelFileDescriptor.createReliablePipe()
                output = pipe[1]
                val context = kotlinx.coroutines.currentCoroutineContext()
                val input = org.kurdistanvpn.runtime.android.RuntimeAuthorityPipeOwner.take(pipe[0],
                    (this@VpnRuntimeController.context.applicationContext as KurdistanApplication).compositionRoot.durableFilePrimitives,
                    this@VpnRuntimeController.context.applicationInfo.uid.toLong(), 0,
                    android.os.SystemClock.elapsedRealtime() + 100_000, { context[kotlinx.coroutines.Job]?.isActive == true })
                    .also { readOwner = it }
                kotlinx.coroutines.coroutineScope {
                    val reader = async(Dispatchers.IO) {
                        val buffer = ByteArray(org.kurdistanvpn.runtime.android.RuntimeUpdateWire.MAX_ARTIFACT_BYTES + 1)
                        try {
                            var count = 0
                            while (true) {
                                val received = input.read(buffer, count, buffer.size - count)
                                if (received < 0) break
                                check(received > 0)
                                count += received
                                check(count <= org.kurdistanvpn.runtime.android.RuntimeUpdateWire.MAX_ARTIFACT_BYTES)
                            }
                            buffer.copyOf(count).also { artifact = it }
                        } finally { buffer.fill(0) }
                    }
                    reader.invokeOnCompletion { failure -> if (failure != null) startScope.launch(Dispatchers.IO) {
                        try { call.remote.cancelProbe(RuntimeStatusWire.VERSION, synchronized(startLock) { ++actionSequence }, call.id, call.peer) }
                        catch (_: Exception) { }
                    } }
                    val metadata = try { call.remote.requestUpdate(RuntimeStatusWire.VERSION, call.sequence,
                        call.id, profileId.value, output, call.peer) }
                    finally { output?.close(); output = null }
                    val bytes = reader.await().also { artifact = it }
                    org.kurdistanvpn.runtime.android.RuntimeUpdateWire.decode(metadata, bytes)
                }.also { result ->
                    transferred = result is org.kurdistanvpn.core.nativeapi.NativeProductResult.Success && result.value != null
                }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { rejected(org.kurdistanvpn.core.model.ProductFailureCode.OPERATION_INTERRUPTED) }
            finally {
                if (!transferred) artifact?.fill(0)
                try { readOwner?.close() } finally {
                    try { output?.close() } finally { synchronized(startLock) { if (pendingProbe === call) pendingProbe = null } }
                }
            }
        }

    internal suspend fun settingsTransition(operation: Int, token: String?): String? = kotlinx.coroutines.withContext(Dispatchers.IO) {
        control?.settingsTransition(RuntimeStatusWire.VERSION, synchronized(startLock) { ++actionSequence }, operation, token, observer)
    }
    internal suspend fun querySettingsStatus(): VpnRuntimeSnapshot = kotlinx.coroutines.withContext(Dispatchers.IO) {
        RuntimeStatusWire.decode(checkNotNull(control).queryStatus(RuntimeStatusWire.VERSION))
    }
    private val ownedSettingsRuntimePort by lazy { RuntimeSettingsApplyPort(::settingsTransition, ::querySettingsStatus) }
    internal fun settingsRuntimePort(): org.kurdistanvpn.data.settings.SettingsRuntimePort = ownedSettingsRuntimePort

    private fun stop(action: RuntimeAction) {
        synchronized(startLock) { recoveryPending = false }
        cancelPendingStart()
        val current = mutableSnapshot.value
        if (action == RuntimeAction.STOP && activeRequestId == null && current.state in setOf(VpnRuntimeState.IDLE, VpnRuntimeState.AWAITING_VPN_CONSENT,
                VpnRuntimeState.BLOCKED, VpnRuntimeState.REVOKED, VpnRuntimeState.FAILED)) {
            context.stopService(Intent(context, KurdVpnService::class.java))
            acceptSnapshot(VpnRuntimeSnapshot(VpnRuntimeState.IDLE))
        } else {
            mutableSnapshot.value = current.copy(state = VpnRuntimeState.STOPPING)
            val remote = control
            startScope.launch {
                val requested = try {
                    remote != null && remote.requestAction(RuntimeStatusWire.VERSION,
                        synchronized(startLock) { ++actionSequence }, action.wireCode, observer)
                } catch (_: android.os.RemoteException) { false }
                if (!requested) {
                    if (action == RuntimeAction.RECOVER_INTERNET) KurdVpnService.recoverInternet(context)
                    else KurdVpnService.stop(context)
                }
            }
        }
    }

    override fun close() {
        synchronized(startLock) { if (closed) return; closed = true; binding = null }
        cancelPendingStart(); admission.close(); startScope.cancel()
        val remote = control
        control = null
        mutableControlReady.value = false
        try { remote?.unregisterObserver(RuntimeStatusWire.VERSION, observer) }
        catch (_: android.os.RemoteException) { }
        catch (_: IllegalStateException) { }
        if (bound) { context.unbindService(connection); bound = false }
        observer = null
        // Releasing observation never stops a valid system-owned always-on session.
    }
    private fun cancelPendingStart() = synchronized(startLock) {
        admission.cancel(); pendingStart?.cancel(); pendingStart = null
    }
    private fun acceptSnapshot(value: VpnRuntimeSnapshot) {
        mutableSnapshot.value = value.validatedForDisplay()
        closeIfUnowned()
    }
    private fun acceptServiceSnapshot(value: VpnRuntimeSnapshot) {
        val current = mutableSnapshot.value
        // A fresh control binding may observe IDLE before the sticky start is delivered.
        // Keep recovery pending until the one fresh automatic request, never replay authority.
        if (current.failure == "RUNTIME_PROCESS_LOST" && value.state == VpnRuntimeState.IDLE &&
            value.runtimeRequestId == null && recoveryPending) return
        // A service with no attempt has no newer outcome for a locally rejected consent/start.
        if (value.state == VpnRuntimeState.IDLE && value.runtimeRequestId == null &&
            current.state in setOf(VpnRuntimeState.PREPARING, VpnRuntimeState.AWAITING_VPN_CONSENT,
                VpnRuntimeState.CONNECTING, VpnRuntimeState.RECONNECTING, VpnRuntimeState.FAILED)) return
        activeRequestId = value.runtimeRequestId
        recoveryPending = false
        acceptSnapshot(value)
    }
    private companion object {
        const val VPN_NETWORK_TEARDOWN_TIMEOUT_MILLIS = 15_000L
        const val VPN_NETWORK_POLL_MILLIS = 50L
    }
}

/** The service now emits terminal failure only after its signed retry budget is settled. */
internal fun isTerminalInitialRuntimeOutcome(snapshot: VpnRuntimeSnapshot): Boolean = snapshot.state in setOf(
    VpnRuntimeState.ACTIVE_KURD_LIVE, VpnRuntimeState.REVOKED, VpnRuntimeState.IDLE,
    VpnRuntimeState.STOPPING, VpnRuntimeState.FAILED, VpnRuntimeState.BLOCKED)
