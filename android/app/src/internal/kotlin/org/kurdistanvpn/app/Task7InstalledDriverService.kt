// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.*
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

class Task7InstalledDriverService : VpnService() {
    private val monitor = Any()
    private val epoch = SecureRandom().nextLong().and(Long.MAX_VALUE).coerceAtLeast(1)
    private var sequence = 0L
    private var current: Task7InstalledCase? = null
    private var client: IBinder? = null
    private var clientDeath: IBinder.DeathRecipient? = null
    private var caseWorker: Future<*>? = null
    private val worker = Executors.newSingleThreadExecutor()
    private val cancellation = Executors.newSingleThreadScheduledExecutor()
    private val control = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code !in 1..4 || reply == null || !task7InstalledSynchronousFlagsV1(flags) || data.dataSize() > 256 || !callerAllowed(getCallingUid())) return false
            data.enforceInterface(DESCRIPTOR)
            val result = if (code == 1) {
                val case = data.readInt(); val level = data.readInt(); val lifetime = data.readStrongBinder()
                require(data.dataAvail() == 0 && task7InstalledCaseAllowedV1(case,level) && lifetime != null)
                synchronized(monitor) {
                    check(current == null && sequence != Long.MAX_VALUE)
                    check(prepare(this@Task7InstalledDriverService) == null)
                    val admitted = Task7InstalledCase(this@Task7InstalledDriverService, epoch, ++sequence, case, level)
                    val died = IBinder.DeathRecipient { cancelCase(admitted) }
                    val admission = admitted.snapshot()
                    promote()
                    try {
                        lifetime.linkToDeath(died, 0)
                        client = lifetime; clientDeath = died; current = admitted
                        val timeout = cancellation.schedule({ cancelCase(admitted) }, 40, TimeUnit.SECONDS)
                        try { caseWorker = worker.submit { try { admitted.run() } finally { timeout.cancel(false) } } }
                        catch (failure: Exception) { timeout.cancel(false); throw failure }
                    } catch (failure: Exception) {
                        lifetime.unlinkToDeath(died, 0)
                        client = null; clientDeath = null; current = null; caseWorker = null
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        throw failure
                    }
                    admission
                }
            } else {
                val requestedEpoch = data.readLong(); val requestedSequence = data.readLong()
                val extension = when (data.dataAvail()) {
                    0 -> intArrayOf()
                    8 -> intArrayOf(data.readInt(), data.readInt())
                    else -> throw IllegalArgumentException()
                }
                val page = task7InstalledSnapshotPageV1(code, extension)
                require(data.dataAvail() == 0)
                val (same, work) = synchronized(monitor) {
                    val same = checkNotNull(current).also { check(it.epoch == requestedEpoch && it.sequence == requestedSequence) }
                    same to checkNotNull(caseWorker)
                }
                if (code == 3) cancelCase(same)
                val snapshot = task7InstalledSnapshotV1(same.snapshot(), work)
                if (code == 4) {
                    check(snapshot[2] != 1L && snapshot[9] == 1L)
                    finishTask7InstalledAdmissionV1(monitor, work, { check(current === same) }, {
                        clientDeath?.let { client?.unlinkToDeath(it, 0) }
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }, { client = null; clientDeath = null; current = null; caseWorker = null })
                }
                when(page) {
                    1 -> same.publicationSnapshot().also { it[4] = snapshot[2] }
                    2 -> same.tunSnapshot().also { it[4] = snapshot[2] }
                    3 -> same.maintenanceSnapshot().also { it[4] = snapshot[2]; it[58] = if(work.isDone)1 else 0 }
                    6 -> same.maintenanceDnsSnapshot().also { it[4]=snapshot[2];it[66]=if(work.isDone)1 else 0 }
                    else -> snapshot
                }
            }
            reply.writeNoException(); reply.writeLongArray(result); return true
        }
    }
    override fun onBind(intent: Intent?): IBinder? {
        if (intent?.action == SERVICE_INTERFACE) return super.onBind(intent)
        return if (intent?.action == ACTION && packageName == "org.kurdistanvpn.app.internal" &&
            applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) control else null
    }
    private fun callerAllowed(uid: Int): Boolean = uid == applicationInfo.uid ||
        (packageManager.getPackagesForUid(uid)?.toSet() == setOf("org.kurdistanvpn.app.internal.test") &&
            packageManager.checkSignatures(applicationInfo.uid, uid) == PackageManager.SIGNATURE_MATCH)
    private fun promote() {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel("task7-internal", "Internal qualification", NotificationManager.IMPORTANCE_LOW))
        val notification = Notification.Builder(this, "task7-internal").setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("Internal VPN qualification").setOngoing(true).build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(28471, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(28471, notification)
    }
    private fun cancelCurrent() {
        val same = synchronized(monitor) { current } ?: return
        cancelCase(same)
    }
    private fun cancelCase(same: Task7InstalledCase) {
        synchronized(monitor) {
            if (current !== same || !same.requestCancellation()) return
            cancellation.execute { same.cancel() }
        }
    }
    override fun onRevoke() { cancelCurrent(); super.onRevoke() }
    override fun onDestroy() { cancelCurrent(); worker.shutdown(); cancellation.shutdown(); super.onDestroy() }
    companion object {
        const val ACTION = "org.kurdistanvpn.app.internal.TASK7_BIND_V1"
        const val DESCRIPTOR = "org.kurdistanvpn.app.internal.Task7InstalledDriverV1"
    }
}

// API 26 native Binder adds TF_ACCEPT_FDS to synchronous remote calls, even for Java flags=0.
// https://android.googlesource.com/platform/frameworks/native/+/android-8.0.0_r1/libs/binder/IPCThreadState.cpp#565
private const val TASK7_BINDER_ACCEPT_FDS_V1 = 0x10
// Android 16 BinderProxy adds this accounting flag to eligible synchronous calls;
// Binder forwards it to onTransact. It does not grant caller authority.
// https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/java/android/os/IBinder.java#190
private const val TASK7_BINDER_COLLECT_NOTED_APP_OPS_V1 = 0x2

internal fun task7InstalledSynchronousFlagsV1(flags: Int): Boolean =
    flags == 0 || flags == TASK7_BINDER_ACCEPT_FDS_V1 ||
        flags == TASK7_BINDER_COLLECT_NOTED_APP_OPS_V1 ||
        flags == (TASK7_BINDER_ACCEPT_FDS_V1 or TASK7_BINDER_COLLECT_NOTED_APP_OPS_V1)

internal fun finishTask7InstalledAdmissionV1(monitor: Any, worker: Future<*>, verify: () -> Unit,
    retire: () -> Unit, releaseAdmission: () -> Unit) {
    synchronized(monitor) {
        verify()
        // Future completion follows run() AND its executor wrapper's timeout cleanup.
        // get() cannot block after isDone, and rejects cancelled/failed wrappers.
        check(worker.isDone)
        worker.get()
        retire()
        // START uses this same monitor. Failure above must retain the old admission.
        releaseAdmission()
    }
}

internal fun task7InstalledSnapshotV1(snapshot: LongArray, worker: Future<*>): LongArray {
    check(snapshot.size == 32)
    if (snapshot[2] != 1L && !worker.isDone) snapshot[2] = 1
    return snapshot
}

internal fun task7InstalledSnapshotPageV1(code: Int, extension: IntArray): Int {
    require(code in 2..4)
    if (extension.isEmpty()) return 0
    require(code == 2 && extension.size == 2 && extension[0] == 1 && (extension[1] in 1..3 || extension[1]==6))
    return extension[1]
}

internal fun task7InstalledPublicationPageMatchesV1(page: LongArray, epoch: Long, sequence: Long): Boolean =
    page.size == 40 && page[0] == epoch && page[1] == sequence && page[2] == 1L && page[3] == 1L

internal fun task7InstalledPublicationPageFailureV1(page: LongArray?, epoch: Long, sequence: Long): String = when {
    page == null -> "_PUBLICATION_PAGE_UNAVAILABLE"
    !task7InstalledPublicationPageMatchesV1(page, epoch, sequence) -> "_PUBLICATION_PAGE_MISMATCH"
    else -> ""
}

internal fun task7InstalledPublicationPageV1(epoch: Long, sequence: Long, state: Long,
    client: LongArray?, delegate: LongArray?): LongArray = LongArray(40) { -1 }.also { result ->
    result[0] = epoch; result[1] = sequence; result[2] = 1; result[3] = 1; result[4] = state
    result[5] = 0; result[6] = 0
    fun copy(values: LongArray?, offset: Int, available: Int) {
        if (values == null || values.size != 16) return
        for (i in listOf(0, 8)) {
            if (values[i] !in -1..7 || values[i + 1] !in -1..4 || values[i + 2] !in -1..60000 ||
                values[i + 3] !in -1..1 || values[i + 4] !in -1..1 || values[i + 5] !in -1..1 ||
                values[i + 6] !in -1..6 || values[i + 7] != -1L) return
        }
        values.copyInto(result, offset); result[available] = 1
    }
    copy(client, 8, 5); copy(delegate, 24, 6)
}
