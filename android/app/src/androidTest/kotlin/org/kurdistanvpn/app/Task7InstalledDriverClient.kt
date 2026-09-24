// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.content.*
import android.net.VpnService
import android.os.*
import androidx.test.platform.app.InstrumentationRegistry
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking

data class Task7InstalledMaintenanceResultV1(val terminal:LongArray,val measurement:LongArray)

class Task7InstalledDriverClient : AutoCloseable {
    data class TunResult(val summary:LongArray,val packets:LongArray)
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val connected = CountDownLatch(1)
    private var binder: IBinder? = null
    private var bound = false
    private val death = Binder()
    private var identity: Pair<Long, Long>? = null
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) { binder = service; connected.countDown() }
        override fun onServiceDisconnected(name: ComponentName?) { binder = null }
    }
    fun prepareFreshFixtureOrVerifyExactPreparedState() {
        check(VpnService.prepare(context) == null) { "TASK7_REAL_VPN_CONSENT_REQUIRED" }
        runBlocking { Task7InstalledFixturePreparation.prepareOrVerify(context.applicationContext as KurdistanApplication) }
    }
    fun prepareFreshUpdateFixtureOrVerifyExactPreparedState() {
        check(VpnService.prepare(context)==null) { "TASK7_REAL_VPN_CONSENT_REQUIRED" }
        runBlocking { Task7InstalledFixturePreparation.prepareUpdateOrVerify(context.applicationContext as KurdistanApplication) }
    }
    fun runCase(case: Int, pressure: Int): LongArray {
        val intent = Intent(context, Task7InstalledDriverService::class.java).setAction(Task7InstalledDriverService.ACTION)
        bound = context.bindService(intent, connection, Context.BIND_AUTO_CREATE)
        check(bound && connected.await(5, TimeUnit.SECONDS)) { "TASK7_BIND_UNAVAILABLE" }
        val admitted = transact(1) { writeInt(case); writeInt(pressure); writeStrongBinder(death) }
        check(admitted[2] == 1L) { "TASK7_ADMISSION_REJECTED" }
        identity = admitted[0] to admitted[1]
        val deadline = SystemClock.elapsedRealtime() + 45_000
        var result: LongArray
        do {
            result = request(2)
            check(result[0] == admitted[0] && result[1] == admitted[1]) { "TASK7_EPOCH_LOST" }
            if (result[2] != 1L) break
            SystemClock.sleep(25)
        } while (SystemClock.elapsedRealtime() < deadline)
        check(result[2] == 2L) {
            val expectedIdentity = checkNotNull(identity)
            val publication = runCatching {
                val id = expectedIdentity
                transact(2, 40) { writeLong(id.first); writeLong(id.second); writeInt(1); writeInt(1) }
            }.getOrNull()
            val publicationFailure = task7InstalledPublicationPageFailureV1(publication, expectedIdentity.first, expectedIdentity.second)
            val provider = (context.applicationContext as KurdistanApplication).runtimeAuthorityReissue.responseDiagnosticSnapshot()
            val providerPublication = runCatching {
                (context.applicationContext as KurdistanApplication).runtimeAuthorityReissue.responseDiagnosticSnapshot(1)
                    .also { check(it.size == 24 && it[0] == 1L && it[1] == 1L) }
            }.getOrNull()
            fun publicationRecord(values: LongArray, offset: Int): String =
                "PHASE_${values[offset]}_CATEGORY_${values[offset + 1]}_AGE_MS_${values[offset + 2]}" +
                    "_PREDICATE_${values[offset + 3]}_STATE_${values[offset + 4]}_COMPLETED_${values[offset + 5]}_EXCEPTION_${values[offset + 6]}"
            val publicationDetails = if (publicationFailure.isNotEmpty()) publicationFailure else {
                checkNotNull(publication)
                "_PUBLICATION_CLIENT_AVAILABLE_${publication[5]}_DELEGATE_AVAILABLE_${publication[6]}" +
                    "_CLIENT_ACQUIRE_${publicationRecord(publication, 8)}_CLIENT_RELEASE_${publicationRecord(publication, 16)}" +
                    "_DELEGATE_ACQUIRE_${publicationRecord(publication, 24)}_DELEGATE_CLOSE_${publicationRecord(publication, 32)}"
            }
            val providerPublicationDetails = if (providerPublication == null) "_PROVIDER_PUBLICATION_PAGE_UNAVAILABLE" else
                "_PROVIDER_PUBLICATION_AVAILABLE_${providerPublication[2]}_COMPLETE_${publicationRecord(providerPublication, 4)}" +
                    "_RELEASE_${publicationRecord(providerPublication, 12)}"
            val packed = result[14] >= 0 && result[14] and (1L shl 62) != 0L
            val kind = if (packed) (result[14] and 255).let { if (it == 255L) -1 else it } else result[14]
            val detail = if (packed) (result[31] and 0xfffff).let { if (it == 0xfffffL) -1 else it } else result[31]
            fun nativeWord(word: Long): String = "PHASE_${word and 15}_STATUS_${(word ushr 4) and 31}_ORDER_${(word ushr 9) and 7}"
            val rejection = if (packed) {
                val callback = (result[14] ushr 11) and 127
                val socket = (result[14] ushr 42) and 0x7ffff
                "_CALL_ADMISSION_${(result[14] ushr 8) and 7}_REVALIDATE_PHASE_${callback and 15}_EXCEPTION_${callback ushr 4}" +
                    "_C_CONTROL_${nativeWord((result[31] ushr 20) and 4095)}" +
                    "_C_REVISION_${nativeWord((result[14] ushr 18) and 4095)}" +
                    "_C_PREPARE_${nativeWord((result[14] ushr 30) and 4095)}" +
                    "_SOCKET_PHASE_${socket and 15}_CATEGORY_${(socket ushr 4) and 7}_ORIGIN_${(socket ushr 7) and 3}_LINE_${socket ushr 9}"
            } else "_REJECTION_UNAVAILABLE"
            "TASK7_CASE_FAILED_CATEGORY_${result[3]}_STAGE_${result[11]}_ORIGIN_${result[12]}_LINE_${result[13]}_CLEANUP_${result[9]}" +
                "_NATIVE_RESULT_KIND_${kind}_NATIVE_RESULT_DETAIL_${detail}" + rejection +
                "_PROVIDER_STAGE_${provider[0]}_CATEGORY_${provider[1]}_ORIGIN_${provider[2]}_LINE_${provider[3]}_FINALIZED_${provider[4]}_CLEANUP_UNPROVEN_${provider[5]}_LEASE_AGE_MS_${provider[6]}" +
                "_REGISTERED_PHASE_${provider[7]}_PREDICATE_${provider[8]}_EXCEPTION_${provider[9]}" +
                publicationDetails + providerPublicationDetails
        }
        val finished = request(4)
        check(finished[2] == 2L && finished[9] == 1L) { "TASK7_FINISH_UNPROVEN" }
        identity = null
        return finished
    }
    fun runTunCase(case:Int):TunResult {
        require(case in 2..7)
        val intent=Intent(context,Task7InstalledDriverService::class.java).setAction(Task7InstalledDriverService.ACTION)
        bound=context.bindService(intent,connection,Context.BIND_AUTO_CREATE)
        check(bound && connected.await(5,TimeUnit.SECONDS)){"TASK7_BIND_UNAVAILABLE"}
        val admitted=transact(1){writeInt(case);writeInt(0);writeStrongBinder(death)}
        check(admitted[2]==1L){"TASK7_ADMISSION_REJECTED"};identity=admitted[0] to admitted[1]
        val deadline=SystemClock.elapsedRealtime()+45000
        var page:LongArray?=null;var summary=admitted;var sentCancel=false
        try {
            do {
                summary=request(2)
                val id=checkNotNull(identity)
                page=transact(2,64){writeLong(id.first);writeLong(id.second);writeInt(1);writeInt(2)}
                check(task7InstalledTunPageMatchesV1(page,id.first,id.second)){"TASK7_TUN_PAGE_MISMATCH"}
                if(case==6 && !sentCancel && page[7]==15L && page[21]==44L){request(3);sentCancel=true}
                if(summary[2]!=1L && page[4]!=1L)break
                SystemClock.sleep(10)
            } while(SystemClock.elapsedRealtime()<deadline)
            val observed=checkNotNull(page){"TASK7_TUN_PAGE_UNAVAILABLE"}
            check(summary[2]==observed[4] && summary[2]==(if(case==6)3L else 2L) && summary[9]==1L &&
                (case!=6 || sentCancel && summary[3]==2L) && task7InstalledTunOutcomeV1(observed)) {
                "TASK7_TUN_FAILED_CASE_${case}_STATE_${summary[2]}_CATEGORY_${summary[3]}_STAGE_${observed[7]}"+
                    "_FAILURE_${observed[54]}_CLEANUP_${observed[9]}_RESULTS_${observed.copyOfRange(8,58).joinToString(",")}"
            }
            // Page2 must be retained and validated before FINISH releases admission.
            val retained=observed.copyOf();val finished=request(4)
            check(finished[2]==summary[2] && finished[9]==1L){"TASK7_FINISH_UNPROVEN"}
            identity=null
            return TunResult(finished,retained)
        } catch(failure:Exception){
            val retained=page
            InstrumentationRegistry.getInstrumentation().sendStatus(0,Bundle().apply{
                putString("task7_tun_page",if(retained==null)"UNAVAILABLE" else "RETAINED")
                if(retained!=null)putLongArray("task7_tun_observations",retained.copyOfRange(2,64))
            })
            throw failure
        }
    }
    fun runMaintenanceCase(case:Int,level:Int=0):Task7InstalledMaintenanceResultV1 {
        require((case in 8..11 || case in 301..304) && task7InstalledCaseAllowedV1(case,level))
        val intent=Intent(context,Task7InstalledDriverService::class.java).setAction(Task7InstalledDriverService.ACTION)
        bound=context.bindService(intent,connection,Context.BIND_AUTO_CREATE)
        check(bound && connected.await(5,TimeUnit.SECONDS)){"TASK7_BIND_UNAVAILABLE"}
        val admitted=transact(1){writeInt(case);writeInt(level);writeStrongBinder(death)}
        check(admitted[2]==1L){"TASK7_ADMISSION_REJECTED"};identity=admitted[0] to admitted[1]
        val deadline=SystemClock.elapsedRealtime()+45000
        var retained:LongArray?=null
        try {
            var summary:LongArray
            do {
                summary=request(2)
                val id=checkNotNull(identity)
                check(summary[0]==id.first && summary[1]==id.second){"TASK7_EPOCH_LOST"}
                val page=transact(2,72){writeLong(id.first);writeLong(id.second);writeInt(1);writeInt(3)}
                check(task7InstalledMaintenancePageMatchesV1(page,id.first,id.second) && page[5]==case.toLong() && page[6]==level.toLong()){"TASK7_MAINTENANCE_PAGE_MISMATCH"}
                retained=page
                if(summary[2]!=1L && page[4]!=1L)break
                SystemClock.sleep(25)
            }while(SystemClock.elapsedRealtime()<deadline)
            val page=checkNotNull(retained){"TASK7_MAINTENANCE_PAGE_UNAVAILABLE"}
            check(summary[2]==2L && summary[9]==1L && page[4]==2L && task7InstalledMaintenanceOutcomeV1(page)){
                "TASK7_MAINTENANCE_FAILED_CASE_${case}_STATE_${page[4]}_STAGE_${page[14]}_CATEGORY_${page[15]}_CLEANUP_${page[11]}_MAINTENANCE_RESULTS_${page.copyOfRange(9,71).joinToString(",")}"
            }
            // This valid invocation's page is owned locally before FINISH releases admission.
            val observed=page.copyOf();val terminal=request(4)
            check(terminal[2]==2L && terminal[9]==1L){"TASK7_FINISH_UNPROVEN"}
            identity=null
            return Task7InstalledMaintenanceResultV1(terminal,observed)
        }catch(failure:Exception){
            InstrumentationRegistry.getInstrumentation().sendStatus(0,Bundle().apply{
                putString("task7_maintenance_page",if(retained==null)"UNAVAILABLE_OR_MISMATCH" else "RETAINED_VALID")
                retained?.let{putLongArray("task7_maintenance_observations",it.copyOfRange(2,72))}
            })
            throw failure
        }
    }
    fun runMaintenanceDnsCase(case:Int):Task7InstalledMaintenanceResultV1 {
        require(case in 12..14)
        bound=context.bindService(Intent(context,Task7InstalledDriverService::class.java).setAction(Task7InstalledDriverService.ACTION),connection,Context.BIND_AUTO_CREATE)
        check(bound && connected.await(5,TimeUnit.SECONDS))
        val admitted=transact(1){writeInt(case);writeInt(0);writeStrongBinder(death)}
        check(admitted[2]==1L);identity=admitted[0] to admitted[1]
        val deadline=SystemClock.elapsedRealtime()+45000
        var page:LongArray
        var summary:LongArray
        do {
            summary=request(2);val id=checkNotNull(identity)
            page=transact(2,80){writeLong(id.first);writeLong(id.second);writeInt(1);writeInt(6)}
            check(task7InstalledMaintenanceDnsPageMatchesV1(page,id.first,id.second) && page[5]==case.toLong())
            if(summary[2]!=1L && page[4]!=1L)break
            SystemClock.sleep(25)
        }while(SystemClock.elapsedRealtime()<deadline)
        check(summary[2]==2L && summary[9]==1L && task7InstalledMaintenanceDnsOutcomeV1(page)){
            "TASK7_DNS_FAILED_${case}_OBS_${page.copyOfRange(2,71).joinToString(",")}"
        }
        val terminal=request(4);check(terminal[2]==2L && terminal[9]==1L);identity=null
        return Task7InstalledMaintenanceResultV1(terminal,page)
    }
    private fun request(code: Int): LongArray = transact(code) {
        val id = checkNotNull(identity); writeLong(id.first); writeLong(id.second)
    }
    private fun transact(code: Int, length: Int = 32, fields: Parcel.() -> Unit): LongArray {
        val data = Parcel.obtain(); val reply = Parcel.obtain()
        try {
            data.writeInterfaceToken(Task7InstalledDriverService.DESCRIPTOR); data.fields()
            check(checkNotNull(binder).transact(code, data, reply, 0))
            reply.readException()
            val result = LongArray(length); reply.readLongArray(result)
            check(reply.dataAvail() == 0)
            return result
        } finally { data.recycle(); reply.recycle() }
    }
    override fun close() {
        try { if (identity != null && binder?.isBinderAlive == true) request(3) }
        finally { if (bound) { context.unbindService(connection); bound = false } }
    }
}
