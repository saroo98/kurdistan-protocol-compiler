// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.Assert.*
import org.junit.Test

class Task7InstalledMaintenanceCaseTest {
    @Test fun componentPressureAdmissionIsClosedAndRequiresRealJoinedMeasurements() {
        for(case in 301..304)for(level in listOf(0,16,32,64))assertTrue(task7InstalledCaseAllowedV1(case,level))
        assertFalse(task7InstalledCaseAllowedV1(305,64));assertFalse(task7InstalledCaseAllowedV1(301,65))
        val v=LongArray(24){-1}
        v[0]=1;v[1]=301;v[2]=1;v[3]=0;v[4]=0;v[5]=1;v[6]=200;v[7]=0
        v[8]=0;v[9]=1;v[10]=1;v[11]=1;v[13]=1;v[14]=500;v[15]=0;v[16]=1
        v[17]=0;v[18]=1;v[19]=0;v[20]=0;v[21]=0;v[22]=1;v[23]=1
        assertTrue(task7MaintenanceMeasurementV1(v,301))
        for(i in listOf(9,10,11,13,14,16,18,22,23))assertFalse(task7MaintenanceMeasurementV1(v.copyOf().apply{this[i]=-1},301))
        assertFalse(task7MaintenanceMeasurementV1(v.copyOf().apply{this[14]=65537},301))
        v[1]=302;v[8]=8;v[13]=0;v[14]=0
        assertTrue(task7MaintenanceMeasurementV1(v,302))
        assertFalse(task7MaintenanceMeasurementV1(v.copyOf().apply{this[8]=9},302))
    }
    @Test fun dnsPacketValidatorRejectsUnrelatedAndDamagedKernelPackets() {
        val client=byteArrayOf(10,77,0,2);val dns=byteArrayOf(10,77,0,1)
        val p="4500003d00014000401100000a4d00020a4d0001c0010035002900001234010000010000000000000775706461746573076578616d706c650000010001"
            .chunked(2).map{it.toInt(16).toByte()}.toByteArray()
        var sum=0;for(i in 0 until 20 step 2)sum+=(p[i].toInt() and 255)*256+(p[i+1].toInt() and 255)
        while(sum>65535)sum=(sum and 65535)+(sum ushr 16)
        val checksum=sum.inv() and 65535;p[10]=(checksum ushr 8).toByte();p[11]=checksum.toByte()
        assertTrue(task7MaintenanceDnsPacketV1(p,p.size,client,dns,0,null))
        assertFalse(task7MaintenanceDnsPacketV1(p,p.size-1,client,dns,0,null))
        assertFalse(task7MaintenanceDnsPacketV1(p.copyOf().apply{this[41]='x'.code.toByte()},p.size,client,dns,0,null))
        assertFalse(task7MaintenanceDnsPacketV1(p.copyOf().apply{this[10]=0},p.size,client,dns,0,null))
        assertFalse(task7MaintenanceDnsPacketV1(p,p.size,dns,client,0,null))
    }
    @Test fun dnsPageCannotPassWithoutActualObservationsAndJoinedCleanup() {
        val p=task7InstalledMaintenanceDnsPageV1(1,2,2,12)
        assertFalse(task7InstalledMaintenanceDnsOutcomeV1(p))
        assertFalse(task7InstalledMaintenanceDnsOutcomeV1(LongArray(80){-1}))
        for(i in listOf(9,10,15,19,23,24,25,26,27,28,29,32,33,34,37,38,39,41,44,48,50,51,53,54,55,56,57,58,59,60,61,62,63,65,66,67,68,69,70))p[i]=1
        p[11]=100;p[12]=200;p[13]=12;p[14]=0;p[16]=65536;p[17]=30000;p[18]=60
        p[21]=110;p[30]=0;p[35]=1;p[36]=0;p[40]=61;p[42]=0;p[43]=92;p[45]=92;p[46]=0;p[47]=60;p[49]=0;p[52]=1;p[64]=1
        assertTrue(task7InstalledMaintenanceDnsOutcomeV1(p))
        for(i in listOf(10,38,44,51,53,56,58,59,60,61,63,66)) {
            val bad=p.copyOf();bad[i]=-1;assertFalse("missing $i",task7InstalledMaintenanceDnsOutcomeV1(bad))
        }
        assertFalse(task7InstalledMaintenanceDnsOutcomeV1(p.copyOf().apply{this[3]=4}))
        assertFalse(task7InstalledMaintenanceDnsOutcomeV1(p.copyOf().apply{this[52]=3}))
        assertFalse(task7InstalledMaintenanceDnsOutcomeV1(p.copyOf().apply{this[71]=0}))
    }
    @Test fun dnsRateWitnessCannotResetOrAdmitBeforeSignedInterval() {
        val rate=Task7MaintenanceDnsRateV1()
        assertEquals(-1L,rate.begin("same",100))
        rate.completed(200)
        assertThrows(IllegalStateException::class.java){rate.begin("same",60_199)}
        assertThrows(IllegalStateException::class.java){rate.begin("other",60_200)}
        assertEquals(200L,rate.begin("same",60_200))
        rate.completed(60_300)
        assertThrows(IllegalStateException::class.java){rate.begin("same",60_400)}
    }
    @Test fun updateFixtureReuseNeverRepairsDifferentSettingsOrRevision() {
        assertTrue(task7UpdatePreparedMatchesV1(listOf("local", "4"), 4, "local", 1, true, true))
        assertFalse(task7UpdatePreparedMatchesV1(listOf("local", "4"), 6, "local", 1, true, true))
        assertFalse(task7UpdatePreparedMatchesV1(listOf("local", "4"), 4, "other", 1, true, true))
        assertFalse(task7UpdatePreparedMatchesV1(listOf("local", "4"), 4, "local", 2, true, true))
        assertFalse(task7UpdatePreparedMatchesV1(listOf("local", "4"), 4, "local", 1, false, true))
        assertFalse(task7UpdatePreparedMatchesV1(listOf("local", "4"), 4, "local", 1, true, false))
        assertFalse(task7UpdatePreparedMatchesV1(listOf("local"), 4, "local", 1, true, true))
    }
    @Test fun firstFailureDiagnosticKeepsPrimaryAndCleanupIndependentAndNeverLeaksText() {
        val emitted=mutableListOf<String>();val diagnostic=Task7MaintenanceDiagnosticV1(8,emitted::add)
        val failure=IllegalStateException("secret-message").apply { stackTrace=arrayOf(
            StackTraceElement("foreign.Secret","secretMethod","Secret.kt",4),
            StackTraceElement("org.kurdistanvpn.runtime.android.RuntimeProductionPlatformOwner", "secretMethod", "RuntimeProductionPlatformOwner.kt", 477)) }
        diagnostic.record(1,6,3,0,15,failure){LongArray(40){-1}}
        diagnostic.record(1,14,6,1,-1,Exception("later")){LongArray(40){-1}}
        diagnostic.record(2,14,6,1,-1,java.util.concurrent.TimeoutException()){LongArray(40){-1}}
        diagnostic.record(2,14,6,7,-1,Exception()){LongArray(40){-1}}
        assertEquals(2,emitted.size)
        val first=emitted[0].removePrefix("DIAG_V1_").split(',').map(String::toLong)
        assertEquals(50,first.size);assertEquals(listOf(1L,1,8,6,3,5,2,477,0,15),first.take(10))
        val cleanup=emitted[1].removePrefix("DIAG_V1_").split(',').map(String::toLong)
        assertEquals(2L,cleanup[1]);assertEquals(2L,cleanup[5]);assertEquals(1L,cleanup[8])
        assertTrue(emitted.all{it.matches(Regex("DIAG_V1_[-0-9,]+"))})
    }
    @Test fun firstFailureDiagnosticBoundsAndUnavailableObservationsCannotAffectExecution() {
        val emitted=mutableListOf<String>();val diagnostic=Task7MaintenanceDiagnosticV1(9,emitted::add)
        diagnostic.record(1,Long.MAX_VALUE,99,99,99,Exception()){error("private observation failed")}
        val values=emitted.single().removePrefix("DIAG_V1_").split(',').map(String::toLong)
        assertEquals(-1L,values[3]);assertEquals(-1L,values[4]);assertEquals(-1L,values[8]);assertEquals(-1L,values[9])
        assertTrue(values.drop(10).all{it==-1L})
        Task7MaintenanceDiagnosticV1(8){error("sink failure")}.record(1,6,3,0,-1,Exception()){LongArray(40){-1}}
        val unavailable=task7MaintenanceDiagnosticObservedV1(false,longArrayOf(1,2,3),8,128,LongArray(16){99},null)
        assertEquals(0L,unavailable[0]);assertTrue(unavailable.drop(1).all{it==-1L})
        val available=task7MaintenanceDiagnosticObservedV1(true,longArrayOf(0,4095,4096),7,127,LongArray(16){-1},null)
        assertEquals(listOf(1L,0,4095,-1,7,127,1,-1),available.take(8))
        assertTrue(available.drop(8).all{it==-1L})
    }
    @Test fun maintainedSequenceCancelsOwnerPublishedAfterCancellationWithoutStartingComponent() {
        val cancelled=AtomicBoolean(false);val sequence=Task7MaintenanceSequenceV1(cancelled)
        val events=mutableListOf<String>()
        assertThrows(IllegalStateException::class.java){
            sequence.run(8,{associated->
                assertTrue(associated);cancelled.set(true)
                sequence.publish({events.add("owner")},{events.add("stop-request")})
                sequence.afterPrerequisite({events.add("prerequisite")},{events.add("component")})
            },{events.add("retire")},{events.add("successor")},{events.add("joined")})
        }
        assertEquals(listOf("owner","stop-request","joined"),events)
        assertTrue(sequence.cleanupProven)
    }
    @Test fun maintainedSequenceFailedNetworkPrerequisiteNeverAcquiresMaintenance() {
        val sequence=Task7MaintenanceSequenceV1(AtomicBoolean(false));val events=mutableListOf<String>()
        assertThrows(IllegalStateException::class.java){
            sequence.run(8,{associated->
                assertTrue(associated);events.add("tun")
                sequence.afterPrerequisite({events.add("network");error("not ready")},{events.add("maintenance")})
            },{events.add("retire")},{events.add("successor")},{events.add("cleanup")})
        }
        assertEquals(listOf("tun","network","cleanup"),events);assertTrue(sequence.cleanupProven)
    }
    @Test fun maintainedSequenceWrongCaseStartsNothingAndDisconnectedNeverStartsSuccessor() {
        val sequence=Task7MaintenanceSequenceV1(AtomicBoolean(false));val events=mutableListOf<String>()
        assertThrows(IllegalArgumentException::class.java){sequence.run(7,{events.add("open")},{events.add("retire")},{events.add("next")},{events.add("cleanup")})}
        assertTrue(events.isEmpty())
        assertTrue(sequence.run(9,{associated->assertFalse(associated);events.add("disconnected")},{events.add("retire")},{error("successor")},{events.add("cleanup")}))
        assertEquals(listOf("disconnected","retire","cleanup"),events)
    }
    @Test fun maintainedSequenceCannotAdmitSuccessorUntilOldCancellationActuallyJoins() {
        val sequence=Task7MaintenanceSequenceV1(AtomicBoolean(false));val cancellation=Task7TunCancellationV1()
        val entered=CountDownLatch(1);val release=CountDownLatch(1);val retire=CountDownLatch(1)
        val successor=AtomicBoolean(false);assertTrue(cancellation.begin())
        val cancelling=Thread{cancellation.complete{entered.countDown();check(release.await(2,TimeUnit.SECONDS))}}.apply{start()}
        assertTrue(entered.await(2,TimeUnit.SECONDS))
        val result=java.util.concurrent.FutureTask{sequence.run(8,{}, {retire.countDown();cancellation.sealAndJoin()}, {successor.set(true)}, {})}
        val runner=Thread(result).apply{start()}
        try {
            assertTrue(retire.await(2,TimeUnit.SECONDS));assertFalse(successor.get());assertFalse(result.isDone)
        }finally{release.countDown();cancelling.join(2000);runner.join(2000)}
        assertTrue(result.get(1,TimeUnit.SECONDS));assertTrue(successor.get());assertFalse(cancellation.begin())
    }
    @Test fun maintainedSequenceFailedOwnerOrWorkerJoinCannotProduceCleanupOrSuccess() {
        for(failure in listOf("owner","worker")) {
            val sequence=Task7MaintenanceSequenceV1(AtomicBoolean(false));var next=false;var finished=false
            val stop=Task7MaintenanceStopV1();val workerDone=CountDownLatch(1)
            val join={
                check(stop.await{failure!="owner"})
                check(workerDone.await(0,TimeUnit.MILLISECONDS))
            }
            assertThrows(IllegalStateException::class.java){
                finished=sequence.run(8,{}, join, {next=true}, join)
            }
            assertFalse(next);assertFalse(finished);assertFalse(sequence.cleanupProven)
        }
    }
    @Test fun maintainedSequenceWaitsForActualOperationWorkerBeforeSuccessorAndFinalSuccess() {
        val sequence=Task7MaintenanceSequenceV1(AtomicBoolean(false))
        val waiting=CountDownLatch(1);val workRelease=CountDownLatch(1);val workDone=CountDownLatch(1)
        val successor=AtomicBoolean(false)
        val operation=Thread{try{check(workRelease.await(2,TimeUnit.SECONDS))}finally{workDone.countDown()}}.apply{start()}
        val join={waiting.countDown();check(workDone.await(2,TimeUnit.SECONDS))}
        val result=java.util.concurrent.FutureTask{sequence.run(8,{},join,{successor.set(true)},join)}
        val runner=Thread(result).apply{start()}
        try {
            assertTrue(waiting.await(2,TimeUnit.SECONDS));assertFalse(successor.get())
            assertFalse(result.isDone);assertFalse(sequence.cleanupProven)
        }finally{workRelease.countDown();operation.join(2000);runner.join(2000)}
        assertTrue(result.get(1,TimeUnit.SECONDS));assertTrue(successor.get());assertTrue(sequence.cleanupProven)
    }
    private fun native(case: Int) = LongArray(24) { -1 }.apply {
        this[0]=1;this[1]=case.toLong();this[2]=1;this[3]=0;this[7]=0;this[17]=0;this[18]=1
        this[19]=0;this[20]=0;this[21]=0;this[22]=1;this[23]=1
        if(case!=3){this[4]=0;this[5]=1;this[6]=320}
        if(case==2){this[8]=13;this[9]=1;this[10]=1;this[11]=1;this[12]=1;this[13]=0;this[14]=0;this[15]=0;this[16]=1}
    }
    @Test fun exactNativeMeasurementRequiresRealCleanupAndChainCause() {
        for(case in 1..3){
            val good=native(case);assertTrue(task7MaintenanceMeasurementV1(good,case))
            for(i in listOf(0,1,2,3,7,17,18,19,20,21,22,23))
                assertFalse(task7MaintenanceMeasurementV1(good.copyOf().also{it[i]=-1},case))
            assertFalse(task7MaintenanceMeasurementV1(good,if(case==3)1 else 3))
            assertFalse(task7MaintenanceMeasurementV1(good.copyOf(25),case))
        }
        for(i in 8..16) assertFalse(task7MaintenanceMeasurementV1(native(2).also{it[i]=-1},2))
        assertFalse(task7MaintenanceMeasurementV1(native(2).also{it[9]=4},2))
        assertFalse(task7MaintenanceMeasurementV1(native(3).also{it[4]=0},3))
    }
    @Test fun pageIsExactClosedAndUnobservedNeverPasses() {
        for(case in 8..11){
            val p=task7InstalledMaintenancePageV1(7,9,1,case)
            assertEquals(72,p.size);assertTrue(task7InstalledMaintenancePageMatchesV1(p,7,9))
            assertFalse(task7InstalledMaintenanceOutcomeV1(p));assertEquals(-1L,p[71])
            assertFalse(task7InstalledMaintenancePageMatchesV1(p.copyOf(73),7,9))
            assertFalse(task7InstalledMaintenancePageMatchesV1(p,8,9))
            for(i in listOf(9,10,11,40,46,47,58,59))
                assertFalse(task7InstalledMaintenancePageMatchesV1(p.copyOf().also{it[i]=2},7,9))
            assertFalse(task7InstalledMaintenancePageMatchesV1(p.copyOf().also{it[71]=0},7,9))
        }
    }
    @Test fun disconnectedOutcomeRequiresEveryIndependentObservationAndUnchangedNativeCopy() {
        val p=task7InstalledMaintenancePageV1(7,9,2,11)
        val measurement=native(2);measurement.copyInto(p,16)
        p[9]=1;p[10]=1;p[11]=1;p[12]=100;p[13]=200;p[14]=15;p[15]=0
        for(i in listOf(40,46,47,51,53,54,58,59))p[i]=1
        p[48]=0;p[49]=1;p[52]=7;p[63]=1
        assertTrue(task7InstalledMaintenancePageMatchesV1(p,7,9));assertTrue(task7InstalledMaintenanceOutcomeV1(p))
        assertArrayEquals(measurement,p.copyOfRange(16,40))
        for(i in listOf(9,10,11,40,46,47,48,49,51,52,53,54,58,59,63))
            assertFalse("missing $i",task7InstalledMaintenanceOutcomeV1(p.copyOf().also{it[i]=-1}))
        assertFalse(task7InstalledMaintenanceOutcomeV1(p.copyOf().also{it[52]=4}))
        assertFalse(task7InstalledMaintenanceOutcomeV1(p.copyOf().also{it[41]=1}))
    }
    @Test fun actualStopWorkerJoinsAndFailedStopCannotHeal() {
        val stop=Task7MaintenanceStopV1();var calls=0
        assertTrue(stop.await{calls++;true});assertTrue(stop.await{calls++;false});assertEquals(1,calls)
        val failed=Task7MaintenanceStopV1()
        assertFalse(failed.await{false});assertFalse(failed.await{true})
    }
    @Test fun pageRejectsCaseInapplicableObservationsBeforeOutcome() {
        for(case in 9..11) for(index in listOf(41,42,43,44,45,50,55,56,57,60,61,64,65,66,67,68,69,70)) {
            val page=task7InstalledMaintenancePageV1(7,9,1,case)
            page[index]=0
            assertFalse("case $case reserved $index",task7InstalledMaintenancePageMatchesV1(page,7,9))
        }
        for(case in 10..11) {
            val page=task7InstalledMaintenancePageV1(7,9,1,case);page[62]=1
            assertFalse(task7InstalledMaintenancePageMatchesV1(page,7,9))
        }
        val associated=task7InstalledMaintenancePageV1(7,9,1,8);associated[63]=0
        assertFalse(task7InstalledMaintenancePageMatchesV1(associated,7,9))
    }
    @Test fun associatedOutcomeRequiresSuccessorRetirementAndOldParentRejection() {
        val page=task7InstalledMaintenancePageV1(7,9,2,8)
        native(3).copyInto(page,16)
        for(i in listOf(9,10,11,40,41,42,43,45,46,47,48,51,53,54,55,56,57,58,59,60,61,62,64,65,68,70))page[i]=1
        page[12]=100;page[13]=200;page[14]=15;page[15]=0;page[44]=0;page[49]=0
        page[52]=7;page[66]=0;page[67]=0;page[69]=7
        assertTrue(task7InstalledMaintenanceOutcomeV1(page))
        for(i in listOf(44,51,52,54,55,56,57,58,59,60,61,64,65,66,67,68,69,70))
            assertFalse("missing $i",task7InstalledMaintenanceOutcomeV1(page.copyOf().also{it[i]=-1}))
        page[49]=1;assertFalse(task7InstalledMaintenanceOutcomeV1(page))
        page[50]=1;assertTrue(task7InstalledMaintenanceOutcomeV1(page))
    }
    @Test fun cancellationCanRequestStopBeforeAcquisitionUnwindsWithoutWaitingOnItself() {
        val stop=Task7MaintenanceStopV1();val entered=CountDownLatch(1);val release=CountDownLatch(1)
        stop.request{entered.countDown();check(release.await(2,TimeUnit.SECONDS));true}
        assertTrue(entered.await(2,TimeUnit.SECONDS));release.countDown()
        assertTrue(stop.await{throw AssertionError("stop retried")})
    }
    @Test fun exhaustedObserverBoundRetainsActualStopWithoutRetry() {
        val stop=Task7MaintenanceStopV1();val entered=CountDownLatch(1);val release=CountDownLatch(1)
        stop.request{entered.countDown();check(release.await(2,TimeUnit.SECONDS));true}
        assertTrue(entered.await(2,TimeUnit.SECONDS))
        try {
            assertThrows(java.util.concurrent.TimeoutException::class.java){stop.await(0){throw AssertionError("retry")}}
        }finally{release.countDown()}
        assertTrue(stop.await{throw AssertionError("stop retried")})
    }
    @Test fun sealedOldCancellationCannotRunAfterSuccessorStarts() {
        val old=Task7TunCancellationV1();val entered=CountDownLatch(1);val release=CountDownLatch(1)
        var successor=false;var oldTouchedSuccessor=false
        assertTrue(old.begin())
        val thread=Thread{old.complete{entered.countDown();check(release.await(2,TimeUnit.SECONDS));oldTouchedSuccessor=successor}}.apply{start()}
        assertTrue(entered.await(2,TimeUnit.SECONDS));release.countDown();old.sealAndJoin();thread.join(2000)
        successor=true;assertFalse(old.begin());assertFalse(oldTouchedSuccessor)
    }
    @Test fun exhaustedCancellationWaitKeepsSealAndAllowsLaterActualJoin() {
        val cancellation=Task7TunCancellationV1()
        assertTrue(cancellation.begin())
        assertThrows(IllegalStateException::class.java){cancellation.sealAndJoin(0)}
        assertFalse(cancellation.begin())
        cancellation.complete{}
        cancellation.sealAndJoin(0)
        assertFalse(cancellation.begin())
    }
}
