// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import java.io.IOException
import java.net.InetAddress
import java.net.DatagramSocket
import java.net.SocketException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.runtime.api.*

class Task7InstalledTunCaseTest {
    @Test fun controlPollTimeoutRetainsOuterDeadlineAndOtherFailures() {
        val timeout = NativeProductResult.Failure(ProductFailureCode.OPERATION_TIMED_OUT)
        val revoked = NativeProductResult.Failure(ProductFailureCode.PROFILE_REVOKED)
        var now = 0L
        var calls = 0
        val result = task7ControlWithinDeadlineV1(40, { now }, { false }) {
            calls++; now += 10
            if (calls == 1) timeout else revoked
        }
        assertSame(revoked, result)
        assertEquals(2, calls)
        calls = 0; now = 0
        val ready = NativeProductResult.Success(NativeControlEvent.TransportReady(1uL, 1uL))
        assertSame(ready, task7ControlWithinDeadlineV1(40, { now }, { false }) {
            calls++; now += 10; if (calls == 1) timeout else ready
        })
        assertEquals(2, calls)
        calls = 0; now = 0
        assertEquals(timeout, task7ControlWithinDeadlineV1(40, { now }, { false }) {
            calls++; now += 10; timeout
        })
        assertEquals(4, calls)
        assertEquals(NativeProductResult.Failure(ProductFailureCode.CANCELLED),
            task7ControlWithinDeadlineV1(40, { 0 }, { true }) { fail("poll after cancellation"); timeout })
    }
    private class BindReadiness {
        var now=0L;var deadline=5000L;var attempts=0;var checks=0;var sourceBinds=0
        val denial=SocketException();val terminal=mutableListOf<Exception>();val records=mutableListOf<String>()
        val calls=mutableListOf<String>();var validate:()->Unit={}
        var bind:()->Unit={throw denial};var wait:(Long)->Unit={now+=it}
        var isEperm:(Exception)->Boolean={it===denial};var onTerminal:(Exception)->Unit={terminal+=it}
        var emit:(String)->Unit={records+=it}
        fun run(){
            task7TunBindReadyV1(1,deadline,{now},{calls+="wait:$it";wait(it)},
                {checks++;calls+="validate";validate()}, {attempts++;calls+="bind";bind()},
                isEperm,onTerminal,emit)
            sourceBinds++
        }
    }
    @Test fun bindReadinessRetriesTransientEpermWithWitnessBeforeAndAfterSuccess() {
        val h=BindReadiness();h.bind={if(h.attempts==1)throw h.denial}
        h.run()
        assertEquals(2,h.attempts);assertEquals(1,h.sourceBinds);assertTrue(h.terminal.isEmpty())
        assertEquals(listOf("validate","bind","validate","wait:10","validate","bind","validate"),h.calls)
        assertEquals(listOf("bind_readiness_substep=1 attempts=2 elapsed_ms=10 outcome=0"),h.records)
    }
    @Test fun bindReadinessPermanentDenialRetainsFirstExceptionAndFiniteCallBound() {
        for(clockAdvances in listOf(true,false)) {
            val h=BindReadiness();if(!clockAdvances)h.wait={}
            h.isEperm={it is SocketException};h.bind={throw if(h.attempts==1)h.denial else SocketException()}
            assertSame(h.denial,assertThrows(SocketException::class.java){h.run()})
            assertEquals(100,h.attempts);assertEquals(0,h.sourceBinds);assertEquals(listOf(h.denial),h.terminal)
            assertEquals(listOf("bind_readiness_substep=1 attempts=100 elapsed_ms=${if(clockAdvances)990 else 0} outcome=1"),h.records)
        }
    }
    @Test fun bindReadinessOtherFailureDoesNotRetryOrChangeException() {
        val h=BindReadiness();val failure=IOException("EPERM text is not authority");h.bind={throw failure}
        assertSame(failure,assertThrows(IOException::class.java){h.run()})
        assertEquals(1,h.attempts);assertEquals(0,h.sourceBinds);assertEquals(listOf(failure),h.terminal)
        assertEquals(listOf("validate","bind"),h.calls)
        assertEquals(listOf("bind_readiness_substep=1 attempts=1 elapsed_ms=0 outcome=2"),h.records)
        assertFalse(task7TunBindIsEpermV1(failure))
        assertFalse(task7TunBindIsEpermV1(SocketException("EPERM").apply{initCause(failure)}))
    }
    @Test fun bindReadinessCancellationAndStaleWitnessCannotAdmitAnotherOperation() {
        for(failAt in 1..4) {
            val h=BindReadiness();val failure=Task7TunFailureV1(7)
            // Covers pre-admission, post-denial, pre-retry and post-success guards.
            h.bind={if(h.attempts==1)throw h.denial}
            h.validate={if(h.checks==failAt)throw failure}
            assertSame(failure,assertThrows(Task7TunFailureV1::class.java){h.run()})
            assertEquals(if(failAt==1)0 else if(failAt==4)2 else 1,h.attempts)
            assertEquals(0,h.sourceBinds);assertTrue(h.terminal.isEmpty())
            assertTrue(h.records.single().endsWith("outcome=3"))
        }
        val h=BindReadiness();val stopped=AtomicBoolean(false)
        val watch=Task7TunNetworkWatchV1<String>(stopped){}
        watch.publish(Task7TunNetworkWitnessV1("selected","tun",InetAddress.getByAddress(byteArrayOf(10,77,0,2))))
        h.validate=watch::requireLive;h.wait={h.now+=it;watch.lost("selected")}
        assertThrows(Task7TunFailureV1::class.java){h.run()}
        assertEquals(1,h.attempts);assertEquals(0,h.sourceBinds)
    }
    @Test fun bindReadinessDeadlinesAndLateSuccessCannotProceed() {
        for(deadline in listOf(0L,15L)) {
            val h=BindReadiness();h.deadline=deadline
            val failure=assertThrows(Task7TunFailureV1::class.java){h.run()}
            assertEquals(2L,failure.kind);assertEquals(if(deadline==0L)0 else 2,h.attempts)
            assertEquals(deadline,h.now);assertEquals(0,h.sourceBinds);assertTrue(h.terminal.isEmpty())
            assertTrue(h.records.single().endsWith("outcome=4"))
        }
        for(elapsed in listOf(1000L,5000L,60001L)) {
            val h=BindReadiness();h.bind={h.now=elapsed}
            assertEquals(2L,assertThrows(Task7TunFailureV1::class.java){h.run()}.kind)
            assertEquals(1,h.attempts);assertEquals(0,h.sourceBinds);assertTrue(h.terminal.isEmpty())
            assertEquals(listOf("bind_readiness_substep=1 attempts=1 elapsed_ms=${if(elapsed<=60000)elapsed else -1} outcome=4"),h.records)
        }
    }
    @Test fun bindReadinessDiagnosticFailureCannotMaskDenialOrSuccess() {
        val denied=BindReadiness();var emissions=0;denied.emit={emissions++;throw IllegalStateException()}
        var terminalEmissions=0;denied.onTerminal={terminalEmissions++;throw IllegalArgumentException()}
        assertSame(denied.denial,assertThrows(SocketException::class.java){denied.run()});assertEquals(1,emissions)
        assertEquals(1,terminalEmissions)
        val admitted=BindReadiness();admitted.bind={};admitted.emit={throw IllegalStateException()}
        admitted.run();assertEquals(1,admitted.attempts);assertEquals(1,admitted.sourceBinds)
    }
    @Test fun bindDiagnosticPreservesBothBoundaryExceptionsAndFirstObservation() {
        for(site in 1..2) {
            val records=mutableListOf<String>();val diagnostic=Task7TunBindDiagnosticV1(records::add)
            val failure=SocketException();var attempts=0
            val observed=assertThrows(SocketException::class.java){diagnostic.run(site){attempts++;throw failure}}
            assertSame(failure,observed);assertEquals(1,attempts)
            assertEquals(listOf("bind_site=$site exception_kind=1 errno_category=-1"),records)
            assertSame(failure,assertThrows(SocketException::class.java){diagnostic.run(site){throw failure}})
            assertEquals(1,records.size)
        }
        val failure=IOException();var emits=0
        val diagnostic=Task7TunBindDiagnosticV1 {emits++;throw IllegalStateException()}
        assertSame(failure,assertThrows(IOException::class.java){diagnostic.run(2){throw failure}})
        assertEquals(1,emits)
        var operations=0;diagnostic.run(1){operations++};assertEquals(1,operations)
    }
    @Test fun bindErrnoCategoriesAreAllowlistedAndCauseTraversalIsBounded() {
        val known=intArrayOf(1,13,64,19,99,98,9,22,97,12,105)
        for(i in known.indices)assertEquals((i+1).toLong(),task7TunBindErrnoCategoryV1(known[i],known))
        assertEquals(-1L,task7TunBindErrnoCategoryV1(9999,known))
        val root=IOException();val one=IOException(root);val two=IOException(one);val three=IOException(two)
        assertEquals(5L,task7TunBindCauseCategoryV1(three){if(it===root)5 else -1})
        assertEquals(-1L,task7TunBindCauseCategoryV1(IOException(three)){if(it===root)5 else -1})
        assertEquals(-1L,task7TunBindCauseCategoryV1(root){9999})
    }
    @Test fun caseSevenDiagnosticUsesOnlyFixedNumericFieldsAndFirstFailure() {
        val records=mutableListOf<String>();val diagnostic=Task7TunDiagnosticV1(records::add)
        diagnostic.failure(2,2,4)
        diagnostic.failure(1,1,1)
        assertEquals(listOf("substep=2 site=2 result=4 position=-1 limit=-1"),records)
        val bufferRecords=mutableListOf<String>()
        Task7TunDiagnosticV1(bufferRecords::add).failure(2,3,0,true,false)
        assertEquals(listOf("substep=2 site=3 result=0 position=1 limit=0"),bufferRecords)
        var attempts=0
        val unavailable=Task7TunDiagnosticV1 {attempts++;throw IllegalStateException()}
        unavailable.failure(2,2,4);unavailable.failure(2,1,4)
        assertEquals(1,attempts)
        for(substep in 1..2)for(site in 1..2)for(result in 0..7) {
            val bounded=mutableListOf<String>()
            Task7TunDiagnosticV1(bounded::add).failure(substep,site,result.toLong())
            assertEquals(listOf("substep=$substep site=$site result=$result position=-1 limit=-1"),bounded)
        }
    }
    @Test fun publishedWitnessRejectsCallbackThreadLossAndIdentityChangeBeforePacketAdmission() {
        val address=InetAddress.getByAddress(byteArrayOf(10,77,0,2))
        for(event in 0..3) {
            val stopped=AtomicBoolean(false);val socket=DatagramSocket(null)
            val watch=Task7TunNetworkWatchV1<String>(stopped) {socket.close()}
            val registered=CountDownLatch(1);val selected=CountDownLatch(1);val delivered=CountDownLatch(1)
            val failure=AtomicReference<Throwable?>()
            val callback=Thread {
                try {
                    registered.countDown();check(selected.await(2,TimeUnit.SECONDS))
                    when(event) {
                        0->watch.lost("selected")
                        1->watch.changed("selected"){it.linkMatches("other",listOf(address))}
                        2->watch.changed("selected"){it.linkMatches("tun",emptyList())}
                        3->watch.changed("selected"){false}
                    }
                } catch(t:Throwable){failure.set(t)} finally{delivered.countDown()}
            }.apply{start()}
            try {
                assertTrue(registered.await(2,TimeUnit.SECONDS))
                watch.publish(Task7TunNetworkWitnessV1("selected","tun",address))
                selected.countDown();assertTrue(delivered.await(2,TimeUnit.SECONDS))
                assertNull(failure.get());assertTrue(stopped.get());assertTrue(socket.isClosed)
                var packetOperations=0
                assertThrows(IllegalStateException::class.java){watch.requireLive();packetOperations++}
                assertEquals(0,packetOperations)
            } finally{selected.countDown();callback.join(2000);socket.close();assertFalse(callback.isAlive)}
        }
    }
    @Test fun publishedWitnessIgnoresUnrelatedAndUnchangedCallbackIdentities() {
        val address=InetAddress.getByAddress(byteArrayOf(10,77,0,2));var terminal=0
        val watch=Task7TunNetworkWatchV1<String>(AtomicBoolean(false)){terminal++}
        watch.lost("unselected")
        watch.publish(Task7TunNetworkWitnessV1("selected","tun",address))
        watch.lost("other");watch.changed("other"){false}
        watch.changed("selected"){it.linkMatches("tun",listOf(address))}
        assertEquals(0,terminal)
        assertThrows(IllegalStateException::class.java){watch.publish(Task7TunNetworkWitnessV1("replacement","tun",address))}
    }
    @Test fun failureSchemaSeparatesDeadlinePacketFixtureAndNativeMismatch() {
        var now=0L
        val timeout=assertThrows(IllegalStateException::class.java){task7TunNextDeliveryV1(5000,{true},{now},{now++}){
            NativeProductResult.Failure(ProductFailureCode.RESOURCE_LIMIT)
        }}
        assertEquals(2L,task7TunFailureClassV1(timeout))
        val native=assertThrows(IllegalStateException::class.java){task7TunNativeValueV1(NativeProductResult.Failure(ProductFailureCode.CANCELLED))}
        assertEquals(3L,task7TunFailureClassV1(native))
        val packet=assertThrows(IllegalStateException::class.java){task7TunRequireV1(false,4)}
        assertEquals(4L,task7TunFailureClassV1(packet))
        val missing=assertThrows(IllegalStateException::class.java){task7TunFixtureValueV1<String>(null)}
        assertEquals(7L,task7TunFailureClassV1(missing))
        assertEquals(5L,task7TunFailureClassV1(IOException()))
        assertEquals(1L,task7TunFailureClassV1(IllegalArgumentException()))
        assertEquals(7L,task7TunFailureClassV1(IllegalStateException()))
    }
    @Test fun packetContractRejectsWrongTupleLengthFragmentAndPayload() {
        val bytes=ByteArray(44).apply {
            this[0]=0x45;this[3]=44;this[6]=0x40;this[8]=64;this[9]=17
            byteArrayOf(10,77,0,2,10,77,0,1).copyInto(this,12)
            this[20]=0xc0.toByte();this[21]=1;this[22]=0x6f;this[23]=0x38;this[25]=24
            byteArrayOf(75,55,84,49,2,1).copyInto(this,28)
        }
        fun accepts(b:ByteArray,n:Int=44)=task7TunPacketMatchesV1(b,n,byteArrayOf(10,77,0,2),byteArrayOf(10,77,0,1),49153,28472,byteArrayOf(75,55,84,49,2,1)+ByteArray(10))
        assertTrue(accepts(bytes));assertFalse(accepts(bytes,43))
        for(i in listOf(0,2,3,6,7,9,12,16,20,21,22,23,24,25,28,32,33,43))
            assertFalse("mutated field $i",accepts(bytes.copyOf().also{it[i]=(it[i].toInt() xor 1).toByte()}))
    }
    @Test fun nextDeliveryRetriesOnlyTransientResourceHandoffWithoutAckRetry() {
        var now=0L;var attempts=0;val delivery=NativePacketDelivery(44,9)
        val result=task7TunNextDeliveryV1(5000,{true},{now},{now++}) {
            if(++attempts<4) NativeProductResult.Failure(ProductFailureCode.RESOURCE_LIMIT) else NativeProductResult.Success(delivery)
        }
        assertEquals(delivery,result);assertEquals(4,attempts);assertEquals(3L,now)
        assertThrows(IllegalStateException::class.java){task7TunNextDeliveryV1(5000,{true},{now},{error("must not wait")}){
            NativeProductResult.Failure(ProductFailureCode.CANCELLED)
        }}
    }
    @Test fun persistentResourceHandoffTimesOutWithinOneSecond() {
        var now=0L;var attempts=0
        assertThrows(IllegalStateException::class.java){task7TunNextDeliveryV1(5000,{true},{now},{now++}){
            attempts++;NativeProductResult.Failure(ProductFailureCode.RESOURCE_LIMIT)
        }}
        assertEquals(1000L,now);assertEquals(1000,attempts)
    }
    @Test fun thrownAdoptionRetainsUnprovenOwnershipWithoutRetry() {
        var adopts=0;var closes=0
        val owner=Task7TunDescriptorV1<Any>({adopts++;throw IOException()},{closes++})
        owner.retainDetached(17)
        assertThrows(IOException::class.java){owner.adoptOnce()}
        assertThrows(IllegalStateException::class.java){owner.adoptOnce()}
        assertThrows(IllegalStateException::class.java){owner.closeOnce()}
        assertEquals(1,adopts);assertEquals(0,closes)
    }
    @Test fun pageTwoRejectsUnobservedSuccess() {
        val page = task7InstalledTunPageV1(7, 9, 1, 2)
        assertEquals(64, page.size)
        assertArrayEquals(longArrayOf(7,9,1,2,1,2,0), page.copyOfRange(0,7))
        assertTrue(page.drop(7).all { it == -1L })
        assertTrue(task7InstalledTunPageMatchesV1(page,7,9))
        assertFalse(task7InstalledTunOutcomeV1(page))
        for (i in listOf(0,1,2,3,5,6)) {
            val bad=page.copyOf();bad[i]=99
            assertFalse(task7InstalledTunPageMatchesV1(bad,7,9))
        }
        for (size in listOf(0,32,40,63,65)) assertFalse(task7InstalledTunPageMatchesV1(page.copyOf(size),7,9))
        assertTrue(page.copyOf().also { it[58]=0 }.let { !task7InstalledTunPageMatchesV1(it,7,9) })
        val qualified=page.copyOf().apply {
            for(i in listOf(8,9,10,11,12,13,16,17,18,20,23,39,40,41,42,43,44,45,55,56,57))this[i]=1
            this[14]=0;this[15]=-1;this[19]=44;this[21]=44;this[22]=1;this[24]=50;this[25]=2
            this[26]=44;this[27]=16;this[28]=0;this[29]=44;this[30]=44;this[31]=16;this[32]=0;this[54]=0
        }
        assertTrue(task7InstalledTunOutcomeV1(qualified))
        for(i in listOf(8,9,10,11,12,13,16,17,18,20,23,39,40,41,42,43,44,45,55,56,57))
            assertFalse(task7InstalledTunOutcomeV1(qualified.copyOf().also{it[i]=-1}))
    }
    @Test fun caseAdmissionOnlyAllowsSixZeroPressureTunCasesAndUnchangedCaseOne() {
        for (case in -1..15) for (level in listOf(-1,0,1,16,32,64,65))
            assertEquals(case==1 && level in listOf(0,16,32,64) || case in 2..14 && level==0,
                task7InstalledCaseAllowedV1(case,level))
    }
    @Test fun conversionUsesAuthenticatedNetworkValuesAndRefusesIncompatibleSelection() {
        val valid=snapshot()
        val config=task7InstalledTunConfigurationV1(valid)
        assertEquals(listOf(LiveIpPrefix("10.0.0.2",32)),config.addresses)
        assertEquals(listOf(LiveIpPrefix("0.0.0.0",0)),config.routes)
        assertEquals(listOf("10.0.0.1"),config.dnsServers)
        assertEquals(1280,config.mtu);assertEquals(VpnRoutingPolicy(),config.routingPolicy)
        assertThrows(IllegalArgumentException::class.java) { task7InstalledTunConfigurationV1(snapshot(udp=false)) }
        assertThrows(IllegalArgumentException::class.java) { task7InstalledTunConfigurationV1(snapshot(perApp=PerAppSelectionMode.EXCLUDE_SELECTED)) }
        assertThrows(IllegalArgumentException::class.java) { task7InstalledTunConfigurationV1(snapshot(ip=IpMode.IPV6_ONLY)) }
        assertThrows(IllegalArgumentException::class.java) { task7InstalledTunConfigurationV1(snapshot(mode=TunnelMode.PROXY_ONLY)) }
        assertThrows(IllegalArgumentException::class.java) { task7InstalledTunConfigurationV1(snapshot(mode=TunnelMode.TUN_PLUS_PROXY)) }
        assertTrue(task7InstalledTunBindingV1(NativeControlEvent.RoutePlanReady(2u,1u,valid),valid))
        assertFalse(task7InstalledTunBindingV1(NativeControlEvent.RoutePlanReady(2u,1u,snapshot(generation=2u)),valid))
        assertFalse(task7InstalledTunBindingV1(NativeControlEvent.RoutePlanReady(2u,1u,snapshot(digest=2)),valid))
    }
    @Test fun fullWritePrecedesExactAck() {
        val calls=mutableListOf<String>()
        val receipt=Task7TunReceiptV1(NativePacketDelivery(44,Long.MIN_VALUE))
        assertEquals(0L,receipt.deliver({calls+="write:44";44},{count->calls+="observed:$count"},
            {calls+="kernel"},{token,count->assertEquals(Long.MIN_VALUE,token);calls+="ack:$count";NativeProductResult.Success(Unit)},
            {error("unexpected reject")}))
        assertEquals(listOf("write:44","observed:44","kernel","ack:44"),calls)
    }
    @Test fun shortZeroAndThrowNeverAckSuccess() {
        for (kind in 0..2) {
            val calls=mutableListOf<String>();val receipt=Task7TunReceiptV1(NativePacketDelivery(44,9))
            assertThrows(Exception::class.java) {
                receipt.deliver({calls+="write";if(kind==2)throw IOException();if(kind==0)43 else 0},
                    {calls+="observed:$it"},{calls+="kernel"},{_,_->calls+="ack";NativeProductResult.Success(Unit)},
                    {calls+="reject";NativeProductResult.Failure(ProductFailureCode.CANCELLED)})
            }
            assertFalse(calls.contains("ack"));assertFalse(calls.contains("kernel"));assertEquals(1,calls.count{it=="write"})
            assertEquals("reject",calls.last())
        }
    }
    @Test fun wrongTokenNeverRecoversOnSameParent() {
        for(token in listOf(1L,2L,Long.MIN_VALUE,Long.MAX_VALUE)) {
            val receipt=Task7TunReceiptV1(NativePacketDelivery(44,token));val calls=mutableListOf<Long>()
            assertEquals(3L,receipt.wrongToken {wrong,length->assertNotEquals(token,wrong);assertTrue(wrong!=0L);assertEquals(44,length);calls+=wrong;NativeProductResult.Failure(ProductFailureCode.OPERATION_INTERRUPTED)})
            assertThrows(IllegalStateException::class.java){receipt.wrongToken {_,_->error("second call")}}
            assertEquals(1,calls.size)
        }
    }
    @Test fun withheldReceiptCancelClosesBeforeJoin() {
        val calls=mutableListOf<String>();val lifetime=Task7TunCancellationV1()
        assertTrue(lifetime.begin())
        lifetime.complete { calls+="generator-close";calls+="consumer-signal";calls+="owner-stop";calls+="relay-cancel" }
        lifetime.sealAndJoin();calls+="join"
        assertEquals(listOf("generator-close","consumer-signal","owner-stop","relay-cancel","join"),calls)
    }
    @Test fun staleOwnerCannotReachNextSubstep() {
        val lifetime=Task7TunCancellationV1();val entered=CountDownLatch(1);val release=CountDownLatch(1)
        assertTrue(lifetime.begin())
        val thread=Thread { lifetime.complete {entered.countDown();check(release.await(2,TimeUnit.SECONDS))} }.apply{start()}
        assertTrue(entered.await(2,TimeUnit.SECONDS));release.countDown();lifetime.sealAndJoin();thread.join(2000)
        assertFalse(lifetime.begin())
    }
    @Test fun unprovenCloseKeepsAdmission() {
        val lifetime=Task7TunCancellationV1();assertTrue(lifetime.begin())
        assertThrows(IOException::class.java){lifetime.complete {throw IOException()}}
        assertThrows(IllegalStateException::class.java){lifetime.sealAndJoin()}
        assertFalse(lifetime.begin())
    }
    private fun snapshot(generation:ULong=1u,digest:Byte=1,udp:Boolean=true,perApp:PerAppSelectionMode=PerAppSelectionMode.ALL_APPS,
        ip:IpMode=IpMode.IPV4_ONLY,mode:TunnelMode=TunnelMode.TUN_ONLY):NativeOpeningSnapshot {
        val raw=mode!=TunnelMode.PROXY_ONLY;val proxy=mode!=TunnelMode.TUN_ONLY
        val capabilities=buildSet {if(raw)add(NativeCapability.RAW_IP);if(proxy)add(NativeCapability.PROXY_STREAM)}
        return NativeOpeningSnapshot(
        generation,ByteArray(32){digest},ByteArray(16){2},ByteArray(16){3},ByteArray(16){4},null,null,null,
        ExitRegion.UNKNOWN,mode,ip,ResolverPolicy.INTERNAL,1280,false,perApp,0,
        if(raw&&ip==IpMode.IPV4_ONLY)NumericAddress("10.0.0.2") else null,
        if(raw&&ip==IpMode.IPV6_ONLY)NumericAddress("fd00::2") else null,
        if(raw)listOf(NumericAddress(if(ip==IpMode.IPV4_ONLY)"10.0.0.1" else "fd00::1")) else emptyList(),
        if(raw)listOf(CanonicalRoute(if(ip==IpMode.IPV4_ONLY)"0.0.0.0/0" else "::/0")) else emptyList(),
        NativeCapabilities(capabilities,capabilities,capabilities),
        NativePacketLimits(1280,1,1,setOf(if(udp)NativePayloadProtocol.UDP else NativePayloadProtocol.TCP)),
        NativeReconnectLimits(1,10,1,1,0,1000,300000),
        if(proxy)NativeProxyLimits(1,1,1,1,1,16777216,16777216,30,1000,1024,1024) else null,null,null,
        NativeResourceLimits(if(raw)NativeRawFlowStatus.ENFORCED_FORWARDING_LEASES else NativeRawFlowStatus.NOT_APPLICABLE,
            if(raw)4096 else 0,if(raw)2048 else 0,if(raw)256 else 0,if(raw)128 else 0,if(raw)300000 else 0,
            NativeSignedRawFlowCapStatus.NOT_SEPARATELY_SPECIFIED,134217728,83886080,if(raw)1048576 else 0))
    }
}
