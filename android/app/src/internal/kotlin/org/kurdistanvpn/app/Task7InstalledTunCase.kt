// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.net.*
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.File
import java.io.FileDescriptor
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.net.SocketException
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.core.nativejni.Task7InstalledFixtureNative
import org.kurdistanvpn.runtime.android.*
import org.kurdistanvpn.runtime.api.*

internal fun task7TunBindErrnoCategoryV1(errno:Int,known:IntArray):Long =
    known.indexOf(errno).let {if(it in 0..10)it.toLong()+1 else -1}
internal fun task7TunBindCauseCategoryV1(failure:Throwable,category:(Throwable)->Long):Long {
    var current:Throwable?=failure
    repeat(4) {
        val observed=current ?: return -1
        val value=category(observed)
        if(value in 1..11)return value
        if(it<3)current=observed.cause
    }
    return -1
}
internal fun task7TunBindIsEpermV1(failure:Throwable):Boolean = task7TunBindCauseCategoryV1(failure) {
    if(it is ErrnoException && it.errno==OsConstants.EPERM)1 else -1
}==1L

/** Fixture-only netd readiness: no traffic or authority change before exact-network admission. */
internal fun task7TunBindReadyV1(substep:Int,deadline:Long,now:()->Long,wait:(Long)->Unit,
    validate:()->Unit,bind:()->Unit,isEperm:(Exception)->Boolean=::task7TunBindIsEpermV1,
    terminal:(Exception)->Unit,emit:(String)->Unit) {
    require(substep in 1..2)
    val started=now();val until=minOf(deadline,started+1000)
    var attempts=0;var outcome=3;var firstDenial:Exception?=null
    fun guard() {
        try {validate()} catch(failure:Exception) {
            outcome=if(failure is Task7TunFailureV1 && failure.kind==2L)4 else 3
            throw failure
        }
        if(now()>=deadline){outcome=4;throw Task7TunFailureV1(2)}
    }
    fun denied():Nothing {
        outcome=1
        val failure=checkNotNull(firstDenial)
        runCatching {terminal(failure)}
        throw failure
    }
    try {
        while(true) {
            guard()
            if(now()>=until || attempts>=100) {
                if(firstDenial!=null)denied()
                outcome=4;throw Task7TunFailureV1(2)
            }
            attempts++
            try {bind()} catch(failure:Exception) {
                if(!isEperm(failure)) {
                    outcome=2;runCatching {terminal(failure)};throw failure
                }
                if(firstDenial==null)firstDenial=failure
                guard()
                if(now()>=until || attempts>=100)denied()
                wait(minOf(10,until-now()).coerceAtLeast(0))
                continue
            }
            guard()
            if(now()>=until){outcome=4;throw Task7TunFailureV1(2)}
            outcome=0
            return
        }
    } finally {
        runCatching {
            val elapsed=now()-started
            emit("bind_readiness_substep=$substep attempts=$attempts elapsed_ms=${if(elapsed in 0..60000)elapsed else -1} outcome=$outcome")
        }
    }
}
/** One bounded bind failure observation; the identical operation exception is rethrown. */
internal class Task7TunBindDiagnosticV1(private val emit:(String)->Unit) {
    private val emitted=AtomicBoolean(false)
    fun run(site:Int,operation:()->Unit) {
        require(site in 1..2)
        try {operation()} catch(failure:Exception) {
            if(emitted.compareAndSet(false,true))runCatching {
                val kind=when(failure){is SocketException->1;is ErrnoException->2;is IOException->3;else->-1}
                val category=task7TunBindCauseCategoryV1(failure) {
                    if(it is ErrnoException)task7TunBindErrnoCategoryV1(it.errno,intArrayOf(
                        OsConstants.EPERM,OsConstants.EACCES,64 /* Linux ENONET, public Android constant only from API31. */,OsConstants.ENODEV,
                        OsConstants.EADDRNOTAVAIL,OsConstants.EADDRINUSE,OsConstants.EBADF,OsConstants.EINVAL,
                        OsConstants.EAFNOSUPPORT,OsConstants.ENOMEM,OsConstants.ENOBUFS)) else -1
                }
                emit("bind_site=$site exception_kind=$kind errno_category=$category")
            }
            throw failure
        }
    }
}

/** Fixed case7 failure evidence only; never emits values from native/platform objects. */
internal class Task7TunDiagnosticV1(private val emit:(String)->Unit) {
    private val emitted=AtomicBoolean(false)
    fun failure(substep:Int,site:Int,result:Long,position:Boolean?=null,limit:Boolean?=null) {
        require(substep in 1..2 && site in 1..3 && result in 0..7)
        require(if(site==3)position!=null && limit!=null else position==null && limit==null)
        fun predicate(value:Boolean?)=when(value){null->-1;false->0;true->1}
        if(emitted.compareAndSet(false,true))
            runCatching { emit("substep=$substep site=$site result=$result position=${predicate(position)} limit=${predicate(limit)}") }
    }
}

internal class Task7TunFailureV1(val kind:Long):IllegalStateException() {
    init { require(kind in 1..7) }
}
internal fun task7TunRequireV1(condition:Boolean,kind:Long) { if(!condition)throw Task7TunFailureV1(kind) }

internal fun task7TunPollIoV1(fd:FileDescriptor,bytes:ByteArray,count:Int,writing:Boolean,until:Long,checkLive:()->Unit):Int {
    require(count in 1..bytes.size)
    while(true){checkLive();task7TunRequireV1(SystemClock.elapsedRealtime()<until,2)
        try {
            val poll=StructPollfd().apply{this.fd=fd;events=(if(writing)OsConstants.POLLOUT else OsConstants.POLLIN).toShort()}
            if(Os.poll(arrayOf(poll),minOf(100,until-SystemClock.elapsedRealtime()).coerceAtLeast(1).toInt())==0)continue
            task7TunRequireV1(poll.revents.toInt() and OsConstants.POLLNVAL==0,5)
            return if(writing)Os.write(fd,bytes,0,count) else Os.read(fd,bytes,0,count)
        }catch(failure:ErrnoException){if(failure.errno!=OsConstants.EINTR && failure.errno!=OsConstants.EAGAIN)throw failure}
    }
}
internal fun <T:Any> task7TunFixtureValueV1(value:T?):T = value ?: throw Task7TunFailureV1(7)
internal fun <T> task7TunNativeValueV1(result:NativeProductResult<T>):T = when(result) {
    is NativeProductResult.Success->result.value
    is NativeProductResult.Failure->throw Task7TunFailureV1(3)
}
internal fun task7TunFailureClassV1(failure:Exception):Long = when(failure) {
    is Task7TunFailureV1->failure.kind
    is SocketTimeoutException->2
    is ErrnoException,is IOException->5
    is IllegalArgumentException->1
    else->7 // An unclassified missing fixture observation is not native-result evidence.
}
internal data class Task7TunNetworkWitnessV1<N:Any>(val network:N,val name:String,val address:InetAddress) {
    fun linkMatches(name:String?,addresses:List<InetAddress>):Boolean = this.name==name && address in addresses
}
/** One worker publishes a complete immutable identity after callback registration. */
internal class Task7TunNetworkWatchV1<N:Any>(private val stopped:AtomicBoolean,private val closeSocket:()->Unit) {
    @Volatile var selected:Task7TunNetworkWitnessV1<N>?=null
        private set
    fun publish(witness:Task7TunNetworkWitnessV1<N>){check(selected==null);selected=witness}
    fun lost(network:N)=changed(network){false}
    fun changed(network:N,valid:(Task7TunNetworkWitnessV1<N>)->Boolean){
        val retained=selected ?: return
        if(retained.network==network && !valid(retained)){stopped.set(true);closeSocket()}
    }
    fun requireLive(){task7TunRequireV1(!stopped.get(),7)}
}

internal fun task7InstalledCaseAllowedV1(case: Int, level: Int): Boolean =
    (case == 1 || case in 301..304) && level in setOf(0,16,32,64) || case in 2..14 && level == 0

internal fun task7TunPacketMatchesV1(b:ByteArray,n:Int,source:ByteArray,destination:ByteArray,
    sourcePort:Int,destinationPort:Int,payload:ByteArray):Boolean {
    if(n!=44 || b.size<n || source.size!=4 || destination.size!=4 || payload.size!=16 || b[0]!=0x45.toByte() ||
        b[2]!=0.toByte() || b[3]!=44.toByte() || b[9]!=17.toByte())return false
    fun word(i:Int)=((b[i].toInt() and 255) shl 8) or (b[i+1].toInt() and 255)
    return word(6) and 0xbfff==0 && (0..3).all{b[12+it]==source[it] && b[16+it]==destination[it]} &&
        word(20)==sourcePort && word(22)==destinationPort && word(24)==24 && payload.indices.all{b[28+it]==payload[it]}
}

internal fun task7InstalledTunPageV1(epoch: Long, sequence: Long, state: Long, case: Int) = LongArray(64) { -1 }.also {
    require(case in 2..7)
    it[0]=epoch;it[1]=sequence;it[2]=1;it[3]=2;it[4]=state;it[5]=case.toLong();it[6]=0
}
internal fun task7InstalledTunPageMatchesV1(page: LongArray, epoch: Long, sequence: Long): Boolean =
    page.size == 64 && page[0] == epoch && page[1] == sequence && page[2] == 1L && page[3] == 2L &&
        page[5] in 2..7 && page[6] == 0L && (58..63).all { page[it] == -1L }

internal fun task7InstalledTunOutcomeV1(p: LongArray): Boolean {
    if (p.size != 64 || p[8] != 1L || p[9] != 1L || p[54] != 0L) return false
    if (listOf(10,11,12,13,16,17,18,20,39,40,41,42,43,44,45).any { p[it] != 1L }) return false
    if (!(p[14] == 0L && p[15] == -1L || p[14] == 1L && p[15] == 1L) || p[19] != 44L || p[21] != 44L) return false
    return when (p[5]) {
        2L -> p[22]==1L && p[23]==1L && p[24]>=50 && p[25]==2L && p[26]==44L && p[27]==16L && p[28]==0L &&
            p[29]==44L && p[30]==44L && p[31]==16L && p[32]==0L && p[55]==1L && p[56]==1L && p[57]==1L
        3L -> p[33]==3L && p[55]==1L && p[26]==-1L
        4L -> p[26]==43L && p[34]==3L && p[55]==1L
        5L -> p[35] in 1..3 && p[36]==4L && p[55]==1L && p[28]==-1L
        6L -> p[37]==1L && p[38]==1L && p[28]==-1L
        7L -> p[46]==4L && p[47]==1L && p[48]==1L && p[49]==1L && p[50]==1L
        else -> false
    }
}
internal fun task7InstalledTunConfigurationV1(s: NativeOpeningSnapshot): LiveTunConfiguration {
    require(s.effectiveMode==TunnelMode.TUN_ONLY && s.effectiveIp==IpMode.IPV4_ONLY &&
        NativeCapability.RAW_IP in s.capabilities.effective && NativePayloadProtocol.UDP in s.packetLimits.payloadProtocols &&
        s.perAppMode==PerAppSelectionMode.ALL_APPS && s.effectivePackageCount==0 && s.clientV4!=null && s.clientV6==null &&
        s.dnsAddresses.size==1 && ':' !in s.dnsAddresses.single().value && s.routes.map{it.value}==listOf("0.0.0.0/0") &&
        s.packetLimits.packetMax==s.effectiveMtu)
    return LiveTunConfiguration(listOf(LiveIpPrefix(s.clientV4!!.value,32)),s.routes.map {
        LiveIpPrefix(it.value.substringBeforeLast('/'),it.value.substringAfterLast('/').toInt())
    },s.dnsAddresses.map{it.value},s.effectiveMtu,s.metered,VpnRoutingPolicy().validate())
}
internal fun task7InstalledTunBindingV1(event: NativeControlEvent.RoutePlanReady, opening: NativeOpeningSnapshot): Boolean {
    val s=event.snapshot
    return event.connectionGeneration>0u && s.profileGeneration==opening.profileGeneration && s.planDigest.contentEquals(opening.planDigest) &&
        task7InstalledTunConfigurationV1(s)==task7InstalledTunConfigurationV1(opening) && s.effectiveDnsMode==opening.effectiveDnsMode &&
        s.packetLimits==opening.packetLimits
}
internal fun task7TunResultV1(result: NativeProductResult<*>): Long = when(result) {
    is NativeProductResult.Success -> 0
    is NativeProductResult.Failure -> when(result.code) {
        ProductFailureCode.SIZE_LIMIT -> 1
        ProductFailureCode.RESOURCE_LIMIT -> 2
        ProductFailureCode.OPERATION_INTERRUPTED -> 3
        ProductFailureCode.CANCELLED -> 4
        ProductFailureCode.NETWORK_UNAVAILABLE -> 5
        ProductFailureCode.OPERATION_TIMED_OUT -> 6
        else -> 7
    }
}
internal fun task7TunNextDeliveryV1(deadline:Long,live:()->Boolean,now:()->Long,wait:()->Unit,
    receive:()->NativeProductResult<NativePacketDelivery>):NativePacketDelivery {
    val until=minOf(deadline,now()+1000)
    while(true){
        task7TunRequireV1(live(),7);task7TunRequireV1(now()<until,2)
        when(val result=receive()){
            is NativeProductResult.Success->{task7TunRequireV1(live(),7);task7TunRequireV1(now()<=until,2);return result.value}
            is NativeProductResult.Failure->{task7TunRequireV1(result.code==ProductFailureCode.RESOURCE_LIMIT,3);wait()}
        }
    }
}
internal class Task7TunReceiptV1(val delivery: NativePacketDelivery) {
    private var retired=false
    fun deliver(write:()->Int, observed:(Int)->Unit, kernel:()->Unit,
        ack:(Long,Int)->NativeProductResult<Unit>, reject:(Long)->NativeProductResult<Unit>):Long {
        check(!retired);retired=true
        try {
            val n=write();observed(n);task7TunRequireV1(n==delivery.length,5)
            kernel()
        } catch(failure:Exception) { reject(delivery.token);throw failure }
        return task7TunResultV1(ack(delivery.token,delivery.length))
    }
    fun wrongToken(ack:(Long,Int)->NativeProductResult<Unit>):Long {
        check(!retired);retired=true
        return task7TunResultV1(ack(if(delivery.token!=1L)1L else 2L,delivery.length))
    }
}
/** Seal/join is also the barrier preventing an old cancel from reaching a new relay. */
internal class Task7TunCancellationV1 {
    private val lock=Any();private var sealed=false;private var started=false
    private val admitted=CountDownLatch(1)
    private val done=CountDownLatch(1);@Volatile private var clean=false
    fun begin():Boolean=synchronized(lock) {if(sealed||started)false else {started=true;admitted.countDown();true}}
    fun awaitAndSeal(){check(admitted.await(5,TimeUnit.SECONDS));sealAndJoin()}
    fun complete(work:()->Unit) {try{work();clean=true}finally{done.countDown()}}
    fun sealAndJoin(timeoutMillis:Long=5000) {
        val pending=synchronized(lock){sealed=true;started}
        if(pending)check(done.await(timeoutMillis.coerceIn(0,5000),TimeUnit.MILLISECONDS)&&clean)
    }
}
/** Failed adoption retains the detached integer. No second adoption or uncertain close retry. */
internal class Task7TunDescriptorV1<T:Any>(private val adopt:(Int)->T,private val close:(T)->Unit) {
    private var raw=-1;private var attempted=false;private var closeAttempted=false
    private var value:T?=null;private var unproven=false
    fun retainDetached(fd:Int){check(raw == -1 && !attempted && fd>=0);raw=fd}
    fun adoptOnce():T {check(!attempted && raw>=0);attempted=true
        try{return adopt(raw).also{value=it;raw=-1}}catch(f:Throwable){unproven=true;throw f}}
    fun closeOnce(){check(!unproven && raw == -1);if(closeAttempted)return;closeAttempted=true
        try{value?.let(close);value=null}catch(f:Throwable){unproven=true;throw f}}
}

/** Runs on the existing case worker. It is the sole consumer of the detached original. */
internal class Task7InstalledTunCase(
    private val service: Task7InstalledDriverService, private val case: Int,
    private val native: Task7InstalledFixtureNative, private val cancelled: AtomicBoolean,
    private val monitor: Any, private val page: LongArray, private val deadline: Long,
    private val ownerChanged: (RuntimeProductionPlatformOwner) -> Unit,
) {
    private val connectivity=service.getSystemService(ConnectivityManager::class.java)
    private val diagnostic=Task7TunDiagnosticV1 { android.util.Log.i("Task7Tun",it) }
    private val bindDiagnostic=Task7TunBindDiagnosticV1 { android.util.Log.i("Task7Tun",it) }
    @Volatile private var step: Step?=null
    @Volatile var cleanupProven=false; private set
    private fun put(i:Int,v:Long)=synchronized(monitor){page[i]=v}
    private fun stage(v:Long){put(7,v)}
    private fun live(){task7TunRequireV1(!cancelled.get(),7);task7TunRequireV1(SystemClock.elapsedRealtime()<deadline,2)}
    private fun expect(result:NativeProductResult<*>,slot:Int,code:Long){val observed=task7TunResultV1(result);put(slot,observed);task7TunRequireV1(observed==code,3)}
    private fun proof(owner:RuntimeProductionPlatformOwner):Any = try {
        task7TunFixtureValueV1(owner.javaClass.getDeclaredField("proof").apply{isAccessible=true}.get(owner))
    } catch(_:Exception){throw Task7TunFailureV1(7)}
    private fun name(proof:Any):String? = try {
        proof.javaClass.getDeclaredMethod("interfaceName").apply{isAccessible=true}.invoke(proof) as String?
    } catch(_:Exception){throw Task7TunFailureV1(7)}
    private fun address(s:String)=InetAddress.getByAddress(s.split('.').map{it.toInt().toByte()}.toByteArray())
    private fun payload(response:Boolean,sequence:Int)=ByteArray(16).also {
        (if(response)"K7R1" else "K7T1").toByteArray(Charsets.US_ASCII).copyInto(it)
        it[4]=case.toByte();it[5]=sequence.toByte()
    }
    private inner class Step(val substep:Int=1) {
        @Volatile var owner:RuntimeProductionPlatformOwner?=null
        var session:ProductionNativeSession?=null
        var route:NativeControlEvent.RoutePlanReady?=null
        var proof:Any?=null
        var tunName:String?=null
        var assigned:InetAddress?=null
        var dns:InetAddress?=null
        @Volatile var generator:DatagramSocket?=null
        val stopped=AtomicBoolean(false)
        val networkWatch=Task7TunNetworkWatchV1<Network>(stopped){generator?.close()}
        val cancellation=Task7TunCancellationV1()
        val original=Task7TunDescriptorV1(ParcelFileDescriptor::adoptFd,ParcelFileDescriptor::close)
        var descriptor:FileDescriptor?=null
        var callbackOwned=false
        var nativeStarted=false
        var nativeFinished=false
        var idle=false
        var closed=false
        var detachUnproven=false
        val callback=object:ConnectivityManager.NetworkCallback(){
            override fun onLost(n:Network){networkWatch.lost(n)}
            override fun onCapabilitiesChanged(n:Network,c:NetworkCapabilities){
                networkWatch.changed(n){c.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && (Build.VERSION.SDK_INT<30 || c.ownerUid==Process.myUid())}
            }
            override fun onLinkPropertiesChanged(n:Network,p:LinkProperties){
                networkWatch.changed(n){it.linkMatches(p.interfaceName,p.linkAddresses.map{link->link.address})}
            }
        }
        fun checkLive(){live();networkWatch.requireLive()}
        fun cancel(){
            if(!cancellation.begin())return
            cancellation.complete {
                put(37,1);generator?.close();stopped.set(true)
                try {if(owner?.stop(RuntimeStopReason.CANCEL)==RuntimeStartDecision.Idle){idle=true;put(45,1)}}
                finally {native.cancel()}
            }
        }
        fun closeOriginal(){check(!detachUnproven);original.closeOnce();if(descriptor!=null)put(39,1)}
        fun closeAll(){
            if(closed)return
            stage(19);var clean=true
            fun attempt(work:()->Unit){try{work()}catch(_:Exception){clean=false}}
            stopped.set(true)
            attempt{generator?.let{it.close();check(it.isClosed);put(40,1)}}
            attempt{closeOriginal()}
            attempt{if(callbackOwned){connectivity.unregisterNetworkCallback(callback);callbackOwned=false;put(41,1)}}
            attempt{cancellation.sealAndJoin();if(cancelled.get())put(38,1)}
            attempt{stage(16);if(owner?.stop(RuntimeStopReason.STOP)==RuntimeStartDecision.Idle)idle=true;check(idle);put(45,1)}
            if(nativeStarted && !nativeFinished)attempt{
                native.cancel()
                val until=SystemClock.elapsedRealtime()+5000
                while(native.snapshot()[11]!=1L && SystemClock.elapsedRealtime()<until)SystemClock.sleep(10)
                val joined=native.snapshot()[11];put(42,joined);check(joined==1L)
                check(clean);check(native.finish()==0);nativeFinished=true;put(43,1)
                val after=native.snapshot();check(after[0]==0L && after[2]==0L);put(44,1)
            }
            check(clean);closed=true
        }
    }
    fun cancel(){step?.cancel()}
    fun run(firstOwner:RuntimeProductionPlatformOwner,first:ProductionNativeSession,route:NativeControlEvent.RoutePlanReady){
        put(52,SystemClock.elapsedRealtime());put(54,0)
        val initial=Step().also{it.owner=firstOwner;it.session=first;it.route=route;it.nativeStarted=true;step=it}
        var expected=false
        try {
            prepare(initial)
            val held=exchangeStart(initial,case==2)
            when(case){
                2->{
                    stage(10);val since=SystemClock.elapsedRealtime();SystemClock.sleep(50);put(24,SystemClock.elapsedRealtime()-since)
                    expect(first.receiveInboundPacket(inbound),25,2);absent(initial)
                    deliver(initial,held,1)
                    stage(14);val second=receive(initial,true);put(29,second.length.toLong());deliver(initial,second,2)
                }
                3->{stage(13);put(33,Task7TunReceiptV1(held).wrongToken(first::confirmInboundDelivery));task7TunRequireV1(synchronized(monitor){page[33]}==3L,3);absent(initial)}
                4->{
                    stage(11)
                    try {val n=write(initial,held.length-1);put(26,n.toLong());task7TunRequireV1(n==43,5)}
                    catch(failure:Exception){first.rejectInboundDelivery(held.token);throw failure}
                    absent(initial);stage(13);expect(first.confirmInboundDelivery(held.token,43),34,3)
                }
                5->{
                    initial.closeOriginal();stage(11)
                    var failed=false
                    try{Os.write(checkNotNull(initial.descriptor),outBytes,0,held.length)}catch(failure:Exception){
                        failed=true;put(35,when(failure){is ErrnoException->1L;is IOException->2L;else->3L})
                    }
                    task7TunRequireV1(failed,5);expect(first.rejectInboundDelivery(held.token),36,4);absent(initial)
                }
                6->{
                    stage(15)
                    while(!cancelled.get() && SystemClock.elapsedRealtime()<deadline)SystemClock.sleep(10)
                    task7TunRequireV1(cancelled.get(),2);initial.cancellation.awaitAndSeal()
                    // The typed closed parent, not a fabricated token, must reject the withheld receipt.
                    task7TunRequireV1(task7TunResultV1(first.confirmInboundDelivery(held.token,held.length))==4L,3)
                }
                7->{
                    val oldToken=firstOwner.startToken();val oldProof=checkNotNull(initial.proof)
                    initial.closeAll();stage(17);task7TunRequireV1(name(oldProof)==null,7);put(47,1)
                    live();val next=Step(2).also{step=it};stage(18);openNext(next)
                    task7TunRequireV1(checkNotNull(next.owner).startToken()!=oldToken,1);put(48,1)
                    prepare(next);expect(first.confirmInboundDelivery(held.token,held.length),46,4)
                    val fresh=exchangeStart(next,false);deliver(next,fresh,1)
                    val second=receive(next,true);deliver(next,second,2);put(49,1)
                    next.closeAll();put(50,1)
                }
                else->error("TASK7_TUN_CASE_REJECTED")
            }
            expected=true
        } catch(failure:Exception){
            if(!cancelled.get())put(54,task7TunFailureClassV1(failure))
            throw failure
        } finally {
            try{checkNotNull(step).closeAll();cleanupProven=true;put(9,1)}
            catch(failure:Exception){put(9,0);put(54,6);throw failure}
            finally{put(8,if(expected)1 else 0);put(53,SystemClock.elapsedRealtime());stage(20)}
        }
        check(synchronized(monitor){task7InstalledTunOutcomeV1(page)})
    }
    private var inBytes=ByteArray(0)
    private var outBytes=ByteArray(0)
    private var outbound=ByteBuffer.allocateDirect(0)
    private var inbound=ByteBuffer.allocateDirect(0)
    private fun prepare(s:Step){
        s.checkLive();stage(2)
        val parent=checkNotNull(s.session);val route=checkNotNull(s.route)
        task7TunRequireV1(task7InstalledTunBindingV1(route,parent.openingSnapshot),1);put(16,1)
        val token=checkNotNull(s.owner).startToken();task7TunRequireV1(route.connectionGeneration>0u && token.generation>0,1);put(17,1)
        val config=task7InstalledTunConfigurationV1(route.snapshot)
        inBytes=ByteArray(config.mtu);outBytes=ByteArray(config.mtu)
        outbound=ByteBuffer.allocateDirect(config.mtu+8).apply{position(4);limit(4+config.mtu)}
        inbound=ByteBuffer.allocateDirect(config.mtu+8).apply{position(4);limit(4+config.mtu)}
        stage(3)
        val established=checkNotNull(s.owner).establishTun(config,blocking=false);put(10,1)
        // Step and descriptor owner are retained before establish/detach. Record
        // the returned integer before any PFD wrapper allocation can throw.
        s.detachUnproven=true
        s.original.retainDetached(established.detachFileDescriptor())
        s.detachUnproven=false
        val pfd=s.original.adoptOnce();put(11,1);s.descriptor=pfd.fileDescriptor
        s.proof=proof(checkNotNull(s.owner));s.tunName=task7TunFixtureValueV1(name(checkNotNull(s.proof)));put(12,1)
        s.assigned=address(checkNotNull(route.snapshot.clientV4).value);s.dns=address(route.snapshot.dnsAddresses.single().value)
        stage(4)
        val builder=NetworkRequest.Builder()
        if(Build.VERSION.SDK_INT>=30)builder.clearCapabilities() else builder.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED).removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        s.callbackOwned=true;connectivity.registerNetworkCallback(builder.build(),s.callback)
        val until=minOf(deadline,SystemClock.elapsedRealtime()+5000)
        while(s.networkWatch.selected==null && SystemClock.elapsedRealtime()<until){
            s.checkLive()
            @Suppress("DEPRECATION") // Required API 26-compatible bounded visible-network scan.
            val matches=connectivity.allNetworks.filter {n->
                val c=connectivity.getNetworkCapabilities(n);val p=connectivity.getLinkProperties(n)
                c?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true && p!=null && p.interfaceName==s.tunName && p.linkAddresses.any{it.address==s.assigned}
            }
            task7TunRequireV1(matches.size<=1,7)
            if(matches.size==1)s.networkWatch.publish(Task7TunNetworkWitnessV1(matches.single(),checkNotNull(s.tunName),checkNotNull(s.assigned)))
            else SystemClock.sleep(10)
        }
        witness(s);put(13,1)
        val selected=task7TunFixtureValueV1(s.networkWatch.selected)
        if(Build.VERSION.SDK_INT>=30){put(14,1);task7TunRequireV1(connectivity.getNetworkCapabilities(selected.network)?.ownerUid==Process.myUid(),7);put(15,1)}else put(14,0)
        stage(5);val socket=DatagramSocket(null);s.generator=socket
        s.checkLive()
        task7TunBindReadyV1(s.substep,deadline,SystemClock::elapsedRealtime,SystemClock::sleep,
            {witness(s)}, {selected.network.bindSocket(socket)},
            terminal={failure->bindDiagnostic.run(1){throw failure}},emit={android.util.Log.i("Task7Tun",it)})
        bindDiagnostic.run(2){socket.bind(InetSocketAddress(selected.address,0))};put(18,1)
    }
    private fun witness(s:Step){
        s.checkLive();val selected=task7TunFixtureValueV1(s.networkWatch.selected)
        task7TunRequireV1(name(checkNotNull(s.proof))==selected.name,7)
        val c=task7TunFixtureValueV1(connectivity.getNetworkCapabilities(selected.network))
        val p=task7TunFixtureValueV1(connectivity.getLinkProperties(selected.network))
        task7TunRequireV1(c.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && selected.linkMatches(p.interfaceName,p.linkAddresses.map{it.address}),7)
        if(Build.VERSION.SDK_INT>=30)task7TunRequireV1(c.ownerUid==Process.myUid(),7)
        s.checkLive()
    }
    private fun io(s:Step,writing:Boolean,count:Int,until:Long=deadline):Int {
        return task7TunPollIoV1(checkNotNull(s.descriptor),if(writing)outBytes else inBytes,count,writing,until,s::checkLive)
    }
    private fun write(s:Step,count:Int):Int=io(s,true,count)
    private fun exchangeStart(s:Step,short:Boolean):NativePacketDelivery{
        stage(6);witness(s);val socket=checkNotNull(s.generator)
        val request=payload(false,1);val packet=DatagramPacket(request,request.size,checkNotNull(s.dns),28472)
        val until=minOf(deadline,SystemClock.elapsedRealtime()+4096);var found=false;var dropped=0
        var nextSend=0L
        for(observed in 0 until 64){
            // UDP delivery is not guaranteed. Generate within the existing capture
            // budget, then submit exactly one observed packet to the native owner.
            val n=task7TunPollIoV1(checkNotNull(s.descriptor),inBytes,inBytes.size,false,until){
                witness(s)
                val now=SystemClock.elapsedRealtime()
                if(now>=nextSend && now<until){socket.send(packet);nextSend=now+100}
            }
            task7TunRequireV1(n>0,5)
            if(packetMatches(s,inBytes,n,false,1)){put(19,n.toLong());found=true;break}
            dropped++;put(51,dropped.toLong())
        }
        put(51,dropped.toLong());task7TunRequireV1(found,4);stage(7)
        for(i in 0 until 44)outbound.put(4+i,inBytes[i])
        val submitted=checkNotNull(s.session).submitOutboundPacket(outbound,44)
        if(case==7 && submitted is NativeProductResult.Failure)
            diagnostic.failure(s.substep,1,task7TunResultV1(submitted))
        expect(submitted,20,0);put(20,1)
        if(short){
            stage(8);inbound.limit(inbound.capacity());for(i in 0 until inbound.capacity())inbound.put(i,0x5a)
            inbound.limit(47)
            expect(checkNotNull(s.session).receiveInboundPacket(inbound),22,1)
            task7TunRequireV1(inbound.position()==4 && inbound.limit()==47,3)
            // The JNI stage publishes no bytes for SIZE_LIMIT.
            inbound.limit(inbound.capacity());task7TunRequireV1((0 until inbound.capacity()).all{inbound.get(it)==0x5a.toByte()},3)
            inbound.limit(4+inBytes.size);put(23,1)
        }
        stage(9);return receive(s).also{put(21,it.length.toLong())}
    }
    private fun receive(s:Step,afterAck:Boolean=false):NativePacketDelivery{
        s.checkLive()
        val delivery=if(afterAck)task7TunNextDeliveryV1(deadline,{!cancelled.get() && !s.stopped.get()},SystemClock::elapsedRealtime,{SystemClock.sleep(1)}){
            checkNotNull(s.session).receiveInboundPacket(inbound)
        } else {
            val received=checkNotNull(s.session).receiveInboundPacket(inbound)
            if(case==7 && received is NativeProductResult.Failure)
                diagnostic.failure(s.substep,2,task7TunResultV1(received))
            task7TunNativeValueV1(received)
        }
        task7TunRequireV1(delivery.length==44,4)
        if(case==7 && (inbound.position()!=4 || inbound.limit()!=4+inBytes.size))
            diagnostic.failure(s.substep,3,0,inbound.position()==4,inbound.limit()==4+inBytes.size)
        task7TunRequireV1(inbound.position()==4 && inbound.limit()==4+inBytes.size,3)
        for(i in 0 until delivery.length)outBytes[i]=inbound.get(4+i)
        return delivery
    }
    private fun packetMatches(s:Step,b:ByteArray,n:Int,response:Boolean,seq:Int):Boolean{
        val src=if(response)s.dns else s.assigned;val dst=if(response)s.assigned else s.dns
        return task7TunPacketMatchesV1(b,n,checkNotNull(src).address,checkNotNull(dst).address,
            if(response)28472 else checkNotNull(s.generator).localPort,if(response)checkNotNull(s.generator).localPort else 28472,payload(response,seq))
    }
    private fun absent(s:Step){
        val socket=checkNotNull(s.generator);socket.soTimeout=50
        try{socket.receive(DatagramPacket(ByteArray(16),16));throw Task7TunFailureV1(4)}
        catch(_:SocketTimeoutException){put(55,1)}
    }
    private fun deliver(s:Step,delivery:NativePacketDelivery,sequence:Int){
        task7TunRequireV1(packetMatches(s,outBytes,delivery.length,true,sequence),4)
        val parent=checkNotNull(s.session);stage(11)
        val code=Task7TunReceiptV1(delivery).deliver({write(s,delivery.length)},
            {put(if(sequence==1)26 else 30,it.toLong())},{
                stage(12);val socket=checkNotNull(s.generator);socket.soTimeout=1000
                val packet=DatagramPacket(ByteArray(17),17);socket.receive(packet)
                put(if(sequence==1)27 else 31,packet.length.toLong())
                task7TunRequireV1(packet.length==16 && packet.address==s.dns && packet.port==28472 && packet.data.copyOf(16).contentEquals(payload(true,sequence)),4)
                put(if(sequence==1)56 else 57,1);stage(13)
            },parent::confirmInboundDelivery,parent::rejectInboundDelivery)
        put(if(sequence==1)28 else 32,code);task7TunRequireV1(code==0L,3)
    }
    private fun openNext(s:Step){
        live();task7TunRequireV1(native.startRelay(File(service.filesDir,"task7-installed-v1").absolutePath,0)==0,7);s.nativeStarted=true
        RuntimeProductionPlatformOwner.acquireIfIdle(service,RuntimeAuthorityTrigger.MANUAL,1,onAdmitted={
            s.owner=it;ownerChanged(it);if(cancelled.get())it.stop(RuntimeStopReason.CANCEL)
        }){admitted->live();s.session=task7TunNativeValueV1(admitted.openProductionSession())}
        val output=ByteBuffer.allocateDirect(32776).apply{position(4);limit(32772)}
        while(s.route==null){s.checkLive()
            when(val event=task7TunNativeValueV1(task7ControlWithinDeadlineV1(deadline,SystemClock::elapsedRealtime,cancelled::get){checkNotNull(s.session).nextControl(output)})){
                is NativeControlEvent.SocketProtectionRequired->{SystemClock.sleep(50);task7TunRequireV1(native.snapshot()[9]==0L,3);task7TunNativeValueV1(checkNotNull(s.session).confirmSocketProtection(event.token,true,null))}
                is NativeControlEvent.RoutePlanReady->s.route=event
                is NativeControlEvent.Failed,is NativeControlEvent.Stopped->throw Task7TunFailureV1(3)
                else->Unit
            }
        }
    }
}
