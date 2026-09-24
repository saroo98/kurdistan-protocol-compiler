// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Network
import android.net.NetworkRequest
import android.net.LinkProperties
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.os.Build
import android.os.Process
import android.os.SystemClock
import java.io.File
import java.io.FileDescriptor
import java.net.InetAddress
import java.net.DatagramSocket
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativejni.Task7InstalledFixtureNative
import org.kurdistanvpn.core.nativejni.Task7MaintenanceFixtureNative
import org.kurdistanvpn.runtime.android.*
import org.kurdistanvpn.runtime.api.RuntimeAuthorityTrigger

internal fun task7MaintenanceNativeCaseV1(case: Int): Int = when(case){8,9->3;10->1;11,304->2;301,303->301;302->302;else->throw IllegalArgumentException()}

/** Closed fixture grammar: query, A reply, TC reply, HTTPS SYN or DNS TCP SYN. */
internal fun task7MaintenanceDnsPacketV1(b:ByteArray,n:Int,client:ByteArray,dns:ByteArray,kind:Int,query:ByteArray?):Boolean {
    if(n !in 40..1500 || n>b.size || client.size!=4 || dns.size!=4 || kind !in 0..4)return false
    fun u(i:Int)=b[i].toInt() and 255
    fun word(i:Int)=u(i)*256+u(i+1)
    fun checksum(start:Int,end:Int,initial:Int=0):Boolean {
        var sum=initial;var i=start
        while(i<end){sum+=u(i)*256+(if(i+1<end)u(i+1)else 0);i+=2}
        while(sum>65535)sum=(sum and 65535)+(sum ushr 16)
        return sum==65535
    }
    fun equal(start:Int,expected:ByteArray)=expected.indices.all{b[start+it]==expected[it]}
    if(u(0)!=0x45 || word(2)!=n || word(6) and 0xbfff!=0 || !checksum(0,20))return false
    val reply=kind in 1..2
    if(!equal(12,if(reply)dns else client))return false
    val destination=if(reply)client else if(kind==3)byteArrayOf(8,8,8,8)else dns
    if(!equal(16,destination))return false
    val protocol=if(kind>=3)6 else 17
    if(u(9)!=protocol)return false
    val pseudo=word(12)+word(14)+word(16)+word(18)+protocol+n-20
    if(kind>=3)return n in 40..80 && u(32) ushr 4 in 5..15 && n==20+(u(32) ushr 4)*4 && word(20)!=0 &&
        word(22)==(if(kind==3)443 else 53) && u(33) and 0x17==2 && checksum(20,n,pseudo)
    if(word(24)!=n-20 || (word(26)!=0 && !checksum(20,n,pseudo)))return false
    val question=byteArrayOf(7,117,112,100,97,116,101,115,7,101,120,97,109,112,108,101,0,0,1,0,1)
    if(n<61 || !equal(40,question))return false
    if(kind==0)return n==61 && word(20)!=0 && word(22)==53 && word(30)==0x100 && word(32)==1 && word(34)==0 && word(36)==0 && word(38)==0
    if(query==null || query.size!=61 || word(20)!=53 || b[22]!=query[20] || b[23]!=query[21] ||
        b[28]!=query[28] || b[29]!=query[29] || word(32)!=1 || word(36)!=0 || word(38)!=0)return false
    if(kind==2)return n==61 && word(30)==0x8300 && word(34)==0
    return n==92 && word(30)==0x8100 && word(34)==1 && equal(61,question.copyOfRange(0,17)) &&
        word(78)==1 && word(80)==1 && word(82)==0 && word(84)==1 && word(86)==4 && equal(88,byteArrayOf(8,8,8,8))
}

internal fun task7InstalledMaintenanceDnsPageV1(epoch:Long,sequence:Long,state:Long,case:Int)=LongArray(80){-1}.apply {
    require(case in 12..14)
    this[0]=epoch;this[1]=sequence;this[2]=1;this[3]=6;this[4]=state;this[5]=case.toLong();this[6]=0
    this[7]=if(case==13)2 else 1;this[8]=(case-11).toLong()
}
internal fun task7InstalledMaintenanceDnsPageMatchesV1(p:LongArray,epoch:Long,sequence:Long):Boolean =
    p.size==80 && p[0]==epoch && p[1]==sequence && p[2]==1L && p[3]==6L && p[4] in 1..3 &&
    p[5] in 12..14 && p[6]==0L && p[7]==(if(p[5]==13L)2L else 1L) && p[8]==p[5]-11 && (71..79).all{p[it]==-1L}
internal fun task7InstalledMaintenanceDnsOutcomeV1(p:LongArray):Boolean {
    if(p.size!=80 || !task7InstalledMaintenanceDnsPageMatchesV1(p,p[0],p[1]) || p[4]!=2L ||
        p[11]<0 || p[12]<p[11] || p[13]!=12L || p[14]!=0L || p[16]!=65536L || p[17]!=30000L || p[18]!=60L)return false
    if(listOf(9,10,15,19,23,24,25,26,27,28,29,32,33,34,37,38,39,41,51,53,54,55,56,57,58,59,60,61,62,63,65,66,67,68,69,70).any{p[it]!=1L})return false
    if(p[21]<p[11] || (p[20]==-1L && p[22]!=-1L) || (p[20]!=-1L && (p[20]<0 || p[22]!=p[21]-p[20] || p[22]<60000)))return false
    if(!(p[30]==0L && p[31]==-1L || p[30]==1L && p[31]==1L) || p[35] !in 1..100 || p[36] !in 0..1000 || p[40]!=61L || p[64]!=1L)return false
    if(p[5]==14L)return (42..49).all{p[it]==-1L} && p[50]==0L && p[52] in 1..2
    val size=if(p[5]==13L)61L else 92L
    return p[42]==0L && p[43]==size && p[44]==1L && p[45]==size && p[46]==0L &&
        p[47] in 40..80 && p[48]==1L && p[49]==0L && p[50]==1L && p[52]==1L
}

/** Process-owned witness only; native signed rate enforcement remains authoritative. */
internal class Task7MaintenanceDnsRateV1 {
    private var identity:String?=null
    private var previous=-1L
    private var running=false
    @Synchronized fun begin(selected:String,now:Long):Long {
        check(!running && selected.isNotEmpty() && (identity==null || identity==selected))
        check(previous==-1L || now>=previous && now-previous>=60000)
        identity=selected;running=true;return previous
    }
    @Synchronized fun completed(now:Long){check(running);previous=now;running=false}
}

/** Fixed local DNS/SYN experiment, using the actual production maintenance owner. */
internal class Task7InstalledMaintenanceDnsCase(private val service:Task7InstalledDriverService,
    epoch:Long,sequence:Long,private val case:Int,private val cancelled:AtomicBoolean) {
    private val lock=Any()
    private val page=task7InstalledMaintenanceDnsPageV1(epoch,sequence,1,case)
    private val deadline=SystemClock.elapsedRealtime()+39000
    private val connectivity=service.getSystemService(ConnectivityManager::class.java)
    private val relay=Task7InstalledFixtureNative()
    private val original=Task7TunDescriptorV1(ParcelFileDescriptor::adoptFd,ParcelFileDescriptor::close)
    private val stop=Task7MaintenanceStopV1()
    private val cancellation=Task7TunCancellationV1()
    private val lost=AtomicBoolean(false)
    private val watch=Task7TunNetworkWatchV1<Network>(lost){ }
    @Volatile private var owner:RuntimeProductionPlatformOwner?=null
    private var session:ProductionNativeSession?=null
    private var maintenance:ProductionNativeMaintenance?=null
    private var descriptor:FileDescriptor?=null
    private var detachedUnproven=false
    private var callbackOwned=false
    private var relayStarted=false
    private var idle=false
    private var task:FutureTask<NativeProductResult<NativeUpdateCheck>>?=null
    private val joined=CountDownLatch(1)
    private var dns=byteArrayOf()
    private var client=byteArrayOf()
    @Volatile var cleanupProven=false;private set
    private val callback=object:ConnectivityManager.NetworkCallback(){
        override fun onLost(n:Network){watch.lost(n)}
        override fun onCapabilitiesChanged(n:Network,c:NetworkCapabilities){watch.changed(n){
            c.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && (Build.VERSION.SDK_INT<30 || c.ownerUid==Process.myUid())}}
        override fun onLinkPropertiesChanged(n:Network,p:LinkProperties){watch.changed(n){
            it.linkMatches(p.interfaceName,p.linkAddresses.map{a->a.address}) && p.dnsServers.size==1 && p.dnsServers[0].address.contentEquals(dns)}}
    }
    private fun put(i:Int,v:Long)=synchronized(lock){page[i]=v}
    private fun stage(v:Long)=put(13,v)
    fun snapshot(state:Long)=synchronized(lock){page.copyOf().also{it[4]=state}}
    private fun remaining(max:Long)=minOf(max,(deadline-SystemClock.elapsedRealtime()).coerceAtLeast(0))
    private fun live(){check(!cancelled.get() && !lost.get() && SystemClock.elapsedRealtime()<deadline)}
    private fun <T> value(r:NativeProductResult<T>):T=when(r){is NativeProductResult.Success->r.value;is NativeProductResult.Failure->error("TASK7_DNS_TYPED_${r.code.name}")}
    private fun result(r:NativeProductResult<*>):Long=when(r){
        is NativeProductResult.Success->0
        is NativeProductResult.Failure->when(r.code){ProductFailureCode.CANCELLED->1;ProductFailureCode.NETWORK_UNAVAILABLE->2
            ProductFailureCode.OPERATION_TIMED_OUT->3;ProductFailureCode.RATE_LIMITED->4;else->5}}
    private fun stopOwner(){
        val retained=owner ?: return
        put(51,1);idle=stop.await(remaining(5000)){retained.stop(RuntimeStopReason.STOP)==RuntimeStartDecision.Idle};check(idle);put(59,1)
    }
    fun cancel(){if(cancellation.begin())cancellation.complete{stopOwner();if(relayStarted)relay.cancel()}}
    private fun current(){
        live();watch.requireLive();val selected=checkNotNull(watch.selected)
        val p=checkNotNull(connectivity.getLinkProperties(selected.network));val c=checkNotNull(connectivity.getNetworkCapabilities(selected.network))
        check(connectivity.activeNetwork==selected.network && c.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
            selected.linkMatches(p.interfaceName,p.linkAddresses.map{it.address}) && p.dnsServers.size==1 && p.dnsServers[0].address.contentEquals(dns))
        if(Build.VERSION.SDK_INT>=30)check(c.ownerUid==Process.myUid())
        if(Build.VERSION.SDK_INT>=28)check(!p.isPrivateDnsActive)
        live()
    }
    private fun setup(){
        stage(2)
        live();check(relay.startRelay(File(service.filesDir,"task7-installed-update-v2").absolutePath,0,if(case==13)2 else 1)==0);relayStarted=true
        RuntimeProductionPlatformOwner.acquireIfIdle(service,RuntimeAuthorityTrigger.MANUAL,1,onAdmitted={
            owner=it;if(cancelled.get())stop.request{it.stop(RuntimeStopReason.CANCEL)==RuntimeStartDecision.Idle}
        }){o->
            live()
            val s=value(o.openProductionSession());session=s;put(23,1)
            val control=ByteBuffer.allocateDirect(32776).apply{position(4);limit(32772)}
            var route:NativeControlEvent.RoutePlanReady?=null
            while(route==null){live();when(val e=value(task7ControlWithinDeadlineV1(deadline,SystemClock::elapsedRealtime,cancelled::get){s.nextControl(control)})){
                is NativeControlEvent.SocketProtectionRequired->value(s.confirmSocketProtection(e.token,true,null))
                is NativeControlEvent.RoutePlanReady->route=e
                is NativeControlEvent.Failed,is NativeControlEvent.Stopped->error("TASK7_DNS_ROUTE_FAILED")
                else->Unit}}
            check(task7InstalledTunBindingV1(route,s.openingSnapshot));put(24,1)
            val opening=s.openingSnapshot
            check(NativeCapability.SAME_DEPLOYMENT_UPDATE in opening.capabilities.effective && opening.updateLimits==NativeUpdateLimits(65536,30000,60))
            put(15,1);put(16,65536);put(17,30000);put(18,60)
            client=checkNotNull(opening.clientV4).value.split('.').map{it.toInt().toByte()}.toByteArray()
            dns=opening.dnsAddresses.single().value.split('.').map{it.toInt().toByte()}.toByteArray()
            stage(3);val tun=o.establishTun(task7InstalledTunConfigurationV1(opening),blocking=false);put(25,1)
            detachedUnproven=true;original.retainDetached(tun.detachFileDescriptor());detachedUnproven=false;put(26,1)
            descriptor=original.adoptOnce().fileDescriptor;put(27,1)
        }
        stage(4)
        val o=checkNotNull(owner)
        val proof=checkNotNull(o.javaClass.getDeclaredField("proof").apply{isAccessible=true}.get(o))
        val name=proof.javaClass.getDeclaredMethod("interfaceName").apply{isAccessible=true}.invoke(proof) as String
        val request=NetworkRequest.Builder()
        if(Build.VERSION.SDK_INT>=30)request.clearCapabilities() else request.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED).removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        connectivity.registerNetworkCallback(request.build(),callback);callbackOwned=true
        val until=minOf(deadline,SystemClock.elapsedRealtime()+2000)
        while(watch.selected==null){
            live();check(SystemClock.elapsedRealtime()<until)
            val n=connectivity.activeNetwork;val p=n?.let(connectivity::getLinkProperties);val c=n?.let(connectivity::getNetworkCapabilities)
            if(n!=null && p!=null && c?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true && p.interfaceName==name && p.linkAddresses.any{it.address.address.contentEquals(client)})
                watch.publish(Task7TunNetworkWitnessV1(n,name,InetAddress.getByAddress(client))) else SystemClock.sleep(10)
        }
        current();put(28,1);put(29,1);put(30,if(Build.VERSION.SDK_INT>=30)1 else 0);if(Build.VERSION.SDK_INT>=30)put(31,1)
        put(32,1);put(33,1);put(34,1)
        var attempts=0;val since=SystemClock.elapsedRealtime()
        DatagramSocket(null).use{socket->task7TunBindReadyV1(1,deadline,SystemClock::elapsedRealtime,SystemClock::sleep,::current,
            {attempts++;checkNotNull(watch.selected).network.bindSocket(socket)},terminal={throw it},emit={})}
        put(35,attempts.toLong());put(36,SystemClock.elapsedRealtime()-since)
        stage(5);o.acquireAssociatedMaintenance{actual->current();put(37,1);maintenance=value(actual.openMaintenanceSession());put(38,1)}
    }
    private fun clean(){
        stopOwner()
        task?.let{check(joined.await(remaining(5000),TimeUnit.MILLISECONDS));put(56,1)}
        put(57,1) // The case worker itself is the sole descriptor consumer, now outside its I/O loop.
        check(!detachedUnproven);original.closeOnce();if(descriptor!=null)put(58,1)
        if(callbackOwned){connectivity.unregisterNetworkCallback(callback);callbackOwned=false}
        cancellation.sealAndJoin(remaining(5000));put(63,1)
        if(relayStarted){
            relay.cancel();val until=SystemClock.elapsedRealtime()+remaining(5000)
            while(relay.snapshot()[11]!=1L && SystemClock.elapsedRealtime()<until)SystemClock.sleep(10)
            check(relay.snapshot()[11]==1L && (owner==null || idle));put(60,1)
            check(relay.finish()==0);put(61,1);relayStarted=false
            val after=relay.snapshot();check(after[0]==0L && after[2]==0L);put(62,1)
        }
        cleanupProven=true;put(10,1)
    }
    fun run():Boolean {
        var success=false
        val marker=File(service.filesDir,"task7-installed-update-v2/prepared-selection")
        val preview=ByteBuffer.allocateDirect(46).apply{for(i in 0 until capacity())put(i,0x5a);position(4);limit(42)}
        put(11,SystemClock.elapsedRealtime());put(14,0)
        try {
            stage(1);live();check(marker.isFile && marker.length() in 1..256)
            val before=marker.readText();val rows=before.lines().filter{it.isNotEmpty()};check(rows.size==2);put(19,1)
            setup();stage(6)
            val invocation=SystemClock.elapsedRealtime();val previous=rate.begin(rows[0],invocation)
            put(20,previous);put(21,invocation);put(22,if(previous<0)-1 else invocation-previous);put(70,1)
            val m=checkNotNull(maintenance)
            val work=FutureTask{try{m.checkSameDeploymentUpdate(NativeUpdateRequest(10000),preview)}finally{rate.completed(SystemClock.elapsedRealtime())}}
            task=work
            Thread({try{work.run()}finally{joined.countDown()}},"task7-dns-update").start();put(39,1)
            val s=checkNotNull(session);val mtu=s.openingSnapshot.effectiveMtu
            val input=ByteArray(mtu);val output=ByteArray(mtu)
            val outbound=ByteBuffer.allocateDirect(mtu+8).apply{position(4);limit(4+mtu)}
            val inbound=ByteBuffer.allocateDirect(mtu+8).apply{position(4);limit(4+mtu)}
            fun observed(kind:Int):Int {
                repeat(64){
                    val n=task7TunPollIoV1(checkNotNull(descriptor),input,mtu,false,deadline){current();check(!work.isDone)}
                    if(task7MaintenanceDnsPacketV1(input,n,client,dns,kind,null))return n
                };error("TASK7_DNS_PACKET_BOUND")
            }
            fun submit(n:Int){for(i in 0 until n)outbound.put(4+i,input[i]);value(s.submitOutboundPacket(outbound,n))}
            stage(7);val n=observed(0);put(40,n.toLong());put(41,1);put(69,1)
            val query=input.copyOf(n)
            if(case==14){stage(10);put(50,0);stopOwner()}else{
                submit(n);put(42,0);stage(8)
                val delivery=value(s.receiveInboundPacket(inbound));put(43,delivery.length.toLong())
                check(inbound.position()==4 && inbound.limit()==4+mtu && delivery.length in 1..mtu)
                for(i in 0 until delivery.length)output[i]=inbound.get(4+i)
                check(task7MaintenanceDnsPacketV1(output,delivery.length,client,dns,if(case==13)2 else 1,query));put(44,1)
                val ack=Task7TunReceiptV1(delivery).deliver({task7TunPollIoV1(checkNotNull(descriptor),output,delivery.length,true,deadline,::current)},
                    {put(45,it.toLong())},{current()},s::confirmInboundDelivery,s::rejectInboundDelivery)
                check(ack==0L);put(46,0);stage(9)
                val syn=observed(if(case==13)4 else 3);put(47,syn.toLong());put(48,1);submit(syn);put(49,0)
                stage(10);put(50,1);value(m.cancel())
            }
            val outcome=work.get(remaining(5000),TimeUnit.MILLISECONDS);check(joined.await(remaining(5000),TimeUnit.MILLISECONDS));put(56,1)
            val code=result(outcome);put(52,code);check(code==1L || case==14 && code==2L)
            put(53,if(preview.position()==4)1 else 0);put(54,if(preview.limit()==42)1 else 0)
            val all=preview.duplicate().apply{clear()};check((0 until 46).all{all.get(it)==0x5a.toByte()});put(55,1)
            stage(11);clean()
            val stale=ByteBuffer.allocateDirect(46).apply{for(i in 0 until 46)put(i,0x5a);position(4);limit(42)}
            put(64,result(m.checkSameDeploymentUpdate(NativeUpdateRequest(10000),stale)))
            val staleAll=stale.duplicate().apply{clear()};check(stale.position()==4 && stale.limit()==42 && (0 until 46).all{staleAll.get(it)==0x5a.toByte()});put(65,1)
            check(marker.readText()==before);put(67,1);put(68,1);put(9,1);success=true
        }catch(f:Exception){put(14,if(f is java.util.concurrent.TimeoutException)2 else 5)
            Task7MaintenanceDiagnosticV1(case){android.util.Log.i("Task7Maintenance",it)}.record(1,synchronized(lock){page[13]},5,0,-1,f){LongArray(40){-1}}
            android.util.Log.i("Task7Maintenance","DNS_FAILURE_V1_${case}_${synchronized(lock){page[13]}}")
        }finally{
            if(!cleanupProven)try{clean()}catch(_:Exception){put(10,0);put(14,6)}
            put(12,SystemClock.elapsedRealtime());stage(12)
        }
        return success && cleanupProven && !cancelled.get()
    }
    companion object { private val rate=Task7MaintenanceDnsRateV1() }
}

/** Fixed existing observations only. Unarmed C words are unavailable, not no-error. */
internal fun task7MaintenanceDiagnosticObservedV1(armed:Boolean,native:LongArray?,admission:Int?,revalidation:Int?,
    client:LongArray?,delegate:LongArray?):LongArray = LongArray(40){-1}.also { result ->
    result[0]=if(armed)1 else 0
    if(armed && native?.size==3)for(i in 0..2)result[1+i]=native[i].takeIf{it in 0..4095} ?: -1
    result[4]=admission?.takeIf{it in 0..7}?.toLong() ?: -1
    result[5]=revalidation?.takeIf{it in 0..127}?.toLong() ?: -1
    val publication=task7InstalledPublicationPageV1(0,0,0,client,delegate)
    result[6]=publication[5].takeIf{it==1L} ?: -1;result[7]=publication[6].takeIf{it==1L} ?: -1
    publication.copyInto(result,8,8,40)
}

/** Internal observation only. Independent first-failure latches never gate ownership. */
internal class Task7MaintenanceDiagnosticV1(private val caseId:Int,private val emit:(String)->Unit) {
    private val lock=Any()
    private var primary=false
    private var cleanup=false
    fun record(event:Int,phase:Long,category:Long,cursor:Int,product:Long,failure:Throwable?,observe:()->LongArray) {
        runCatching {
            if(event !in 1..3 || (caseId !in 8..14 && caseId !in 301..304))return
            synchronized(lock) {
                if(event==1){if(primary)return;primary=true}
                if(event==2){if(cleanup)return;cleanup=true}
            }
            val values=LongArray(50){-1}
            values[0]=1;values[1]=event.toLong();values[2]=caseId.toLong()
            values[3]=phase.takeIf{it in 1..15} ?: -1
            values[4]=category.takeIf{it in 0..6} ?: -1
            values[5]=when(failure){null->0;is RuntimeAuthorityCleanupUnprovenException->1
                is java.util.concurrent.TimeoutException->2;is java.util.concurrent.CancellationException->3
                is IllegalArgumentException->4;is IllegalStateException->5;else->6}
            var cause=failure
            for(depth in 0 until 4){
                val actual=cause ?: break
                for(frame in actual.stackTrace.take(32)){
                    val origin=when(frame.className.substringBefore('$')+"#"+frame.fileName){
                        "org.kurdistanvpn.app.Task7InstalledMaintenanceCase#Task7InstalledMaintenanceCase.kt"->1L
                        "org.kurdistanvpn.runtime.android.RuntimeProductionPlatformOwner#RuntimeProductionPlatformOwner.kt"->2L
                        "org.kurdistanvpn.runtime.android.RuntimeProductionGuardOwnershipV1#RuntimeProductionPlatformOwner.kt"->3L
                        "org.kurdistanvpn.runtime.android.RuntimeProductionAuthorityClientV1#RuntimeProductionAuthorityClientV1.kt"->4L
                        "org.kurdistanvpn.core.nativejni.ProductionNativeParentV1#ProductionNativeOpenV1.kt"->5L
                        "org.kurdistanvpn.core.nativejni.ProductionNativeMaintenanceV1Kt#ProductionNativeMaintenanceV1.kt"->6L
                        "org.kurdistanvpn.core.nativejni.AndroidProductionCallbacks#AndroidProductionCallbacks.kt"->7L
                        else->continue
                    }
                    values[6]=origin;values[7]=frame.lineNumber.takeIf{it in 1..10000}?.toLong() ?: -1
                    break
                }
                if(values[6]!=-1L)break
                cause=actual.cause
            }
            values[8]=cursor.takeIf{it in 0..10}?.toLong() ?: -1
            values[9]=product.takeIf{it in 1..16} ?: -1
            val observed=runCatching{observe()}.getOrNull()
            if(observed?.size==40){
                // Revalidate every field even if an observation producer is faulty.
                val normalized=task7MaintenanceDiagnosticObservedV1(observed[0]==1L,
                    observed.copyOfRange(1,4),observed[4].takeIf{it in 0..7}?.toInt(),
                    observed[5].takeIf{it in 0..127}?.toInt(),
                    if(observed[6]==1L)observed.copyOfRange(8,24) else null,
                    if(observed[7]==1L)observed.copyOfRange(24,40) else null)
                if(observed[0] !in 0..1)normalized[0]=-1
                normalized.copyInto(values,10)
            }
            emit("DIAG_V1_"+values.joinToString(","))
        }
    }
}
internal fun task7MaintenanceMeasurementV1(v: LongArray, case: Int): Boolean {
    if((case !in 1..3 && case !in 301..302) || v.size!=24 || v[0]!=1L || v[1]!=case.toLong() || v[2]!=1L || v[3]!=0L || v[7]!=0L ||
        v[17]!=0L || v[18]!=1L || v[19]!=0L || v[20]!=0L || v[21]!=0L || v[22]!=1L || v[23]!=1L)return false
    if(case==3)return (4..6).all{v[it]==-1L} && (8..16).all{v[it]==-1L}
    if(v[4]!=0L || v[5] !in 1..512 || v[6] !in 3..1048576)return false
    if(case in 301..302){
        if(v[9]!=1L || v[10]!=1L || v[11]!=1L || v[12]!=-1L || v[15]!=0L || v[16]!=1L)return false
        return if(case==301)v[8]==0L && v[13]==1L && v[14] in 1..65536 else v[8]==8L && v[13]==0L && v[14]==0L
    }
    if(case==1)return (8..16).all{v[it]==-1L}
    return v[8]==13L && v[9]==1L && v[10]==1L && v[11]==1L && v[12]==1L &&
        v[13]==0L && v[14]==0L && v[15]==0L && v[16]==1L
}

internal fun task7InstalledMaintenancePageV1(epoch:Long,sequence:Long,state:Long,caseId:Int,level:Int=0):LongArray = LongArray(72){-1}.apply {
    require((caseId in 8..11 || caseId in 301..304) && task7InstalledCaseAllowedV1(caseId,level))
    this[0]=epoch;this[1]=sequence;this[2]=1;this[3]=3;this[4]=state;this[5]=caseId.toLong();this[6]=0
    this[6]=level.toLong();this[7]=if(caseId==8)2 else 1;this[8]=task7MaintenanceNativeCaseV1(caseId).toLong()
}
internal fun task7InstalledMaintenancePageMatchesV1(p:LongArray,epoch:Long,sequence:Long):Boolean {
    if(p.size!=72 || p[0]!=epoch || p[1]!=sequence || p[2]!=1L || p[3]!=3L || p[4] !in 1..3 ||
        (p[5] !in 8..11 && p[5] !in 301..304) || p[6] !in 0..64 || !task7InstalledCaseAllowedV1(p[5].toInt(),p[6].toInt()) ||
        p[7]!=(if(p[5]==8L)2L else 1L) || p[8]!=task7MaintenanceNativeCaseV1(p[5].toInt()).toLong())return false
    val pressure=p[5] in 301..304
    if(if(pressure)p[71] !in -1..30 else p[71]!=-1L)return false
    if(p[12]<-1 || p[13]<-1 || p[14] !in -1..15 || p[15] !in -1..7)return false
    for(i in listOf(9,10,11,40,41,42,43,44,45,46,47,48,49,50,51,53,54,55,56,57,58,59,60,61,62,63,64,65,68,70))
        if(p[i] !in -1..1)return false
    for(i in listOf(52,66,69))if(p[i] !in -1..26)return false
    if(p[67] !in -1..23)return false
    if(p[5]!=8L && listOf(41,42,43,44,45,50,60,61,64,65,66,67,68,69,70).any{p[it]!=-1L})return false
    if(p[5]!=8L && !pressure && (55..57).any{p[it]!=-1L})return false
    if(p[5]>=10L && p[62]!=-1L)return false
    if(p[5]==8L && p[63]!=-1L)return false
    return if(p[9]==1L)task7MaintenanceMeasurementV1(p.copyOfRange(16,40),p[8].toInt()) else (16..39).all{p[it]==-1L}
}
internal fun task7InstalledMaintenanceOutcomeV1(p:LongArray):Boolean {
    if(p.size!=72 || !task7InstalledMaintenancePageMatchesV1(p,p[0],p[1]) || p[4]!=2L ||
        p[12]<0 || p[13]<p[12] || p[14]!=15L || p[15]!=0L)return false
    if(listOf(9,10,11,40,46,47,51,53,54,58,59).any{p[it]!=1L} || p[52]!=7L)return false
    if(p[49] !in 0..1)return false
    if(p[5] in 301..304)return (55..57).all{p[it]==1L} && p[48]==0L && p[62]==-1L &&
        p[63]==(if(p[5]==304L)1L else 0L) && p[71]==(if(p[5]==303L)30L else 1L)
    if(p[5]==8L){
        if(listOf(41,42,43,45,48,55,56,57,60,61,62,64,65,68,70).any{p[it]!=1L} || p[44]!=0L ||
            p[66]!=0L || p[67]!=0L || p[69]!=7L || p[63]!=-1L)return false
        return if(p[49]==1L)p[50]==1L else p[50]==-1L
    }
    if((41..45).any{p[it]!=-1L} || (55..57).any{p[it]!=-1L} || (64..70).any{p[it]!=-1L} ||
        p[48]!=0L || p[50]!=-1L || p[60]!=-1L || p[61]!=-1L)return false
    return p[62]==(if(p[5]==9L)1L else -1L) && p[63]==(if(p[5]==11L)1L else 0L)
}

/** One actual stop worker. A timeout/failure retains its task and cannot retry/heal it. */
internal class Task7MaintenanceStopV1 {
    private val lock=Any()
    private var task:FutureTask<Boolean>?=null
    private val done=CountDownLatch(1)
    fun request(action:()->Boolean):FutureTask<Boolean> = synchronized(lock){task ?: FutureTask(action).also { work ->
            task=work
            Thread({try{work.run()}finally{done.countDown()}},"task7-maintenance-stop").start()
        }}
    fun await(timeoutMillis:Long=5000,action:()->Boolean):Boolean {
        val retained=request(action)
        val wait=timeoutMillis.coerceIn(0,5000)
        val until=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(wait)
        val result=retained.get(wait,TimeUnit.MILLISECONDS)
        check(done.await((until-System.nanoTime()).coerceAtLeast(0),TimeUnit.NANOSECONDS))
        return result
    }
}

/** Fixed owned cases only. No numeric identity, route or provider arrives from Binder. */
internal class Task7MaintenanceSequenceV1(private val cancelled:AtomicBoolean) {
    @Volatile var cleanupProven=false;private set
    fun publish(retain:()->Unit,requestStop:()->Unit) {
        retain()
        if(cancelled.get())requestStop()
    }
    fun afterPrerequisite(prerequisite:()->Unit,work:()->Unit) {
        check(!cancelled.get())
        prerequisite()
        check(!cancelled.get())
        work()
    }
    fun run(caseId:Int,initial:(Boolean)->Unit,retireInitial:()->Unit,
        successor:()->Unit,cleanup:()->Unit):Boolean {
        require(caseId in 8..11 || caseId in 301..304)
        cleanupProven=false
        try {
            check(!cancelled.get())
            initial(caseId==8)
            retireInitial()
            if(caseId==8){check(!cancelled.get());successor()}
        }finally{
            cleanup()
            cleanupProven=true
        }
        return !cancelled.get()
    }
}

internal class Task7InstalledMaintenanceCase(private val service:Task7InstalledDriverService,
    private val epoch:Long,private val sequence:Long,private val caseId:Int,private val cancelled:AtomicBoolean,private val level:Int=0) {
    private val monitor=Any()
    private val page=task7InstalledMaintenancePageV1(epoch,sequence,1,caseId,level)
    private val component=Task7MaintenanceFixtureNative()
    private val relay=Task7InstalledFixtureNative()
    private val connectivity=service.getSystemService(ConnectivityManager::class.java)
    private val deadline=SystemClock.elapsedRealtime()+39_000
    private class Failure(val category:Long):IllegalStateException()
    private class Step {
        @Volatile var owner:RuntimeProductionPlatformOwner?=null
        @Volatile var relayStarted=false
        var relayFinished=false
        var maintenance:ProductionNativeMaintenance?=null
        val cancellation=Task7TunCancellationV1()
        val stop=Task7MaintenanceStopV1()
        @Volatile var idle=false
        var worker:FutureTask<Pair<Int,LongArray>>?=null
        var workerDone:CountDownLatch?=null
        var workerJoined=false
    }
    @Volatile private var step=Step()
    private val sequenceFlow=Task7MaintenanceSequenceV1(cancelled)
    private val diagnostic=Task7MaintenanceDiagnosticV1(caseId){android.util.Log.i("Task7Maintenance",it)}
    private var productFailure=-1L
    val cleanupProven:Boolean get()=sequenceFlow.cleanupProven
    private fun put(i:Int,v:Long)=synchronized(monitor){page[i]=v}
    private fun stage(n:Long)=put(14,n)
    private fun demand(value:Boolean,category:Long=3){if(!value)throw Failure(category)}
    private fun live(){demand(!cancelled.get(),1);demand(SystemClock.elapsedRealtime()<deadline,2)}
    private fun remaining(maximum:Long)=minOf(maximum,(deadline-SystemClock.elapsedRealtime()).coerceAtLeast(0))
    private fun <T> opened(result:NativeProductResult<T>):T=when(result){is NativeProductResult.Success->result.value;is NativeProductResult.Failure->{
        productFailure=when(result.code){
            ProductFailureCode.INVALID_INPUT->1;ProductFailureCode.SIZE_LIMIT->2;ProductFailureCode.PROFILE_INCOMPATIBLE->3
            ProductFailureCode.OPERATION_INTERRUPTED->4;ProductFailureCode.RESOURCE_LIMIT->5;ProductFailureCode.RATE_LIMITED->6
            ProductFailureCode.CANCELLED->7;ProductFailureCode.OPERATION_TIMED_OUT->8;ProductFailureCode.NETWORK_UNAVAILABLE->9
            ProductFailureCode.ROUTE_POLICY_REJECTED->10;ProductFailureCode.NODE_UNREACHABLE->11;ProductFailureCode.PROFILE_EXPIRED->12
            ProductFailureCode.PROFILE_REVOKED->13;ProductFailureCode.PROFILE_UNTRUSTED->14;ProductFailureCode.INTERNAL_FAILURE->15;else->16}
        throw Failure(3)
    }}
    private fun observeDiagnostic(event:Int,failure:Throwable?,cursor:Int=0){
        runCatching {
            val retained=step
            diagnostic.record(event,synchronized(monitor){page[14]},when(failure){null->0;is Failure->failure.category
                is java.util.concurrent.TimeoutException->2;else->5},cursor,productFailure,failure){
                fun field(instance:Any?,name:String):Any?=checkNotNull(instance).javaClass.getDeclaredField(name).apply{isAccessible=true}.get(instance)
                fun publication(instance:Any?):LongArray?=runCatching{
                    val values=field(instance,"publicationDiagnostic") as LongArray
                    synchronized(values){values.copyOf()}
                }.getOrNull()
                val owner=retained.owner
                val client=runCatching{publication(owner)}.getOrNull()
                val delegate=runCatching{field(field(owner,"maintenance"),"delegate")}.getOrNull()
                val admission=runCatching{field(field(field(owner,"client"),"calls"),"firstAdmissionRejection") as Int}.getOrNull()
                val revalidation=runCatching{field(delegate,"firstRevalidationRejection") as Int}.getOrNull()
                val armed=retained.relayStarted
                val native=if(armed)runCatching{relay.snapshot().copyOfRange(13,16)}.getOrNull() else null
                task7MaintenanceDiagnosticObservedV1(armed,native,admission,revalidation,client,publication(delegate))
            }
        }
    }
    private fun <T> observePrimary(action:()->T):T=try{action()}catch(failure:Exception){
        observeDiagnostic(1,failure);throw failure
    }
    fun snapshot(state:Long):LongArray=synchronized(monitor){page.copyOf().also{it[4]=state}}
    private fun noVpn()=connectivity.allNetworks.none{connectivity.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true}
    private fun waitFramework(vpn:Boolean){
        val until=minOf(deadline,SystemClock.elapsedRealtime()+2000)
        while(true){
            live()
            val selected=connectivity.activeNetwork
            val ready=if(vpn)selected!=null && connectivity.getNetworkCapabilities(selected)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true &&
                connectivity.getLinkProperties(selected)?.interfaceName!=null else noVpn()
            if(ready)return
            demand(SystemClock.elapsedRealtime()<until,2);SystemClock.sleep(25)
        }
    }
    private fun observeFramework(associated:Boolean){
        val capabilities=connectivity.activeNetwork?.let{connectivity.getNetworkCapabilities(it)}
        val vpn=capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true
        put(48,if(vpn)1 else 0);put(49,if(Build.VERSION.SDK_INT>=30)1 else 0)
        if(associated){
            demand(vpn,1)
            if(Build.VERSION.SDK_INT>=30){val own=capabilities?.ownerUid==Process.myUid();put(50,if(own)1 else 0);demand(own,1)}
        } else demand(!vpn && noVpn(),1)
    }
    private fun stop(s:Step,reason:RuntimeStopReason){
        val owner=s.owner ?: return
        s.idle=s.stop.await(remaining(5000)){owner.stop(reason)==RuntimeStartDecision.Idle}
        demand(s.idle,6)
    }
    fun cancel(){
        val retained=step
        if(retained.cancellation.begin())retained.cancellation.complete{
            stop(retained,RuntimeStopReason.CANCEL)
            if(retained.relayStarted && !retained.relayFinished)relay.cancel()
        }
    }
    private fun admit(s:Step,kind:Int,slot:Int,setup:(RuntimeProductionPlatformOwner)->Unit){
        live()
        RuntimeProductionPlatformOwner.acquireIfIdle(service,RuntimeAuthorityTrigger.MANUAL,kind,
            onAdmitted={owner->sequenceFlow.publish({s.owner=owner;put(slot,1)},{
                // Do not join this acquisition's guard from inside its own callback.
                s.stop.request{owner.stop(RuntimeStopReason.CANCEL)==RuntimeStartDecision.Idle};Unit
            })}){owner->observePrimary{live();setup(owner)}}
    }
    private fun native(s:Step,case:Int):Pair<Int,LongArray>{
        live();if(s.workerJoined){s.worker=null;s.workerJoined=false};demand(s.worker==null,1)
        val maintenance=checkNotNull(s.maintenance)
        val done=CountDownLatch(1)
        val task=FutureTask{val values=LongArray(24){-1};component.run(maintenance,case,values) to values}
        s.worker=task;s.workerDone=done
        Thread({try{task.run()}finally{done.countDown()}},"task7-maintenance-operation").start()
        val result=task.get(remaining(6000),TimeUnit.MILLISECONDS)
        demand(done.await(remaining(5000),TimeUnit.MILLISECONDS),6);s.workerJoined=true
        return result
    }
    private fun cleanup(s:Step){
        var cursor=1
        try{
        stop(s,RuntimeStopReason.STOP)
        cursor=2
        s.workerDone?.let{demand(it.await(remaining(5000),TimeUnit.MILLISECONDS),6);s.workerJoined=true}
        cursor=3
        s.cancellation.sealAndJoin(remaining(5000))
        if(s.relayStarted && !s.relayFinished){
            cursor=4
            relay.cancel();val until=minOf(deadline,SystemClock.elapsedRealtime()+5000)
            cursor=5
            while(relay.snapshot()[11]!=1L && SystemClock.elapsedRealtime()<until)SystemClock.sleep(25)
            demand(relay.snapshot()[11]==1L,6);put(55,1)
            cursor=6
            demand(s.idle || s.owner==null,6)
            cursor=7
            demand(relay.finish()==0,6);s.relayFinished=true;put(56,1)
            cursor=8
            val after=relay.snapshot();demand(after[0]==0L && after[2]==0L,6);put(57,1)
        }
        observeDiagnostic(3,null,10)
        }catch(failure:Exception){observeDiagnostic(2,failure,cursor);throw failure}
    }
    private fun stale(maintenance:ProductionNativeMaintenance,slot:Int){
        val values=LongArray(24){-1};val result=component.run(maintenance,3,values)
        put(slot,result.toLong());demand(result==7 && values.all{it==-1L})
        if(slot==52)put(53,1)
    }
    private fun associated(s:Step){
        demand(relay.startRelay(File(service.filesDir,"task7-installed-v1").absolutePath,0)==0)
        s.relayStarted=true
        admit(s,1,40){owner->
            val session=opened(owner.openProductionSession());put(41,1);stage(3)
            val buffer=ByteBuffer.allocateDirect(32776).apply{position(4);limit(32772)}
            var route:NativeControlEvent.RoutePlanReady?=null
            while(route==null){
                live()
                when(val event=opened(task7ControlWithinDeadlineV1(deadline,SystemClock::elapsedRealtime,cancelled::get){session.nextControl(buffer)})){
                    is NativeControlEvent.SocketProtectionRequired->{
                        demand(relay.snapshot()[9]==0L);opened(session.confirmSocketProtection(event.token,true,null))
                    }
                    is NativeControlEvent.RoutePlanReady->route=event
                    is NativeControlEvent.Failed,is NativeControlEvent.Stopped->throw Failure(3)
                    else->Unit
                }
            }
            demand(task7InstalledTunBindingV1(route,session.openingSnapshot));put(42,1);stage(4)
            // The returned original remains with the actual guard. Never detach or close it here.
            owner.establishTun(task7InstalledTunConfigurationV1(session.openingSnapshot));put(43,1);put(44,0);put(60,1)
        }
        stage(5)
        sequenceFlow.afterPrerequisite({waitFramework(true);observeFramework(true)}){
            stage(6)
            checkNotNull(s.owner).acquireAssociatedMaintenance{owner->
                observePrimary{put(45,1);live();s.maintenance=opened(owner.openMaintenanceSession());put(46,1)}
            }
        }
    }
    fun run():Boolean {
        var success=false;var initial:Step?=null
        put(12,SystemClock.elapsedRealtime());put(15,0)
        try {
            success=sequenceFlow.run(caseId,{associatedMode->
            observePrimary{
            stage(1);live();demand(noVpn(),1);stage(2)
            val first=step;initial=first
            // Fixture allocation is setup, not part of the short publication lease.
            // Match the tunnel driver: prepare ballast before acquiring authority.
            if(caseId in 301..304){
                demand(relay.startRelay(File(service.filesDir,"task7-installed-v1").absolutePath,level)==0)
                first.relayStarted=true
            }
            if(associatedMode)associated(first) else {
                admit(first,2,40){owner->
                    stage(6);first.maintenance=opened(owner.openMaintenanceSession());put(46,1)}
                observeFramework(false)
            }
            stage(7)
            val selected=task7MaintenanceNativeCaseV1(caseId)
            repeat(if(caseId==303)30 else 1){iteration->
            val(result,measurement)=native(first,selected)
            android.util.Log.i("Task7Maintenance", "COMPONENT_STATUS_V1_${caseId}_${result.coerceIn(-1,26)}")
            demand(result==0);demand(task7MaintenanceMeasurementV1(measurement,selected),4)
            synchronized(monitor){measurement.copyInto(page,16);page[9]=1;page[47]=if(measurement[7]==0L)1 else 0}
            if(caseId in 301..304){
                val memory=relay.snapshot();demand(memory[0]==level.toLong()*1048576 && memory[1]==level.toLong() && memory[2]==1L)
                put(71,(iteration+1).toLong())
                android.util.Log.i("Task7Maintenance","PRESSURE_V1_${caseId}_${level}_${iteration+1}_"+memory.take(9).joinToString(","))
            }
            }
            put(54,1)
            if(selected==3)put(62,1)
            if(caseId!=8)put(63,if(caseId==11 || caseId==304)1 else 0) else put(61,1)
            }
            },{
            observePrimary{
            val first=checkNotNull(initial)
            stage(8);cleanup(first);put(51,if(first.idle)1 else 0)
            stage(9);stale(checkNotNull(first.maintenance),52)
            }
            },{
                observePrimary{
                val first=checkNotNull(initial)
                val old=checkNotNull(first.maintenance);val token=checkNotNull(first.owner).startToken()
                stage(10);waitFramework(false);put(70,1);live()
                val next=Step();step=next;stage(11)
                admit(next,2,65){owner->next.maintenance=opened(owner.openMaintenanceSession())}
                demand(checkNotNull(next.owner).startToken()!=token);put(64,1)
                val(nextStatus,nextValues)=native(next,3);put(66,nextStatus.toLong())
                demand(nextStatus==0 && task7MaintenanceMeasurementV1(nextValues,3),4);put(67,nextValues[7])
                stage(12);stale(old,69);stage(13);cleanup(next);put(68,if(next.idle)1 else 0)
                }
            },{
                stage(14)
                try {
                    cleanup(step)
                    demand(initial==null || initial!!.idle || initial!!.owner==null,6)
                    put(59,1)
                }catch(failure:Exception){observeDiagnostic(2,failure,9);throw Failure(6)}
            })
            if(success)put(10,1)
        } catch(failure:Exception){
            put(15,when(failure){is Failure->failure.category;is java.util.concurrent.TimeoutException->2;else->5})
        } finally {
            put(11,if(cleanupProven)1 else 0)
            put(13,SystemClock.elapsedRealtime());stage(15)
        }
        return success && cleanupProven && !cancelled.get()
    }
}
