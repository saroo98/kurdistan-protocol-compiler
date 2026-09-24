// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.lang.reflect.Proxy
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*

class ProductionNativeSessionV1Test {
    @Test fun trustedProbeBindingGatesNativeAndSuppressesReplacedResult() {
        for(mode in listOf("missing","replaced","native-reject")) {
            var current=mode!="missing";var count=0
            val binding=object:AndroidProductionProbeBindingV1 {
                override fun permits(target:Int)=current && target==7
                override fun isCurrent()=current
                override fun observe(event:NativeControlEvent){}
                override fun invalidate(){current=false}
            }
            val calls=Proxy.newProxyInstance(ProductionNativeCallsV1::class.java.classLoader,arrayOf(ProductionNativeCallsV1::class.java)){_,method,args ->
                check(method.name=="runProbe");count++
                if(mode=="native-reject")1 else {
                    val output=args[4] as ByteBuffer
                    output.put(byteArrayOf(1,2,1,1,1,0,0,1)).putInt(100).putInt(0).putShort(0).put(0).putShort(0)
                    output.position(0);(args[7] as LongArray)[0]=21;current=false;0
                }
            } as ProductionNativeCallsV1
            val parent=ProductionNativeParentV1({0},{0}).apply{bind(-9)}
            val snapshot=(ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(ProductionResultCodecV1Test.tunSnapshot())) as NativeProductResult.Success).value
            val session=ProductionNativeSessionV1(snapshot,parent,calls,binding){error("stream")}
            val result=session.runProbe(NativeProbeRequest(7,NativeProbeMethod.TCP_CONNECT,1000,1000,1))
            assertEquals(NativeProductResult.Failure(if(mode=="native-reject")ProductFailureCode.PROFILE_INCOMPATIBLE else ProductFailureCode.OPERATION_INTERRUPTED),result)
            assertEquals(if(mode=="missing")0 else 1,count)
            session.close();assertFalse(current)
        }
    }
    @Test fun activeProbeDecodesCompletedAggregateAndWipesOwnedBuffers() {
        for (completion in listOf(0,8,6)) {
            var input:ByteBuffer?=null;var output:ByteBuffer?=null;var metadata:LongArray?=null;var closes=0
            val calls=Proxy.newProxyInstance(ProductionNativeCallsV1::class.java.classLoader,
                arrayOf(ProductionNativeCallsV1::class.java)){_,method,args->
                check(method.name=="runProbe");assertEquals(-9L,args[0]);assertEquals(0,args[2]);assertEquals(9,args[3])
                input=args[1] as ByteBuffer;output=args[4] as ByteBuffer;metadata=args[7] as LongArray
                assertEquals(9,input!!.capacity());assertEquals(21,output!!.capacity());assertEquals(0,args[5]);assertEquals(21,args[6])
                assertArrayEquals(byteArrayOf(1,0,1,1,3,-24,3,-24,1),ByteArray(9){input!!.get(it)})
                output!!.put(byteArrayOf(1,2,1,1,1,0,0,1)).putInt(100).putInt(0).putShort(0).put(0).putShort(completion.toShort())
                output!!.position(0);metadata!![0]=21;0
            } as ProductionNativeCallsV1
            val parent=ProductionNativeParentV1({0},{closes++;0}).apply{bind(-9)}
            val snapshot=(ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(ProductionResultCodecV1Test.tunSnapshot())) as NativeProductResult.Success).value
            val session:ProductionNativeSession=ProductionNativeSessionV1(snapshot,parent,calls){error("unexpected stream")}
            val result=session.runProbe(NativeProbeRequest(1,NativeProbeMethod.TCP_CONNECT,1000,1000,1)) as NativeProductResult.Success
            assertEquals(NativeProbePath.ACTIVE_RELAY_END_TO_END,result.value.path)
            assertEquals(when(completion){8->NativeProbeCompletion.TIMED_OUT;6->NativeProbeCompletion.RATE_LIMITED;else->NativeProbeCompletion.COMPLETE},result.value.completion)
            repeat(9){assertEquals(0.toByte(),input!!.get(it))};repeat(21){assertEquals(0.toByte(),output!!.get(it))}
            assertEquals(0L,metadata!![0]);assertEquals(0,closes);session.close()
        }
    }

    @Test fun probeRejectsMalformedOrTransportOutputAndWipesChangedBounds() {
        for (mode in listOf("wrong-path","metadata-overflow","failure-output","exception","cancel")) {
            var input:ByteBuffer?=null;var output:ByteBuffer?=null;var metadata:LongArray?=null;var closes=0
            val calls=Proxy.newProxyInstance(ProductionNativeCallsV1::class.java.classLoader,
                arrayOf(ProductionNativeCallsV1::class.java)){_,method,args->
                check(method.name=="runProbe");input=args[1] as ByteBuffer;output=args[4] as ByteBuffer;metadata=args[7] as LongArray
                if(mode=="cancel") 7 else {
                    output!!.put(byteArrayOf(1,1,1,1,1,0,0,1)).putInt(100).putInt(0).putShort(0).put(0).putShort(0)
                    output!!.position(0);metadata!![0]=if(mode=="metadata-overflow")Long.MAX_VALUE else 21
                    if(mode=="exception"){input!!.limit(0);output!!.limit(0);error("injected call failure")}
                    if(mode=="failure-output")8 else 0
                }
            } as ProductionNativeCallsV1
            val parent=ProductionNativeParentV1({0},{closes++;0}).apply{bind(-9)}
            val snapshot=(ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(ProductionResultCodecV1Test.tunSnapshot())) as NativeProductResult.Success).value
            val session=ProductionNativeSessionV1(snapshot,parent,calls){error("unexpected stream")}
            assertEquals(NativeProductResult.Failure(if(mode=="cancel")ProductFailureCode.CANCELLED else ProductFailureCode.INTERNAL_FAILURE),
                session.runProbe(NativeProbeRequest(1,NativeProbeMethod.TCP_CONNECT,1000,1000,1)))
            assertEquals(if(mode=="cancel")0 else 1,closes)
            repeat(9){assertEquals(0.toByte(),input!!.get(it))};repeat(21){assertEquals(0.toByte(),output!!.get(it))}
            assertEquals(0L,metadata!![0]);session.close()
        }
    }

    @Test fun streamOpeningAdoptsExactChildAndWipesEncodedRequest() {
        var encoded:ByteBuffer?=null;var metadata:LongArray?=null;var closes=0
        val parent=ProductionNativeParentV1({0},{0}).apply{bind(-9)}
        val calls=Proxy.newProxyInstance(ProductionNativeCallsV1::class.java.classLoader,
            arrayOf(ProductionNativeCallsV1::class.java)){_,method,args->
            check(method.name=="openStream");assertEquals(-9L,args[0]);assertEquals(0,args[2]);assertEquals(10,args[3])
            encoded=args[1] as ByteBuffer;metadata=args[4] as LongArray
            assertEquals(259,encoded!!.capacity());metadata!![0]=Long.MIN_VALUE;0
        } as ProductionNativeCallsV1
        val streamCalls=Proxy.newProxyInstance(ProductionNativeStreamCallsV1::class.java.classLoader,
            arrayOf(ProductionNativeStreamCallsV1::class.java)){_,method,args->
            check(method.name=="close");assertEquals(-9L,args[0]);assertEquals(Long.MIN_VALUE,args[1]);closes++;0
        } as ProductionNativeStreamCallsV1
        val snapshot=(ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(ProductionResultCodecV1Test.tunSnapshot())) as NativeProductResult.Success).value
        val session=ProductionNativeSessionV1(snapshot,parent,calls){ProductionNativeStreamV1(it,streamCalls)}
        val result=session.openProxyStream(NativeProxyRequest(NativeProxyAddressKind.IPV4,byteArrayOf(8,8,8,8),443)) as NativeProductResult.Success
        assertEquals(0L,metadata!![0]);repeat(259){assertEquals(0.toByte(),encoded!!.get(it))}
        result.value.close();result.value.close();assertEquals(1,closes);session.close()
    }

    @Test fun packetReceiptIsNotAcknowledgedByCopyAndMalformedMetadataRetiresParent() {
        var entered = 0; var confirms = 0; var closes = 0; var malformed = false
        val output = ByteBuffer.allocateDirect(100000).order(ByteOrder.LITTLE_ENDIAN).apply { position(7); limit(1507) }
        val calls = Proxy.newProxyInstance(ProductionNativeCallsV1::class.java.classLoader,
            arrayOf(ProductionNativeCallsV1::class.java)) { _, method, args ->
            when (method.name) {
                "receivePacket" -> {
                    entered++; assertSame(output,args[1]); assertEquals(7,args[2]); assertEquals(1507,args[3])
                    (args[4] as LongArray).apply { this[0] = if (malformed) Long.MAX_VALUE else 48; this[1] = Long.MIN_VALUE }; 0
                }
                "confirmPacket" -> { confirms++; assertEquals(Long.MIN_VALUE,args[1]); assertEquals(48L,args[2]); 0 }
                else -> error("unexpected call")
            }
        } as ProductionNativeCallsV1
        val parent = ProductionNativeParentV1({0},{closes++;0}).apply { bind(-9) }
        val snapshot = (ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(ProductionResultCodecV1Test.tunSnapshot())) as NativeProductResult.Success).value
        val session = ProductionNativeSessionV1(snapshot,parent,calls) { error("unexpected stream") }
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT),session.receiveInboundPacket(output.asReadOnlyBuffer()))
        assertEquals(0,entered)
        assertEquals(NativeProductResult.Success(NativePacketDelivery(48,Long.MIN_VALUE)),session.receiveInboundPacket(output))
        assertEquals(0,confirms)
        assertEquals(NativeProductResult.Success(Unit),session.confirmInboundDelivery(Long.MIN_VALUE,48)); assertEquals(1,confirms)
        assertEquals(7,output.position()); assertEquals(1507,output.limit()); assertEquals(ByteOrder.LITTLE_ENDIAN,output.order())
        malformed = true
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE),session.receiveInboundPacket(output))
        assertEquals(1,closes)
    }

    @Test fun oneControlPollOwnerStopsOnConcurrentCancelOrClose() {
        for (close in listOf(false,true)) {
            val entered = java.util.concurrent.CountDownLatch(1)
            val release = java.util.concurrent.CountDownLatch(1)
            var nativeCalls = 0; var closes = 0
            val calls = Proxy.newProxyInstance(ProductionNativeCallsV1::class.java.classLoader,
                arrayOf(ProductionNativeCallsV1::class.java)) { _, method, _ ->
                check(method.name == "nextControl"); nativeCalls++; entered.countDown()
                check(release.await(5,java.util.concurrent.TimeUnit.SECONDS)); 20
            } as ProductionNativeCallsV1
            val parent = ProductionNativeParentV1({0},{closes++;0}).apply { bind(-9) }
            val snapshot = (ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(ProductionResultCodecV1Test.tunSnapshot())) as NativeProductResult.Success).value
            val session = ProductionNativeSessionV1(snapshot,parent,calls) { error("unexpected stream") }
            val executor = java.util.concurrent.Executors.newSingleThreadExecutor()
            try {
                val result = executor.submit<NativeProductResult<NativeControlEvent>> { session.nextControl(ByteBuffer.allocateDirect(32800)) }
                assertTrue(entered.await(5,java.util.concurrent.TimeUnit.SECONDS))
                assertEquals(NativeProductResult.Failure(ProductFailureCode.RESOURCE_LIMIT),session.nextControl(ByteBuffer.allocateDirect(32800)))
                if (close) session.close() else assertEquals(NativeProductResult.Success(Unit),session.cancel())
                release.countDown()
                assertEquals(NativeProductResult.Failure(ProductFailureCode.CANCELLED),result.get(5,java.util.concurrent.TimeUnit.SECONDS))
                assertEquals(1,nativeCalls)
                session.close(); assertEquals(1,closes)
            } finally { release.countDown(); executor.shutdownNow() }
        }
    }

    @Test fun controlRetriesPrivatelyAndRejectsSequenceRegression() {
        var entered = 0; var closes = 0
        val output = ByteBuffer.allocateDirect(100000).order(ByteOrder.LITTLE_ENDIAN).apply { position(7); limit(32807) }
        var firstMetadata: Any? = null
        val calls = Proxy.newProxyInstance(ProductionNativeCallsV1::class.java.classLoader,
            arrayOf(ProductionNativeCallsV1::class.java)) { _, method, args ->
            check(method.name == "nextControl"); entered++
            assertEquals(-9L,args[0]); assertSame(output,args[1]); assertEquals(7,args[2]); assertEquals(32807,args[3])
            val metadata = args[4] as LongArray
            if (entered == 1) { firstMetadata = metadata; 20 } else {
                if (entered == 2) assertSame(firstMetadata,metadata)
                val event = ByteBuffer.allocate(32).put(byteArrayOf(75,80,67,49,1,2,0,0)).putInt(32).putLong(1).putLong(1).putInt(0).array()
                event.forEachIndexed { i, byte -> output.put(7+i,byte) }; metadata[0] = 32; 0
            }
        } as ProductionNativeCallsV1
        val parent = ProductionNativeParentV1({0},{closes++;0}).apply { bind(-9) }
        val snapshot = (ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(ProductionResultCodecV1Test.tunSnapshot())) as NativeProductResult.Success).value
        val session = ProductionNativeSessionV1(snapshot,parent,calls) { error("unexpected stream") }
        assertEquals(NativeProductResult.Success(NativeControlEvent.TransportConnecting(1uL,1uL)),session.nextControl(output))
        assertEquals(2,entered); assertEquals(7,output.position()); assertEquals(32807,output.limit()); assertEquals(ByteOrder.LITTLE_ENDIAN,output.order())
        assertEquals(0L,(firstMetadata as LongArray)[0])
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE),session.nextControl(output))
        assertEquals(1,closes); assertSame(snapshot,session.openingSnapshot)
    }

    @Test fun packetPrefixPreservesBorrowAndUnknownStatusRetiresOwner() {
        var entered = 0; var closes = 0; var status = 0
        val bytes = ByteBuffer.allocateDirect(100000).asReadOnlyBuffer().order(ByteOrder.LITTLE_ENDIAN)
        bytes.position(7); bytes.limit(55)
        val calls = Proxy.newProxyInstance(ProductionNativeCallsV1::class.java.classLoader,
            arrayOf(ProductionNativeCallsV1::class.java)) { _, method, args ->
            check(method.name == "submitPacket"); entered++
            assertEquals(-9L,args[0]); assertSame(bytes,args[1]); assertEquals(7,args[2]); assertEquals(8,args[3]); status
        } as ProductionNativeCallsV1
        val parent = ProductionNativeParentV1({0},{closes++;0}).apply { bind(-9) }
        val snapshot = (ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(ProductionResultCodecV1Test.tunSnapshot())) as NativeProductResult.Success).value
        val session = ProductionNativeSessionV1(snapshot,parent,calls) { error("unexpected stream") }
        for (length in listOf(-1,0,49)) assertEquals(NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT),session.submitOutboundPacket(bytes,length))
        assertEquals(0,entered)
        repeat(266) { assertEquals(0,parent.beginCall()) }
        assertEquals(NativeProductResult.Failure(ProductFailureCode.RESOURCE_LIMIT),session.submitOutboundPacket(bytes,1))
        repeat(266) { parent.finishCall() }
        assertEquals(NativeProductResult.Success(Unit),session.submitOutboundPacket(bytes,1))
        assertEquals(7,bytes.position()); assertEquals(55,bytes.limit()); assertEquals(ByteOrder.LITTLE_ENDIAN,bytes.order())
        status = 99
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE),session.submitOutboundPacket(bytes,1))
        assertEquals(1,closes); assertEquals(2,entered)
        session.close(); assertEquals(1,closes)
    }

    @Test fun scalarCommandsPreserveRawIdsAndExplicitReconnectMapping() {
        val seen = mutableListOf<List<Long>>()
        val calls = object : ProductionNativeCallsV1 {
            override fun runProbe(parent: Long, request: ByteBuffer, position: Int, limit: Int, output: ByteBuffer, outputPosition: Int, outputLimit: Int, metadata: LongArray): Int = error("unexpected probe")
            override fun openStream(parent: Long, request: ByteBuffer, position: Int, limit: Int, metadata: LongArray): Int = error("unexpected stream")
            override fun receivePacket(parent: Long, output: ByteBuffer, position: Int, limit: Int, metadata: LongArray): Int = error("unexpected receive")
            override fun nextControl(parent: Long, output: ByteBuffer, position: Int, limit: Int, metadata: LongArray): Int = error("unexpected control")
            override fun submitPacket(parent: Long, input: ByteBuffer, position: Int, limit: Int): Int = error("unexpected packet")
            override fun confirmSocket(parent: Long, token: Long, protected: Int, hasNetwork: Int, network: Long): Int {
                seen += listOf(parent,token,protected.toLong(),hasNetwork.toLong(),network); return 0
            }
            override fun confirmPacket(parent: Long, token: Long, length: Long): Int { seen += listOf(parent,token,length); return 3 }
            override fun rejectPacket(parent: Long, token: Long): Int { seen += listOf(parent,token); return 0 }
            override fun reconnect(parent: Long, reason: Int): Int { seen += listOf(parent,reason.toLong()); return 0 }
            override fun handover(parent: Long, hasNetwork: Int, network: Long): Int { seen += listOf(parent,hasNetwork.toLong(),network); return 0 }
        }
        val owner = ProductionNativeParentV1({0},{0}).apply { bind(Long.MIN_VALUE) }
        val decoded = ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(ProductionResultCodecV1Test.tunSnapshot())) as NativeProductResult.Success
        val session = ProductionNativeSessionV1(decoded.value,owner,calls) { error("unexpected stream") }
        assertEquals(NativeProductResult.Success(Unit),session.confirmSocketProtection(-1,true,Long.MIN_VALUE))
        assertEquals(NativeProductResult.Failure(ProductFailureCode.OPERATION_INTERRUPTED),session.confirmInboundDelivery(-2,17))
        assertEquals(NativeProductResult.Success(Unit),session.rejectInboundDelivery(-3))
        for (reason in listOf(NativeReconnectReason.USER_REQUEST,NativeReconnectReason.NETWORK_FAILURE,NativeReconnectReason.SETTINGS_CHANGE))
            assertEquals(NativeProductResult.Success(Unit),session.requestReconnect(reason))
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT),session.requestReconnect(NativeReconnectReason.HANDOVER))
        assertEquals(NativeProductResult.Success(Unit),session.requestHandover(null))
        assertEquals(listOf(listOf(Long.MIN_VALUE,-1,1,1,Long.MIN_VALUE),listOf(Long.MIN_VALUE,-2,17),
            listOf(Long.MIN_VALUE,-3),listOf(Long.MIN_VALUE,1),listOf(Long.MIN_VALUE,2),listOf(Long.MIN_VALUE,3),
            listOf(Long.MIN_VALUE,0,0)),seen)
        assertEquals(NativeProductResult.Success(Unit),session.cancel())
        assertEquals(NativeProductResult.Failure(ProductFailureCode.CANCELLED),session.rejectInboundDelivery(-3))
        session.close()
    }
}
