// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicInteger
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.ProductFailureCode

internal object BootstrapBindingCodecV1 {
    fun decodeLegacy(input: ByteBuffer): NativeLegacyBootstrapFactsV1 {
        require(input.remaining() == 41)
        val reader=input.duplicate().order(ByteOrder.BIG_ENDIAN)
        val generation=reader.long.toULong()
        val digest=ByteArray(32)
        return try { reader.get(digest);NativeLegacyBootstrapFactsV1(generation,digest,reader.get().toInt() and 255) }
        finally { digest.fill(0) }
    }
    fun decodeProduction(input: ByteBuffer): NativeProductionBootstrapFactsV1 {
        require(input.remaining() == 44)
        val reader=input.duplicate().order(ByteOrder.BIG_ENDIAN)
        val generation=reader.long.toULong()
        val digest=ByteArray(32)
        return try {
            reader.get(digest)
            NativeProductionBootstrapFactsV1(generation,digest,reader.short.toInt() and 65535,
                reader.get().toInt() and 255,reader.get().toInt() and 255)
        } finally { digest.fill(0) }
    }
}

/** 0 idle, 1 synchronously owned, 2 cleanup/capacity unproven (permanent refusal). */
internal class BootstrapBindingGuardV1 {
    private val state=AtomicInteger(0)
    fun tryAcquire()=state.compareAndSet(0,1)
    fun finish(cleanupProven: Boolean) { check(state.compareAndSet(1,if(cleanupProven)0 else 2)) }
}

/** One guard for both methods and all NativeBridge instances in this process. */
internal val processBootstrapBindingGuardV1=BootstrapBindingGuardV1()

internal typealias BootstrapNativeCallV1 = (Array<ByteBuffer>, ByteBuffer, ByteBuffer?, ByteBuffer?, ByteBuffer?) -> Int

/** Takes the first decoded owner; second-lane failure must retire it too. */
internal fun completeBootstrapSelectorPairV1(facts:NativeProductionBootstrapFactsV1,
    active:NativeActiveProductionSelectorsV1,disconnected:ByteBuffer?,length:Int):NativeProductionBootstrapReadV1 {
    var second:NativeDisconnectedProductionSelectorsV1?=null
    return try {
        val view=checkNotNull(disconnected).duplicate().apply{limit(length)}
        second=ProductionSelectorCodecV1.decodeDisconnected(view,facts)
        NativeProductionBootstrapReadV1(facts,active,second)
    } catch(error:Throwable) {try{active.close()}finally{second?.close()};throw error}
}

/** Actual wrapper staging, also exercised without loading a native library. */
internal object BootstrapBindingCallsV1 : BootstrapBindingCallOwnerV1(processBootstrapBindingGuardV1)

/** The actual call owner takes its guard explicitly; production has one instance,
 * while tests can isolate terminal anomalies without a reset hook. */
internal open class BootstrapBindingCallOwnerV1(private val guard:BootstrapBindingGuardV1) {
    fun legacy(material:NativeBootstrapMaterialV1,policy:ByteBuffer,mapError:(Int)->OperationError,
        invoke:BootstrapNativeCallV1):NativeResult<NativeLegacyBootstrapFactsV1> =
        execute(material,policy,false,{NativeResult.Failure(mapError(it))},invoke) { facts,_,_,_ ->
            NativeResult.Success(BootstrapBindingCodecV1.decodeLegacy(facts))
        }
    fun production(material:NativeBootstrapMaterialV1,settings:ByteBuffer,
        invoke:BootstrapNativeCallV1):NativeProductResult<NativeProductionBootstrapReadV1> =
        execute(material,settings,true,{NativeProductResult.Failure(productionFailureV1(it))},invoke) { facts,active,disconnected,metadata ->
            val decoded=BootstrapBindingCodecV1.decodeProduction(facts)
            val lengths=checkNotNull(metadata).duplicate().order(ByteOrder.BIG_ENDIAN)
            val activeLength=lengths.int;val disconnectedLength=lengths.int
            require(activeLength in 54..512 && disconnectedLength in 54..512)
            val a=ProductionSelectorCodecV1.decodeActive(checkNotNull(active).duplicate().apply{limit(activeLength)},decoded)
            NativeProductResult.Success(completeBootstrapSelectorPairV1(decoded,a,disconnected,disconnectedLength))
        }

    private fun <T> execute(material:NativeBootstrapMaterialV1,fifth:ByteBuffer,production:Boolean,
        failure:(Int)->T,invoke:BootstrapNativeCallV1,
        decode:(ByteBuffer,ByteBuffer?,ByteBuffer?,ByteBuffer?)->T):T {
        val invalid=if(production)2 else 1
        val size=if(production)4 else 2
        val resource=if(production)5 else 24
        val internal=if(production)18 else 14
        if(!guard.tryAcquire())return failure(resource)
        val owned=arrayOfNulls<ByteBuffer>(9)
        var clean=false
        var capacityProven=true
        try {
            val sources=arrayOf(material.verifyRequest,material.activationRecord,material.recipientRequest,material.recipientPrivate,fifth)
            val maxima=intArrayOf(1405996,1118299,512,128,if(production)196608 else 16777)
            for(i in sources.indices) {
                if(sources[i].remaining()<=0)return failure(invalid)
                if(sources[i].remaining()>maxima[i])return failure(size)
            }
            for(i in sources.indices) {
                owned[i]=ByteBuffer.allocateDirect(sources[i].remaining())
                checkNotNull(owned[i]).put(sources[i].duplicate()).flip()
            }
            owned[5]=ByteBuffer.allocateDirect(if(production)44 else 41)
            if(production) {
                owned[6]=ByteBuffer.allocateDirect(512);owned[7]=ByteBuffer.allocateDirect(512);owned[8]=ByteBuffer.allocateDirect(8)
            }
            val code=invoke(Array(5){checkNotNull(owned[it])},checkNotNull(owned[5]),owned[6],owned[7],owned[8])
            // Private Go/C/JNI signal only, never a canonical error enum entry.
            if(code == -6401) {capacityProven=false;return failure(internal)}
            if(code!=0)return failure(code)
            return decode(checkNotNull(owned[5]),owned[6],owned[7],owned[8])
        } catch(_:Throwable) {return failure(internal)}
        finally {
            try {
                owned.forEach { buffer -> if(buffer!=null) {
                    val full=buffer.duplicate().apply{clear()}
                    for(index in 0 until full.capacity())full.put(index,0)
                } }
                clean=true
            } finally {guard.finish(clean && capacityProven)}
        }
    }
}
