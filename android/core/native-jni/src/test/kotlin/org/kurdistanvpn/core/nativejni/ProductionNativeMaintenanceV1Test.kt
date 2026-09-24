// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*

class ProductionNativeMaintenanceV1Test {
    @Test fun disconnectedBindingCannotBeUsedAfterLocalOwnerLoss() {
        val calls=CandidateCalls();val parent=ProductionNativeParentV1({0},{calls.closes++;0},1).also{it.bind(-7)}
        val binding=object:AndroidProductionProbeBindingV1 {
            override fun permits(target:Int)=false
            override fun isCurrent()=false
            override fun observe(event:NativeControlEvent){}
            override fun invalidate(){}
        }
        val owner=ProductionNativeMaintenanceV1(parent,1uL,calls,binding)
        assertEquals(NativeProductResult.Failure(ProductFailureCode.OPERATION_INTERRUPTED),owner.runProbe(NativeProbeRequest(1,NativeProbeMethod.TCP_CONNECT,1000,2000,2)))
        assertNull(calls.input)
        // An associated maintenance opening deliberately has no disconnected
        // probe role, but retains its real update authority and lifecycle.
        val checked=owner.checkSameDeploymentUpdate(NativeUpdateRequest(1000),ByteBuffer.allocateDirect(38))
        assertTrue(checked is NativeProductResult.Success)
        assertEquals(NativeProductResult.Success(Unit),owner.releaseUpdate(Long.MIN_VALUE+1))
        owner.close();assertEquals(1,calls.closes)
    }
    @Test fun capturedMaintenanceAdoptsBeforeRecheckingTrustedGeneration() {
        for (changed in listOf(false,true)) {
            var generationReads=0;var adopted:java.io.Closeable?=null;var closes=0
            var request:ByteBuffer?=null
            val delegate=java.lang.reflect.Proxy.newProxyInstance(AndroidProductionPlatformDelegateV1::class.java.classLoader,
                arrayOf(AndroidProductionPlatformDelegateV1::class.java)){_,method,args ->
                assertEquals(-3L,args[0])
                when(method.name){
                    "capturedGeneration" -> { generationReads++;if(changed && generationReads==2) 8L else Long.MIN_VALUE }
                    "captureSizes" -> {(args[1] as IntArray).fill(1);0}
                    "captureCopyInto" -> {(args[6] as IntArray).fill(1);0}
                    else -> error("unexpected delegate call")
                }
            } as AndroidProductionPlatformDelegateV1
            val result=openMaintenanceCapturedV1(delegate,-3,
                nativeOpen={input,metadata->request=input;assertEquals(2,input.get(5).toInt());metadata[0]=-7;0},
                cancel={0},close={closes++;0},adopt={adopted=it},failedOpening={error("claimed")},
                construct={parent,generation->assertSame(adopted,parent);assertEquals(Long.MIN_VALUE.toULong(),generation);"constructed"})
            assertEquals(2,generationReads)
            assertEquals(if(changed) NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE) else NativeProductResult.Success("constructed"),result)
            assertEquals(if(changed)1 else 0,closes)
            for(i in 0 until request!!.capacity())assertEquals(0.toByte(),request!!.get(i))
            adopted!!.close();assertEquals(1,closes)
        }
    }
    private class CandidateCalls : ProductionNativeMaintenanceCallsV1 {
        var malformed = false
        var consumed = false
        var materializeStatus = 0
        var decision = 0
        var checkStatus = 0
        var probeMode = 0
        var closes = 0
        var releases = 0
        var candidateId = Long.MIN_VALUE+1
        var input: ByteBuffer? = null
        var metadata: LongArray? = null
        override fun checkUpdate(parent: Long, request: ByteBuffer, position: Int, limit: Int,
            output: ByteBuffer, outputPosition: Int, outputLimit: Int, metadata: LongArray): Int {
            assertEquals(-7L,parent); assertEquals(3,limit-position)
            input=request; this.metadata=metadata
            if (checkStatus != 0) return checkStatus
            if (consumed) return 3
            if (decision != 0) {
                output.put(outputPosition,1);output.put(outputPosition+1,0);output.put(outputPosition+2,decision.toByte())
                metadata[0]=3;return 0
            }
            val bytes = byteArrayOf(1,0,0, 128.toByte(),0,0,0,0,0,0,1, 1,
                0,0,0,0,0,0,0,2, 0,0,0,0, 0,0,0,0,0,0,0,0,0,0, 0,0,0,4)
            for (i in 0..7) bytes[3+i] = (candidateId ushr (56-8*i)).toByte()
            if (malformed) bytes[11]=2
            for(i in bytes.indices) output.put(outputPosition+i,bytes[i])
            metadata[0]=38; return 0
        }
        override fun materialize(parent: Long, candidate: Long, output: ByteBuffer, position: Int, limit: Int, metadata: LongArray): Int {
            assertEquals(-7L,parent); assertEquals(candidateId,candidate);this.metadata=metadata
            if(consumed)return 3
            if(limit-position<4)return 4
            consumed=true
            if(materializeStatus!=0)return materializeStatus
            for(i in 0..3)output.put(position+i,(i+1).toByte())
            metadata[0]=4;return 0
        }
        override fun runProbe(parent: Long,request: ByteBuffer,position: Int,limit: Int,output: ByteBuffer,outputPosition: Int,outputLimit: Int,metadata: LongArray):Int {
            assertEquals(-7L,parent);assertEquals(9,limit-position);input=request;this.metadata=metadata
            if(probeMode==3){request.limit(0);output.limit(0);error("injected")}
            val bytes=byteArrayOf(1,1,1,1,0,1,1,0,0,0,0,0,0,0,0,0,3,232.toByte(),0,0,8)
            if(probeMode==1)bytes[1]=2
            for(i in bytes.indices)output.put(outputPosition+i,bytes[i])
            metadata[0]=if(probeMode==2)Long.MAX_VALUE else 21
            return 0
        }
        override fun release(parent: Long,candidate: Long):Int {
            assertEquals(-7L,parent);assertEquals(candidateId,candidate);releases++
            if(consumed)return 3
            consumed=true;return 0
        }
    }
    private fun maintenance(calls:CandidateCalls):ProductionNativeMaintenanceV1 {
        val parent=ProductionNativeParentV1({0},{calls.closes++;0},1).also{it.bind(-7)}
        return ProductionNativeMaintenanceV1(parent,1uL,calls)
    }

    @Test fun candidateRawIdentityAndBorrowedSlicesSurviveShortMaterialize() {
        val calls=CandidateCalls();val owner=maintenance(calls)
        val preview=ByteBuffer.allocateDirect(80).order(ByteOrder.LITTLE_ENDIAN).apply{position(7);limit(45)}
        val checked=owner.checkSameDeploymentUpdate(NativeUpdateRequest(1000),preview) as NativeProductResult.Success
        val candidate=(checked.value as NativeUpdateCheck.Candidate).candidate
        assertEquals(Long.MIN_VALUE+1,candidate.handle);assertEquals(2uL,candidate.generation)
        assertEquals(7,preview.position());assertEquals(45,preview.limit());assertEquals(0L,calls.metadata!![0])
        for(i in 0 until calls.input!!.capacity())assertEquals(0.toByte(),calls.input!!.get(i))
        val artifact=ByteBuffer.allocateDirect(20).apply{position(5);limit(8)}
        assertEquals(NativeProductResult.Failure(ProductFailureCode.SIZE_LIMIT),owner.materializeVerifiedUpdate(candidate.handle,artifact))
        assertFalse(calls.consumed);artifact.limit(9)
        assertEquals(NativeProductResult.Success(4),owner.materializeVerifiedUpdate(candidate.handle,artifact))
        assertTrue(calls.consumed);assertEquals(5,artifact.position());assertEquals(9,artifact.limit())
        for(i in 0..3)assertEquals((i+1).toByte(),artifact.get(5+i))
        assertEquals(NativeProductResult.Failure(ProductFailureCode.OPERATION_INTERRUPTED),owner.materializeVerifiedUpdate(candidate.handle,artifact))
        owner.close();assertEquals(1,calls.closes)
    }

    @Test fun malformedCandidateRetiresParentAndConsumedFailureNeverResurrects() {
        val malformed=CandidateCalls().apply{this.malformed=true};val owner=maintenance(malformed)
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE),owner.checkSameDeploymentUpdate(NativeUpdateRequest(1000),ByteBuffer.allocateDirect(38)))
        assertEquals(1,malformed.closes);assertEquals(0,malformed.releases)
        val calls=CandidateCalls().apply{materializeStatus=18};val second=maintenance(calls)
        val candidate=((second.checkSameDeploymentUpdate(NativeUpdateRequest(1000),ByteBuffer.allocateDirect(38)) as NativeProductResult.Success).value as NativeUpdateCheck.Candidate).candidate
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE),second.materializeVerifiedUpdate(candidate.handle,ByteBuffer.allocateDirect(4)))
        assertTrue(calls.consumed);assertEquals(1,calls.closes);assertEquals(0,calls.releases)
    }

    @Test fun releaseUsesActualRepeatedNativeRejection() {
        val calls=CandidateCalls();val owner=maintenance(calls)
        val candidate=((owner.checkSameDeploymentUpdate(NativeUpdateRequest(1000),ByteBuffer.allocateDirect(38)) as NativeProductResult.Success).value as NativeUpdateCheck.Candidate).candidate
        assertEquals(NativeProductResult.Success(Unit),owner.releaseUpdate(candidate.handle))
        assertEquals(NativeProductResult.Failure(ProductFailureCode.OPERATION_INTERRUPTED),owner.releaseUpdate(candidate.handle))
        assertEquals(2,calls.releases);owner.close()
    }

    @Test fun injectedCompletedDecisionDoesNotReleaseExistingCandidate() {
        // Deliberate decoder-boundary injection, not a normal native sequence:
        // the actual native owner rejects a held candidate before admission.
        val calls=CandidateCalls();val owner=maintenance(calls)
        owner.checkSameDeploymentUpdate(NativeUpdateRequest(1000),ByteBuffer.allocateDirect(38))
        calls.decision=7
        assertEquals(NativeProductResult.Failure(ProductFailureCode.RATE_LIMITED),owner.checkSameDeploymentUpdate(NativeUpdateRequest(1000),ByteBuffer.allocateDirect(38)))
        assertEquals(0,calls.closes);assertEquals(0,calls.releases)
        assertEquals(NativeProductResult.Success(Unit),owner.releaseUpdate(Long.MIN_VALUE+1));owner.close()
    }

    @Test fun heldCandidateSurvivesNativeP1InvalidState() {
        val calls=CandidateCalls();val owner=maintenance(calls)
        owner.checkSameDeploymentUpdate(NativeUpdateRequest(1000),ByteBuffer.allocateDirect(38))
        calls.checkStatus=3
        assertEquals(NativeProductResult.Failure(ProductFailureCode.OPERATION_INTERRUPTED),
            owner.checkSameDeploymentUpdate(NativeUpdateRequest(1000),ByteBuffer.allocateDirect(38)))
        assertEquals(0,calls.closes);assertEquals(0,calls.releases)
        assertEquals(NativeProductResult.Success(Unit),owner.releaseUpdate(Long.MIN_VALUE+1));owner.close()
    }

    @Test fun expiredCandidateBookkeepingAcceptsFreshNativePublication() {
        val calls=CandidateCalls();val owner=maintenance(calls)
        owner.checkSameDeploymentUpdate(NativeUpdateRequest(1000),ByteBuffer.allocateDirect(38))
        calls.consumed=true // Native candidate timer retired only the candidate.
        assertEquals(NativeProductResult.Failure(ProductFailureCode.OPERATION_INTERRUPTED),owner.releaseUpdate(calls.candidateId))
        calls.candidateId++
        calls.consumed=false
        val fresh=owner.checkSameDeploymentUpdate(NativeUpdateRequest(1000),ByteBuffer.allocateDirect(38))
        assertTrue(fresh is NativeProductResult.Success)
        assertEquals(calls.candidateId,((fresh as NativeProductResult.Success).value as NativeUpdateCheck.Candidate).candidate.handle)
        assertEquals(0,calls.closes)
        assertEquals(NativeProductResult.Success(4),owner.materializeVerifiedUpdate(calls.candidateId,ByteBuffer.allocateDirect(4)))
        owner.close()
    }

    @Test fun duplicateNativeCandidatePublicationStillRetiresParent() {
        val calls=CandidateCalls();val owner=maintenance(calls)
        owner.checkSameDeploymentUpdate(NativeUpdateRequest(1000),ByteBuffer.allocateDirect(38))
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE),owner.checkSameDeploymentUpdate(NativeUpdateRequest(1000),ByteBuffer.allocateDirect(38)))
        assertEquals(1,calls.closes)
    }

    @Test fun freshCompletedRateLimitHasNoCandidateCleanup() {
        val calls=CandidateCalls().apply{decision=7};val owner=maintenance(calls)
        assertEquals(NativeProductResult.Failure(ProductFailureCode.RATE_LIMITED),
            owner.checkSameDeploymentUpdate(NativeUpdateRequest(1000),ByteBuffer.allocateDirect(38)))
        assertEquals(0,calls.closes);assertEquals(0,calls.releases)
        assertFalse(calls.consumed);owner.close();assertEquals(1,calls.closes)
    }

    @Test fun disconnectedProbeRejectsBadPathMetadataAndWipesExceptionCapacity() {
        for(mode in 0..3){
            val calls=CandidateCalls().apply{probeMode=mode};val owner=maintenance(calls)
            val result=owner.runProbe(NativeProbeRequest(1,NativeProbeMethod.TCP_CONNECT,1000,2000,2))
            if(mode==0){
                val value=(result as NativeProductResult.Success).value
                assertEquals(NativeProbePath.DISCONNECTED_TCP_CONNECT,value.path)
                assertEquals(NativeProbeCompletion.TIMED_OUT,value.completion)
                assertEquals(0,calls.closes);assertEquals(NativeProductResult.Success(Unit),owner.cancel())
                assertEquals(0,calls.closes)
            }else{assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE),result);assertEquals(1,calls.closes)}
            assertEquals(0L,calls.metadata!![0])
            for(i in 0 until calls.input!!.capacity())assertEquals(0.toByte(),calls.input!!.get(i))
            owner.close();assertEquals(1,calls.closes)
        }
    }
    @Test fun openingAdoptsRawParentBeforeConstructionAndBoundsCalls() {
        var values: LongArray? = null
        var adopted: ProductionNativeParentV1? = null
        var closes = 0
        val result = openMaintenanceOwnedV1(
            acquire = { values = it; it[0] = Long.MIN_VALUE; 0 },
            cancel = { 0 }, close = { assertEquals(Long.MIN_VALUE,it); closes++; 0 },
            adopt = { adopted = it as ProductionNativeParentV1 }, failedOpening = { error("claimed") },
            construct = { parent ->
                assertSame(adopted,parent)
                assertEquals(0,parent.beginCall()); assertEquals(5,parent.beginCall()); parent.finishCall()
                parent
            }) as NativeProductResult.Success
        assertEquals(0L,values!![0]);assertEquals(0,closes)
        result.value.close();result.value.close();assertEquals(1,closes)
    }

    @Test fun openingConstructionFailureClosesAndNeverFakesUnclaimedCleanup() {
        for (mode in listOf("construct","adopt","native")) {
            var closes=0;var failed=0;var values:LongArray?=null
            val result=openMaintenanceOwnedV1(
                acquire={values=it;if(mode!="native")it[0]=-7; if(mode=="native")5 else 0},
                cancel={0},close={closes++;0},
                adopt={if(mode=="adopt")error("injected")},failedOpening={failed++},
                construct={error("injected")})
            assertEquals(NativeProductResult.Failure(if(mode=="native")ProductFailureCode.RESOURCE_LIMIT else ProductFailureCode.INTERNAL_FAILURE),result)
            assertEquals(if(mode=="native")0 else 1,closes)
            assertEquals(if(mode=="native")1 else 0,failed)
            assertEquals(0L,values!![0])
        }
    }
}
