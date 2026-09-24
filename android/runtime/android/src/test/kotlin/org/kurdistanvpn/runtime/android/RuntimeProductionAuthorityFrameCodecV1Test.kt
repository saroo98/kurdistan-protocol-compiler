// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.nio.ByteBuffer
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.runtime.api.*

class RuntimeProductionAuthorityFrameCodecV1Test {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val payload = hex("4b435431010000000000002500000001000000010001000100000001000000000b16212c37")
    // Independently framed literals, tags calculated using .NET HMACSHA256.
    private val vectors = listOf(
        "4b524146030000b6000000fb0000002511111111111111111111111111111111555555555555555555555555555555552222222222222222222222222222222200000000000000010101000000000000000200000000000003e83333333333333333333333333333333366666666666666666666666666666666444444444444444444444444444444440000000000000001000000000000000200000000000003e8000000000000118000000000000000fb000200014b435431010000000000002500000001000000010001000100000001000000000b16212c371e3944641329d33d256dbf0e67d1675ee48ccc04d6ac700059ee376078c572bc",
        "4b524146030000b6000000d60000000011111111111111111111111111111111555555555555555555555555555555552222222222222222222222222222222200000000000000010201000000000000000200000000000003e83333333333333333333333333333333366666666666666666666666666666666444444444444444444444444444444440000000000000001000000000000000200000000000003e8000000000000118000000000000000d6000200012bd5da528145c92145d3e51490b2c5b06b4f16f9fdc6511b701d59899bda4641",
        "4b524146030000b6000000d60000000011111111111111111111111111111111555555555555555555555555555555552222222222222222222222222222222200000000000000010301000000000000000200000000000003e83333333333333333333333333333333366666666666666666666666666666666444444444444444444444444444444440000000000000001000000000000000200000000000003e8000000000000118000000000000000d600020001ea34bd9712962a231071672f3d7736cb00b48612409dbfb540c4482416656977"
    ).map(::hex)
    private fun request(purpose: RuntimeAuthorityPurpose): RuntimeProductionAuthorityRequestV1 =
        RuntimeProductionAuthorityRequestV1(RuntimeAuthorityRequest("1".repeat(32),"5".repeat(32),"2".repeat(32),1,purpose,
            RuntimeAuthorityTrigger.MANUAL,2,1000,"3".repeat(32),"6".repeat(32),
            RuntimeDescriptorBinding("4".repeat(32),1,2,1000,0x1180,if(purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY) 251 else 214,0),2,0))

    @Test fun exactAllPurposeGoldenVectorsAndOneUseOwnership() {
        RuntimeAuthorityPurpose.entries.forEachIndexed { index, purpose ->
            val request=request(purpose)
            val input=if(index == 0) payload else byteArrayOf()
            val transferredKey=ByteArray(32) { 7 }
            val sealer=RuntimeProductionAuthorityFrameCodecV1.sealer(transferredKey,request)
            assertTrue(transferredKey.all { it == 0.toByte() })
            assertArrayEquals(vectors[index],sealer.seal(input))
            assertNull(sealer.seal(input))
            val verifier=RuntimeProductionAuthorityFrameCodecV1.verifier(ByteArray(32) { 7 },request)
            val result=verifier.verifyAndConsume(vectors[index],request.request.descriptor,100) as RuntimeProductionFrameVerificationV1.Verified
            assertEquals(request,result.authority.request)
            val snapshot=result.authority.takeCapture()
            if(index == 0) {
                assertNotNull(snapshot)
                val out=ByteBuffer.allocate(1); snapshot!!.copyRecipientPrivateTo(out)
                assertEquals(44,out.get(0).toInt()); snapshot.close()
            } else assertNull(snapshot)
            assertNull(result.authority.takeCapture()); result.authority.close()
            assertEquals(RuntimeFrameRejection.TERMINAL,(verifier.verifyAndConsume(vectors[index],request.request.descriptor,100) as RuntimeProductionFrameVerificationV1.Rejected).reason)
        }
    }
    @Test fun exactSizeAndBindingRejections() {
        assertEquals(2_721_789,RuntimeProductionAuthorityFrameCodecV1.encodedLength(2_721_575))
        assertEquals(214,RuntimeProductionAuthorityFrameCodecV1.encodedLength(0))
        assertThrows(IllegalArgumentException::class.java) { RuntimeProductionAuthorityFrameCodecV1.encodedLength(2_721_576) }
        val expected=request(RuntimeAuthorityPurpose.FULL_AUTHORITY)
        val frame=vectors[0]
        val variants=listOf(expected.request.copy(providerEpoch="7".repeat(32)),expected.request.copy(frameChannelId="7".repeat(32)),
            expected.request.copy(purpose=RuntimeAuthorityPurpose.PRE_ACTIVE),expected.request.copy(revision=4))
        variants.forEach {
            assertTrue(RuntimeProductionAuthorityFrameCodecV1.verifier(ByteArray(32) { 7 },RuntimeProductionAuthorityRequestV1(it))
                .verifyAndConsume(frame,it.descriptor,100) is RuntimeProductionFrameVerificationV1.Rejected)
        }
        for(offset in listOf(4,5,6,7,181,frame.lastIndex)) {
            val changed=frame.copyOf(); changed[offset]=(changed[offset].toInt() xor 1).toByte()
            assertTrue(RuntimeProductionAuthorityFrameCodecV1.verifier(ByteArray(32) { 7 },expected)
                .verifyAndConsume(changed,expected.request.descriptor,100) is RuntimeProductionFrameVerificationV1.Rejected)
        }
        assertEquals(RuntimeFrameRejection.EXPIRED,(RuntimeProductionAuthorityFrameCodecV1.verifier(ByteArray(32) { 7 },expected)
            .verifyAndConsume(frame,expected.request.descriptor,1000) as RuntimeProductionFrameVerificationV1.Rejected).reason)
        assertTrue(RuntimeProductionAuthorityFrameCodecV1.verifier(ByteArray(32) { 7 },expected)
            .verifyAndConsume(frame,expected.request.descriptor.copy(inode=3),100) is RuntimeProductionFrameVerificationV1.Rejected)
        val legacyRequest=expected.request.copy(descriptor=expected.request.descriptor.copy(length=250))
        val legacy=RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 },legacyRequest).seal(payload)!!
        assertTrue(RuntimeProductionAuthorityFrameCodecV1.verifier(ByteArray(32) { 7 },expected)
            .verifyAndConsume(legacy,expected.request.descriptor,100) is RuntimeProductionFrameVerificationV1.Rejected)
        assertTrue(RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 7 },expected.request)
            .verifyAndConsume(frame,expected.request.descriptor,100) is RuntimeFrameVerification.Rejected)
    }
    @Test fun malformedKctAndWrongPurposeNeverYieldCapture() {
        val request=request(RuntimeAuthorityPurpose.FULL_AUTHORITY)
        val invalid=payload.copyOf(); invalid[0]=0
        assertNull(RuntimeProductionAuthorityFrameCodecV1.sealer(ByteArray(32) { 7 },request).seal(invalid))
        assertNull(RuntimeProductionAuthorityFrameCodecV1.sealer(ByteArray(32) { 7 },request(RuntimeAuthorityPurpose.PRE_TUN)).seal(payload))
    }
}
