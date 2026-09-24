// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.lang.reflect.Modifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProductionNativeAbiV1Test {
    /** Literal descriptors are derived from the accepted ABI, not the implementation. */
    @Test fun exactCanonicalNativeDescriptors() {
        val expected = mapOf(
            "nativeProdOpenV1" to "(Ljava/nio/ByteBuffer;IIJLjava/nio/ByteBuffer;II[J)I",
            "nativeProdNextControlV1" to "(JLjava/nio/ByteBuffer;II[J)I",
            "nativeProdConfirmSocketV1" to "(JJIIJ)I",
            "nativeProdSubmitPacketV1" to "(JLjava/nio/ByteBuffer;II)I",
            "nativeProdReceivePacketV1" to "(JLjava/nio/ByteBuffer;II[J)I",
            "nativeProdConfirmPacketV1" to "(JJJ)I",
            "nativeProdRejectPacketV1" to "(JJ)I",
            "nativeProdOpenStreamV1" to "(JLjava/nio/ByteBuffer;II[J)I",
            "nativeProdRunProbeV1" to "(JLjava/nio/ByteBuffer;IILjava/nio/ByteBuffer;II[J)I",
            "nativeProdReconnectV1" to "(JI)I",
            "nativeProdHandoverV1" to "(JIJ)I",
            "nativeProdCancelV1" to "(J)I",
            "nativeProdCloseV1" to "(J)I",
            "nativeStreamSendV1" to "(JJLjava/nio/ByteBuffer;II)I",
            "nativeStreamReceiveV1" to "(JJLjava/nio/ByteBuffer;II[J)I",
            "nativeStreamConfirmV1" to "(JJJJ)I",
            "nativeStreamRejectV1" to "(JJJ)I",
            "nativeStreamHalfCloseV1" to "(JJ)I",
            "nativeStreamCancelV1" to "(JJ)I",
            "nativeStreamCloseV1" to "(JJ)I",
            "nativeMaintenanceOpenV1" to "(Ljava/nio/ByteBuffer;IIJ[J)I",
            "nativeMaintenanceCheckUpdateV1" to "(JLjava/nio/ByteBuffer;IILjava/nio/ByteBuffer;II[J)I",
            "nativeMaintenanceMaterializeV1" to "(JJLjava/nio/ByteBuffer;II[J)I",
            "nativeMaintenanceReleaseUpdateV1" to "(JJ)I",
            "nativeMaintenanceRunProbeV1" to "(JLjava/nio/ByteBuffer;IILjava/nio/ByteBuffer;II[J)I",
            "nativeMaintenanceCancelV1" to "(J)I",
            "nativeMaintenanceCloseV1" to "(J)I",
        )
        val methods = Class.forName("org.kurdistanvpn.core.nativejni.NativeBridge", false, javaClass.classLoader)
            .declaredMethods.filter { it.name.startsWith("nativeProd") || it.name.startsWith("nativeStream") || it.name.startsWith("nativeMaintenance") }
        assertEquals(expected.keys, methods.map { it.name }.toSet())
        assertEquals(27, methods.size)
        for (method in methods) {
            assertTrue(method.name, Modifier.isPrivate(method.modifiers) && Modifier.isNative(method.modifiers))
            val descriptor = method.parameterTypes.joinToString("", "(", ")") { it.descriptorString() } + method.returnType.descriptorString()
            assertEquals(method.name, expected[method.name], descriptor)
        }
    }
}
