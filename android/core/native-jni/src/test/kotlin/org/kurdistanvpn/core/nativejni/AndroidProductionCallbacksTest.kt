// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import org.junit.Assert.*
import org.junit.Test

class AndroidProductionCallbacksTest {
    @Test fun maintenanceReservationCannotClaimProductionAndOpensOnlyOnce() {
        val reservation=AndroidProductionReservationV1();val values=LongArray(2)
        assertEquals(0,reservation.reserve(2,values){values[0]=-3;values[1]=-4;0})
        assertTrue(reservation.openProduction<Unit>{_,_->error("cross-kind")} is org.kurdistanvpn.core.nativeapi.NativeProductResult.Failure)
        assertEquals(org.kurdistanvpn.core.nativeapi.NativeProductResult.Success(Unit),
            reservation.openMaintenance { owner,lease ->
                assertEquals(-3L,owner);assertEquals(-4L,lease)
                org.kurdistanvpn.core.nativeapi.NativeProductResult.Success(Unit)
            })
        assertTrue(reservation.openMaintenance<Unit>{_,_->error("repeat")} is org.kurdistanvpn.core.nativeapi.NativeProductResult.Failure)
    }
    @Test fun successfulPrivateReservationIsOneUseAndKindExact() {
        for (kind in listOf(1,2)) {
            val reservation=AndroidProductionReservationV1()
            var registrations=0;var openings=0
            val values=LongArray(2)
            assertEquals(0,reservation.reserve(kind,values){registrations++;values[0]=Long.MIN_VALUE;values[1]=-7;0})
            values.fill(0)
            assertEquals(3,reservation.reserve(kind,values){registrations++;0})
            val result=reservation.openProduction { owner,lease->
                openings++;assertEquals(Long.MIN_VALUE,owner);assertEquals(-7L,lease)
                org.kurdistanvpn.core.nativeapi.NativeProductResult.Success(Unit)
            }
            assertEquals(if(kind==1) org.kurdistanvpn.core.nativeapi.NativeProductResult.Success(Unit)
                else org.kurdistanvpn.core.nativeapi.NativeProductResult.Failure(org.kurdistanvpn.core.model.ProductFailureCode.OPERATION_INTERRUPTED),result)
            assertTrue(reservation.openProduction<Unit>{_,_->error("reopened")} is org.kurdistanvpn.core.nativeapi.NativeProductResult.Failure)
            assertEquals(1,registrations);assertEquals(if(kind==1)1 else 0,openings)
        }
    }

    @Test fun reservationNeverHoldsMonitorAcrossNativeWorkOrRetriesFailedClaim() {
        val reservation=AndroidProductionReservationV1();val values=LongArray(2)
        val entered=java.util.concurrent.CountDownLatch(1);val release=java.util.concurrent.CountDownLatch(1)
        val executor=java.util.concurrent.Executors.newSingleThreadExecutor()
        try {
            val pending=executor.submit<Int>{reservation.reserve(1,values){entered.countDown();check(release.await(5,java.util.concurrent.TimeUnit.SECONDS));values[0]=5;values[1]=6;0}}
            assertTrue(entered.await(5,java.util.concurrent.TimeUnit.SECONDS))
            assertTrue(reservation.openProduction<Unit>{_,_->error("opened pending reserve")} is org.kurdistanvpn.core.nativeapi.NativeProductResult.Failure)
            release.countDown();assertEquals(0,pending.get(5,java.util.concurrent.TimeUnit.SECONDS))
            try { reservation.openProduction<Unit>{_,_->error("native throw")};fail("exception swallowed") }catch(_:IllegalStateException){}
            assertTrue(reservation.openProduction<Unit>{_,_->error("retry after native throw")} is org.kurdistanvpn.core.nativeapi.NativeProductResult.Failure)
            val failed=AndroidProductionReservationV1()
            assertEquals(5,failed.reserve(1,LongArray(2)){5})
            assertTrue(failed.openProduction<Unit>{_,_->error("opened failed reserve")} is org.kurdistanvpn.core.nativeapi.NativeProductResult.Failure)
        }finally{release.countDown();executor.shutdownNow()}
    }

    @Test fun trustedOpeningExposesNoRawTokenParameter() {
        val method=AndroidProductionCallbacks::class.java.declaredMethods.single{it.name=="openProduction"}
        assertEquals(2,method.parameterCount)
        assertFalse(method.parameterTypes.any{it==java.lang.Long.TYPE})
        assertEquals(org.kurdistanvpn.core.nativeapi.NativeProductResult::class.java,method.returnType)
    }

    @Test fun retiredReservationCannotBeginOpening() {
        val reservation=AndroidProductionReservationV1();val values=LongArray(2)
        assertEquals(0,reservation.reserve(1,values){values[0]=5;values[1]=6;0})
        reservation.retire()
        assertTrue(reservation.openProduction<Unit>{_,_->error("opened retired reservation")} is org.kurdistanvpn.core.nativeapi.NativeProductResult.Failure)
    }

    @Test fun failedOpeningFinalizerHasPrivateExactKindAndLeaseDescriptor() {
        val method = AndroidProductionCallbacks::class.java.getDeclaredMethod("finalizeFailedOpening", java.lang.Integer.TYPE, java.lang.Long.TYPE)
        assertEquals(java.lang.Integer.TYPE, method.returnType)
        assertTrue(java.lang.reflect.Modifier.isPrivate(method.modifiers))
        assertTrue(java.lang.reflect.Modifier.isNative(method.modifiers))
    }

    @Test fun actualCallbackClassHasAllFrozenTypedDescriptors() {
        val expected = mapOf(
            "captureSizes" to "(J[I)I",
            "captureCopyInto" to "(JLjava/nio/ByteBuffer;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;[I)I",
            "productionCurrentRegister" to "(JJJ[J)I", "maintenanceCurrentRegister" to "(JJJ[J)I",
            "revisionRevalidate" to "(JJJ)I", "publicationAcquire" to "(JJJ[J)I",
            "publicationIsCurrent" to "(JJJ[I)I", "publicationClose" to "(JJJ)I", "revisionClose" to "(JJ)I",
            "socketRegister" to "(JJJJJIIIJJ[J[I)I", "socketConfirm" to "(JJIIJ)I", "socketClose" to "(JJ)I",
            "maintenanceNetworkAcquire" to "(JJJ[J)I", "maintenanceNetworkSnapshot" to "(JJLjava/nio/ByteBuffer;[I)I",
            "maintenanceNetworkIsCurrent" to "(JJ[I)I", "maintenanceNetworkBindSocket" to "(JJI)I",
            "maintenanceNetworkClose" to "(JJ)I", "systemRootsInto" to "(JJLjava/nio/ByteBuffer;[I)I",
            "cancelCall" to "(JJ)I", "ownerClose" to "(J)I",
        )
        fun descriptor(type: Class<*>): String = when (type) {
            java.lang.Long.TYPE -> "J"; java.lang.Integer.TYPE -> "I"
            else -> if (type.isArray) type.name.replace('.', '/') else "L${type.name.replace('.', '/')};"
        }
        val methods = AndroidProductionCallbacks::class.java.declaredMethods
        for ((name, signature) in expected) {
            val method = methods.single { it.name == name }
            val actual = method.parameterTypes.joinToString("", "(", ")") { descriptor(it) } + descriptor(method.returnType)
            assertEquals(name, signature, actual)
        }
    }
}
