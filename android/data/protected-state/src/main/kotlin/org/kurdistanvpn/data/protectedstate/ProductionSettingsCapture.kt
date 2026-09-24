// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.data.protectedstate

import java.nio.ByteBuffer
import java.io.OutputStream
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.model.ProductSettings
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.core.nativejni.ProductionSettingsEncodingV1
import org.kurdistanvpn.data.secure.RuntimeAuthorityMaterial

sealed interface ProductionCaptureReadResult {
    data class Ready(val capture:ReissuedProductionCapture):ProductionCaptureReadResult
    data class Rejected(val category:AuthorityReadFailure,val error:OperationError?=null):ProductionCaptureReadResult
}

/** A one-use currentness-checked payload, not registration or runtime authority. */
sealed interface ReissuedProductionCapture:AutoCloseable {
    val presentation: org.kurdistanvpn.runtime.api.RuntimeProfilePresentation
    val revision:Long
    val signedRetryBudget:Int
    val length:Int
    fun writeTo(output:OutputStream)
}

/** Takes ownership of exact KCT bytes and the locally retained paired availability. */
internal class OwnedReissuedProductionCapture(private val wire:ByteArray,override val revision:Long,
    override val signedRetryBudget:Int,private var availability:NativeProductionBootstrapReadV1?,
    override val presentation: org.kurdistanvpn.runtime.api.RuntimeProfilePresentation,
    private val finalRead:()->Unit):ReissuedProductionCapture {
    override val length=wire.size
    private var terminal=false
    private var cleanupFailure:Throwable?=null
    init{require(revision>0 && signedRetryBudget in 0..5 && wire.size in 37..2721575)}
    @Synchronized override fun writeTo(output:OutputStream) {
        check(!terminal){"CAPTURE_ALREADY_CONSUMED"};terminal=true
        var outgoing:ByteArray?=null
        try {finalRead();outgoing=wire.clone();output.write(outgoing,0,outgoing.size)}
        finally {outgoing?.fill(0);close()}
    }
    @Synchronized override fun close() {
        terminal=true;wire.fill(0)
        cleanupFailure?.let{throw it}
        val retained=availability;availability=null
        try{retained?.close()}catch(error:Throwable){cleanupFailure=error;throw error}
    }
    override fun toString()="ReissuedProductionCapture(redacted)"
}

internal fun bootstrapMaterialV1(material:RuntimeAuthorityMaterial)=NativeBootstrapMaterialV1(
    ByteBuffer.wrap(material.verifyRequest),ByteBuffer.wrap(material.activationRecord),
    ByteBuffer.wrap(material.recipientRequest),ByteBuffer.wrap(material.recipientPrivate))

internal fun encodeProductionSettingsOwnedV1(settings:ProductSettings):NativeProductResult<ByteArray> {
    // ProductSettings and its nested collection owners are immutable model values.
    val staging=ByteArray(196608)
    return try {
        when(val result=ProductionSettingsEncodingV1.encode(settings,ByteBuffer.wrap(staging))) {
            is NativeProductResult.Failure -> result
            is NativeProductResult.Success -> {
                check(result.value in 1..staging.size)
                NativeProductResult.Success(staging.copyOf(result.value))
            }
        }
    } finally{staging.fill(0)}
}

/** Closed read-only-computation conversion, not a P1-to-legacy integer cast. */
internal fun bootstrapOperationErrorV1(code:ProductFailureCode):OperationError=when(code) {
    ProductFailureCode.INVALID_INPUT -> OperationError.INVALID_INPUT
    ProductFailureCode.SIZE_LIMIT -> OperationError.SIZE_LIMIT
    ProductFailureCode.RESOURCE_LIMIT -> OperationError.RESOURCE_LIMIT
    ProductFailureCode.CANCELLED -> OperationError.CANCELLED
    ProductFailureCode.PROFILE_INCOMPATIBLE -> OperationError.INCOMPATIBLE_NATIVE_CORE
    ProductFailureCode.PROFILE_UNTRUSTED -> OperationError.TRUST_REJECTED
    ProductFailureCode.PROFILE_ROLLBACK -> OperationError.RECOVERY_REQUIRED
    ProductFailureCode.PROFILE_EXPIRED,ProductFailureCode.PROFILE_REVOKED,ProductFailureCode.PROFILE_WRONG_DEVICE,
    ProductFailureCode.NO_PERMITTED_STRATEGY,ProductFailureCode.ROUTE_POLICY_REJECTED,
    ProductFailureCode.DNS_POLICY_REJECTED -> OperationError.POLICY_REJECTED
    else -> OperationError.INTERNAL_FAILURE
}
