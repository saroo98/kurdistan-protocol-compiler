// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.nio.ByteBuffer
import org.kurdistanvpn.runtime.api.*

/** Shared 165-byte request/ID field order only. Version framing, authentication,
 * payload rules and domains remain owned independently by each frame codec. */
internal object RuntimeAuthorityRequestWire {
    private fun ByteBuffer.putId(id: String) { repeat(16) { put(id.substring(it * 2, it * 2 + 2).toInt(16).toByte()) } }
    private fun ByteBuffer.readId(): String = buildString(32) {
        repeat(16) { val value = this@readId.get().toInt() and 255; append("0123456789abcdef"[value ushr 4]); append("0123456789abcdef"[value and 15]) }
    }
    fun write(output: ByteBuffer, r: RuntimeAuthorityRequest) = with(output) {
        putId(r.consumerEpoch); putId(r.providerEpoch); putId(r.requestId)
        putLong(r.generation); put(r.purpose.wire.toByte()); put(r.trigger.wire.toByte())
        putLong(r.revision); putLong(r.deadlineElapsedMillis); putId(r.capabilityChannelId); putId(r.frameChannelId)
        putId(r.descriptor.id); putLong(r.descriptor.device); putLong(r.descriptor.inode); putLong(r.descriptor.ownerUid)
        putLong(r.descriptor.mode); putLong(r.descriptor.length); put(r.descriptor.accessMode.toByte())
        put(r.signedRetryBudget.toByte()); put(r.retryAttempt.toByte())
    }
    fun read(input: ByteBuffer): RuntimeAuthorityRequest = with(input) {
        val consumerEpoch = readId(); val providerEpoch = readId(); val id = readId(); val generation = long
        val purposeCode = get().toInt() and 255
        val triggerCode = get().toInt() and 255
        val purpose = RuntimeAuthorityPurpose.entries.single { it.wire == purposeCode }
        val trigger = RuntimeAuthorityTrigger.entries.single { it.wire == triggerCode }
        val revision = long; val deadline = long; val capabilityChannel = readId(); val frameChannel = readId()
        val descriptor = RuntimeDescriptorBinding(readId(), long, long, long, long, long, get().toInt() and 255)
        return@with RuntimeAuthorityRequest(consumerEpoch, providerEpoch, id, generation, purpose, trigger, revision, deadline,
            capabilityChannel, frameChannel, descriptor,
            get().toInt() and 255, get().toInt() and 255)
    }
}
