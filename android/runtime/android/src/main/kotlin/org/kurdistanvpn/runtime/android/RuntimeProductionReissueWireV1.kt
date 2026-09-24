// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

/** Explicit successor parser selection. Scalar start/offer serialization remains shared with v2. */
object RuntimeProductionReissueWireV1 {
    /** Optional display metadata, never part of an executable authority request/frame. */
    fun writePresentation(parcel: android.os.Parcel, value: org.kurdistanvpn.runtime.api.RuntimeProfilePresentation?) {
        parcel.writeInt(1)
        parcel.writeInt(if (value == null) 0 else 1)
        value?.let {
            parcel.writeString(it.profileId); parcel.writeLong(it.profileGeneration.toLong())
            parcel.writeLong(it.trustRevision); parcel.writeLong(it.settingsRevision)
        }
    }
    fun readPresentation(parcel: android.os.Parcel): org.kurdistanvpn.runtime.api.RuntimeProfilePresentation? {
        require(parcel.dataAvail() >= 8 && parcel.readInt() == 1)
        return when (parcel.readInt()) {
            0 -> null
            1 -> {
                val profileId = checkNotNull(parcel.readString())
                require(parcel.dataAvail() >= 24)
                org.kurdistanvpn.runtime.api.RuntimeProfilePresentation(profileId,
                    parcel.readLong().toULong(), parcel.readLong(), parcel.readLong())
            }
            else -> throw IllegalArgumentException("INVALID_PRESENTATION")
        }
    }
    const val DESCRIPTOR = "org.kurdistanvpn.runtime.android.AuthorityReissueV3"
    const val CALLBACK = "org.kurdistanvpn.runtime.android.AuthorityReissueLifetimeV3"
    const val VERSION = 3
    const val CAPTURE_FORMAT_KCT1 = 1
    const val HELLO = 101
    const val OFFER = 102
    const val RESPONSE = 103
    const val RESPONSE_READY = 104
    const val COMPLETE = 105
    const val CANCEL = 106
    const val RELEASE_LEASE = 107
    const val REGISTERED_CURRENT = 108
    const val PREPUBLICATION_CURRENT = 109
    const val CANCEL_RETIRED = 110
    const val INVALIDATED = 1

    fun acceptsOpcode(code: Int): Boolean = when (code) {
        HELLO, OFFER, RESPONSE, RESPONSE_READY, COMPLETE, CANCEL, RELEASE_LEASE, REGISTERED_CURRENT, PREPUBLICATION_CURRENT, CANCEL_RETIRED -> true
        else -> false
    }

    fun validObservationDeadline(now: Long, deadline: Long): Boolean =
        now >= 0 && deadline > now && deadline - now <= 60_000

    /** v3 COMPLETE adds the original provider lease deadline; v2 remains one Boolean int. */
    fun writeCompletionReply(production: Boolean, status: Int, deadline: Long,
        writeInt: (Int) -> Unit, writeLong: (Long) -> Unit) {
        require(status in 0..1)
        require(if (production && status == 1) deadline > 0 else deadline == 0L)
        writeInt(status)
        if (production) writeLong(deadline)
    }

    fun readCompletionReply(encodedBytes: Int, status: Int, deadline: Long, requestDeadline: Long): Long? {
        require(encodedBytes == 12 && status in 0..1 && requestDeadline > 0)
        require(if (status == 0) deadline == 0L else deadline > 0 && deadline <= requestDeadline)
        return if (status == 1) deadline else null
    }
}
