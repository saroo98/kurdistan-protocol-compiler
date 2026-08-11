// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Parcel
import android.os.ParcelFileDescriptor
import java.util.concurrent.atomic.AtomicReference

internal object RuntimeAuthorityBroker {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val expected = AtomicReference<Expected?>()
    private val pending = AtomicReference<Pending?>()

    fun arm(
        requestId: String,
        receiver: (ParcelFileDescriptor, Int) -> Unit,
    ): Boolean {
        if (!validRequestId(requestId)) return false
        val next = Expected(requestId, receiver)
        if (!expected.compareAndSet(null, next)) return false
        val waiting = pending.get()
        if (waiting != null && waiting.requestId == requestId && pending.compareAndSet(waiting, null)) {
            expected.compareAndSet(next, null)
            receiver(waiting.descriptor, waiting.length)
        }
        return true
    }

    fun submit(requestId: String, descriptor: ParcelFileDescriptor, length: Int): Boolean {
        if (!validRequestId(requestId) || length !in 1..RuntimeStartLimit.MAX_BYTES) {
            descriptor.close()
            return false
        }
        val armed = expected.get()
        if (armed != null) {
            if (armed.requestId != requestId || !expected.compareAndSet(armed, null)) {
                descriptor.close()
                return false
            }
            armed.receiver(descriptor, length)
            return true
        }
        val value = Pending(requestId, descriptor, length)
        if (!pending.compareAndSet(null, value)) {
            descriptor.close()
            return false
        }
        mainHandler.postDelayed({
            if (pending.compareAndSet(value, null)) value.descriptor.close()
        }, RuntimeAuthorityTimeoutPolicy.PENDING_DESCRIPTOR_MILLIS)
        return true
    }

    fun cancel(requestId: String) {
        val armed = expected.get()
        if (armed?.requestId == requestId) expected.compareAndSet(armed, null)
        val waiting = pending.get()
        if (waiting?.requestId == requestId && pending.compareAndSet(waiting, null)) {
            waiting.descriptor.close()
        }
    }

    private fun validRequestId(value: String): Boolean =
        value.length == 32 && value.all { it in '0'..'9' || it in 'a'..'f' }

    private data class Expected(
        val requestId: String,
        val receiver: (ParcelFileDescriptor, Int) -> Unit,
    )

    private data class Pending(
        val requestId: String,
        val descriptor: ParcelFileDescriptor,
        val length: Int,
    )
}

internal object RuntimeStartLimit {
    const val MAX_BYTES = org.kurdistanvpn.runtime.api.RuntimeStartWire.MAX_RUNTIME_OPEN_BYTES
}

class RuntimeAuthorityHandoffService : Service() {
    private val handoffBinder by lazy {
        RuntimeAuthorityBinder(applicationInfo.uid)
    }

    override fun onBind(intent: Intent?): IBinder? =
        if (intent?.action == ACTION_BIND_AUTHORITY) handoffBinder else null

    companion object {
        const val ACTION_BIND_AUTHORITY =
            "org.kurdistanvpn.runtime.action.BIND_AUTHORITY"
    }
}

internal class RuntimeAuthorityBinder(
    private val applicationUid: Int,
) : Binder() {
    override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
        if (code != TRANSACTION_SUBMIT) return super.onTransact(code, data, reply, flags)
        data.enforceInterface(DESCRIPTOR)
        if (getCallingUid() != applicationUid) {
            reply?.writeNoException()
            reply?.writeInt(0)
            return true
        }
        val requestId = data.readString().orEmpty()
        val descriptor = if (Build.VERSION.SDK_INT >= 33) {
            data.readTypedObject(ParcelFileDescriptor.CREATOR)
        } else {
            @Suppress("DEPRECATION")
            data.readParcelable<ParcelFileDescriptor>(ParcelFileDescriptor::class.java.classLoader)
        }
        val length = data.readInt()
        val ownedDescriptor = descriptor?.let {
            runCatching { ParcelFileDescriptor.dup(it.fileDescriptor) }.getOrNull()
        }
        runCatching { descriptor?.close() }
        val accepted = ownedDescriptor != null && RuntimeAuthorityBroker.submit(
            requestId,
            ownedDescriptor,
            length,
        )
        reply?.writeNoException()
        reply?.writeInt(if (accepted) 1 else 0)
        return true
    }

    companion object {
        private const val DESCRIPTOR = "org.kurdistanvpn.runtime.android.RuntimeAuthorityHandoff"
        private const val TRANSACTION_SUBMIT = FIRST_CALL_TRANSACTION

        fun submit(
            remote: IBinder,
            requestId: String,
            descriptor: ParcelFileDescriptor,
            length: Int,
        ): Boolean {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            return try {
                data.writeInterfaceToken(DESCRIPTOR)
                data.writeString(requestId)
                if (Build.VERSION.SDK_INT >= 33) {
                    data.writeTypedObject(descriptor, 0)
                } else {
                    @Suppress("DEPRECATION")
                    data.writeParcelable(descriptor, 0)
                }
                data.writeInt(length)
                if (!remote.transact(TRANSACTION_SUBMIT, data, reply, 0)) return false
                reply.readException()
                reply.readInt() == 1
            } finally {
                reply.recycle()
                data.recycle()
            }
        }
    }
}
