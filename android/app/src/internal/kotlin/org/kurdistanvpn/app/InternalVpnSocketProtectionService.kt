// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import org.kurdistanvpn.runtime.android.ActiveVpnUnderlyingNetwork

/**
 * Internal-build-only bridge that protects a duplicated socket descriptor in
 * the VPN process. It accepts no endpoint metadata and persists no state.
 */
class InternalVpnSocketProtectionService : VpnService() {
    private val protectionBinder = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != TRANSACTION_PROTECT_SOCKET) {
                return super.onTransact(code, data, reply, flags)
            }
            data.enforceInterface(DESCRIPTOR)
            val callerMayProtect = callerMayProtect(Binder.getCallingUid())
            val descriptor = if (data.readInt() == 1) {
                ParcelFileDescriptor.CREATOR.createFromParcel(data)
            } else {
                null
            }
            val protected = descriptor?.use { candidate ->
                val network = ActiveVpnUnderlyingNetwork.current()
                callerMayProtect && network != null && data.dataAvail() == 0 &&
                    protect(candidate.fd) && runCatching {
                        network.bindSocket(candidate.fileDescriptor)
                    }.isSuccess
            } == true
            reply?.writeNoException()
            reply?.writeInt(if (protected) 1 else 0)
            return true
        }
    }

    override fun onBind(intent: Intent?): IBinder? {
        val isInternalBuild = packageName == INTERNAL_PACKAGE &&
            applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        return if (isInternalBuild && intent?.action == ACTION_BIND) protectionBinder else null
    }

    private fun callerMayProtect(callerUid: Int): Boolean {
        if (callerUid == applicationInfo.uid) return true
        val callerPackages = packageManager.getPackagesForUid(callerUid)?.toSet() ?: return false
        return callerPackages == setOf(INTERNAL_TEST_PACKAGE) &&
            packageManager.checkSignatures(applicationInfo.uid, callerUid) ==
            PackageManager.SIGNATURE_MATCH
    }

    companion object {
        const val ACTION_BIND = "org.kurdistanvpn.internal.action.BIND_SOCKET_PROTECTION"
        const val DESCRIPTOR = "org.kurdistanvpn.internal.socket_protection"
        const val TRANSACTION_PROTECT_SOCKET = IBinder.FIRST_CALL_TRANSACTION
        private const val INTERNAL_PACKAGE = "org.kurdistanvpn.app.internal"
        private const val INTERNAL_TEST_PACKAGE = "org.kurdistanvpn.app.internal.test"
    }
}
