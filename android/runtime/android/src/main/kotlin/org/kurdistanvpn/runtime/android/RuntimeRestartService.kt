// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.IBinder

/** Started with an admitted session, separate from Android's TUN-owning binding. */
class RuntimeRestartService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            // A lifecycle wakeup is not authority. The existing automatic entry reopens
            // protected state and checks consent, pause, revision and fresh authorization.
            try {
                startForegroundService(Intent(this, KurdVpnService::class.java)
                    .setAction(VpnService.SERVICE_INTERFACE))
            } catch (_: RuntimeException) {
                stopSelf()
                return START_NOT_STICKY
            }
        }
        return START_STICKY
    }
}
