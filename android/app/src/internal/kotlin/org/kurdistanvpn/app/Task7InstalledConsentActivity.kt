// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle

/** No store access: only Android's real VPN consent request, from the target Activity. */
class Task7InstalledConsentActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) return
        val consent = VpnService.prepare(this)
        if (consent == null) finish() else startActivityForResult(consent, 1)
    }
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1) finish()
    }
}
