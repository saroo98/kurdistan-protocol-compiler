// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.app.Application

class KurdistanApplication : Application() {
    lateinit var compositionRoot: Phase9CompositionRoot
        private set

    override fun onCreate() {
        super.onCreate()
        compositionRoot = Phase9CompositionRoot.create(this)
    }
}
