// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.app.Application

class KurdistanApplication : Application() {
    val compositionRoot: Phase9CompositionRoot by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        Phase9CompositionRoot.create(this)
    }
}
