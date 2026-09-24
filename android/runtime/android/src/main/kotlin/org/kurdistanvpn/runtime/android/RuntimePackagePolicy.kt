// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import android.content.Context

/** OS-owned, same-boot package change sequence. Null is unavailable, never a made-up revision. */
fun currentRuntimePackageRevision(context: Context): Long? = try {
    (context.packageManager.getChangedPackages(0)?.sequenceNumber ?: 0).toLong().takeIf { it >= 0 }
} catch (_: Exception) { null }
