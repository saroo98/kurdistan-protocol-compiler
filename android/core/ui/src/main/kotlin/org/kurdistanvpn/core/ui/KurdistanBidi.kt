// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.ui

import android.text.BidiFormatter
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalConfiguration

/** Sorani per-app locale may differ from the process default used by BidiFormatter. */
@Composable
fun kurdistanBidiFormatter(): BidiFormatter {
    val locale = LocalConfiguration.current.locales[0]
    return if (locale.language == "ckb") BidiFormatter.getInstance(locale) else BidiFormatter.getInstance()
}
