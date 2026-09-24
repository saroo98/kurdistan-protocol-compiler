// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import java.nio.CharBuffer
import java.util.UUID

/** No clipboard polling or persistence. Backgrounding clears earlier than the60second maximum. */
internal class ProxyClipboard(context: Context) {
    private val clipboard = context.getSystemService(ClipboardManager::class.java)
    private var owner: String? = null
    val ownsValue: Boolean get() = owner != null
    fun copy(chars: CharArray) {
        clear()
        val id = UUID.randomUUID().toString()
        val copy = chars.copyOf()
        try {
            val clip = ClipData.newPlainText(id, CharBuffer.wrap(copy))
            clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
            clipboard.setPrimaryClip(clip)
        } finally { copy.fill('\u0000') }
        owner = id
    }
    fun clear() {
        val id = owner ?: return
        try {
            // Android also signals background access denial with null, not
            // only SecurityException. Retain the nonsecret tag for retry.
            val description = clipboard.primaryClipDescription ?: return
            if (description.label?.toString() == id) {
                if (Build.VERSION.SDK_INT >= 28) clipboard.clearPrimaryClip()
                else clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
            }
            owner = null
        } catch (_: SecurityException) {
            // A background clipboard denial retains only the nonsensitive ownership
            // tag so the next foreground clear can retry without erasing another clip.
        }
    }
}
