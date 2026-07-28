// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.platform.importing

import android.content.ClipData
import android.content.ContentResolver
import android.net.Uri

object AndroidImportSources {
    fun document(
        resolver: ContentResolver,
        uri: Uri,
        artifactClass: ArtifactClass,
    ): ImportCandidate =
        ImportCandidate(
            ingress = IngressKind.FILE,
            artifactClass = artifactClass,
            parts = listOf(readBounded(resolver, uri, MAX_ARTIFACT_BYTES)),
        )

    fun sharedDocument(
        resolver: ContentResolver,
        uri: Uri,
        artifactClass: ArtifactClass,
    ): ImportCandidate = document(resolver, uri, artifactClass)

    fun clipboard(
        clip: ClipData,
        artifactClass: ArtifactClass,
    ): ImportCandidate {
        require(clip.itemCount == 1)
        val text = checkNotNull(clip.getItemAt(0).text).toString()
        require(text.isNotBlank() && text.length <= MAX_CLIPBOARD_CHARS)
        return ImportCandidate(
            ingress = IngressKind.CLIPBOARD,
            artifactClass = artifactClass,
            parts = listOf(text.encodeToByteArray()),
        )
    }

    fun uri(
        value: String,
        artifactClass: ArtifactClass,
    ): ImportCandidate {
        require(value.startsWith("kurd://artifact/") && value.length <= MAX_ARTIFACT_BYTES * 4 / 3 + 32)
        return ImportCandidate(
            ingress = IngressKind.URI,
            artifactClass = artifactClass,
            parts = listOf(value.encodeToByteArray()),
        )
    }

    private fun readBounded(
        resolver: ContentResolver,
        uri: Uri,
        maximum: Int,
    ): ByteArray =
        checkNotNull(resolver.openInputStream(uri)).use { input ->
            BoundedInputReader.read(input, maximum)
        }
}
