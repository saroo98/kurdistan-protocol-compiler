// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.data.secure

import java.io.File
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.BasicFileAttributes

class StorageLockedException : IllegalStateException("STORAGE_LOCKED")

/** Legacy app-private directory only. Metadata checks cannot defeat hostile swap-away-and-back races. */
internal class ProcessFileLock(root: File, private val identityKey: (Path) -> Any = ::nioIdentityKey) {
    private val root = root.canonicalFile.toPath()
    private val rootIdentity = identity(this.root, directory = true)

    fun <T> withLock(block: () -> T): T {
        val deadline = System.nanoTime() + 2_000_000_000L
        if (Thread.currentThread().isInterrupted) throw StorageLockedException()
        val entry = admit()
        var acquired: FileLock? = null
        var failure: Throwable? = null
        try {
            while (true) {
                if (Thread.currentThread().isInterrupted || System.nanoTime() >= deadline) throw StorageLockedException()
                check(!entry.uncertain) { "secure lock release uncertain" }
                acquired = try { entry.channel.tryLock() }
                catch (_: OverlappingFileLockException) { null }
                if (acquired != null) {
                    validate(entry)
                    check(!entry.uncertain) { "secure lock release uncertain" }
                    if (Thread.currentThread().isInterrupted) throw StorageLockedException()
                    return block()
                }
                if (System.nanoTime() >= deadline) throw StorageLockedException()
                try { Thread.sleep(10) }
                catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw StorageLockedException()
                }
            }
        } catch (caught: Throwable) {
            failure = caught
            throw caught
        } finally {
            var cleanup: Throwable? = null
            try { acquired?.release() }
            catch (caught: Throwable) { entry.uncertain = true; cleanup = caught }
            try {
                synchronized(entries) {
                    entry.leases--
                    if (entry.leases == 0) {
                        // Close and removal are serialized with admission, never with callback execution.
                        try { entry.channel.close() }
                        catch (caught: Throwable) { entry.uncertain = true; throw caught }
                        entries.remove(root)
                    }
                }
            } catch (caught: Throwable) {
                if (cleanup == null) cleanup = caught else cleanup.addSuppressed(caught)
            }
            cleanup?.let { if (failure != null) failure.addSuppressed(it) else throw it }
        }
    }

    private fun admit(): Entry = synchronized(entries) {
        check(identity(root, directory = true) == rootIdentity) { "secure root identity changed" }
        entries[root]?.let {
            validate(it)
            check(!it.uncertain) { "secure lock release uncertain" }
            it.leases++
            return@synchronized it
        }
        val path = root.resolve(".store.lock")
        val before = if (Files.exists(path, NOFOLLOW_LINKS)) identity(path) else null
        val channel = FileChannel.open(path, CREATE, WRITE, NOFOLLOW_LINKS)
        try {
            val after = identity(path)
            check(before == null || before == after) { "secure lock identity changed" }
            val entry = Entry(channel, rootIdentity, after)
            validate(entry)
            entries[root] = entry
            entry
        } catch (failure: Throwable) {
            try { channel.close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
            throw failure
        }
    }

    private fun validate(entry: Entry) {
        check(identity(root, directory = true) == entry.rootIdentity && entry.rootIdentity == rootIdentity) {
            "secure root identity changed"
        }
        check(identity(root.resolve(".store.lock")) == entry.lockIdentity) { "secure lock identity changed" }
    }

    private class Entry(val channel: FileChannel, val rootIdentity: Any, val lockIdentity: Any) {
        var leases = 1
        @Volatile var uncertain = false
    }

    private fun identity(path: Path, directory: Boolean = false): Any {
        val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        check(!attributes.isSymbolicLink && if (directory) attributes.isDirectory else attributes.isRegularFile) {
            "unsafe secure lock path"
        }
        return identityKey(path)
    }

    internal companion object {
        private val entries = mutableMapOf<Path, Entry>()
        internal fun nioIdentityKey(path: Path): Any = checkNotNull(
            Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS).fileKey(),
        ) { "secure file identity unavailable" }
    }
}
