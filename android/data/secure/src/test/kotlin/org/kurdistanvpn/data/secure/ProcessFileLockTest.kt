// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.data.secure

import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class ProcessFileLockTest {
    private fun <T> locked(root: File, block: () -> T): T = ProcessFileLock(root, ::hostIdentity).withLock(block)

    @Test fun releasesAfterCallbackThrows() = fixture { root ->
        val expected = IllegalArgumentException("synthetic callback")
        assertSame(expected, assertThrows(IllegalArgumentException::class.java) { locked(root) { throw expected } })
        assertEquals(7, locked(root) { 7 })
        assertEquals("ACQUIRED", probe(root))
    }

    @Test fun sameJvmTimeoutDoesNotReleaseHolderNativeLock() = fixture { root ->
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        val holder = executor.submit { locked(root) { entered.countDown(); check(release.await(15, TimeUnit.SECONDS)) } }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val start = System.nanoTime()
            val failure = assertThrows(Exception::class.java) { locked(File(root, ".")) { fail("waiter entered") } }
            assertEquals("STORAGE_LOCKED", failure.message)
            val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)
            assertTrue("elapsed=$elapsed", elapsed in 1900..5000)
            assertEquals("CONTENDED", probe(root))
            assertFalse(holder.isDone)
        } finally {
            release.countDown()
            try { holder.get(5, TimeUnit.SECONDS) } finally { executor.shutdownNow() }
        }
        assertEquals("ACQUIRED", probe(root))
    }

    @Test fun childHolderTimesOutThenProcessExitReleasesLock() = fixture { root ->
        val child = child(root, "hold")
        try {
            assertEquals("ACQUIRED", line(child))
            assertEquals("STORAGE_LOCKED", assertThrows(Exception::class.java) { locked(root) { fail("entered") } }.message)
        } finally {
            child.destroyForcibly()
            assertTrue(child.waitFor(5, TimeUnit.SECONDS))
        }
        assertEquals(9, locked(root) { 9 })
    }

    @Test fun preInterruptedCallerCannotEnterAndKeepsFlag() = fixture { root ->
        val lock = ProcessFileLock(root, ::hostIdentity)
        Thread.currentThread().interrupt()
        try {
            assertEquals("STORAGE_LOCKED", assertThrows(Exception::class.java) { lock.withLock { fail("entered") } }.message)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        assertEquals("ACQUIRED", probe(root))
    }

    @Test fun interruptionDuringAcquisitionValidationCannotEnterCallback() = fixture { root ->
        var lockReads = 0
        val lock = ProcessFileLock(root) { path ->
            hostIdentity(path).also {
                if (path.fileName.toString() == ".store.lock" && ++lockReads == 3) Thread.currentThread().interrupt()
            }
        }
        try {
            assertThrows(StorageLockedException::class.java) { lock.withLock { fail("interrupted acquisition entered") } }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        assertEquals("ACQUIRED", probe(root))
    }

    @Test fun updateOwnsAndClearsBothBuffersIncludingTransformFailure() = fixture { parent ->
        val store = store(parent)
        var replacement = byteArrayOf(1, 2)
        update(store) { assertNull(it); replacement }
        assertArrayEquals(byteArrayOf(0, 0), replacement)
        var previous: ByteArray? = null
        replacement = byteArrayOf(3)
        update(store) { previous = it; assertArrayEquals(byteArrayOf(1, 2), it); replacement }
        assertArrayEquals(byteArrayOf(0, 0), previous)
        assertArrayEquals(byteArrayOf(0), replacement)
        assertArrayEquals(byteArrayOf(3), store.reopen("record", SecureDataClass.PROFILE_ARTIFACT))
        assertThrows(IllegalArgumentException::class.java) {
            update(store) { previous = it; throw IllegalArgumentException("synthetic") }
        }
        assertArrayEquals(byteArrayOf(0), previous)
        assertArrayEquals(byteArrayOf(3), store.reopen("record", SecureDataClass.PROFILE_ARTIFACT))
    }

    @Test fun reopenClearsOwnedPlaintextWhenActualLockReleaseFails() = fixture { parent ->
        val store = store(parent)
        store.stage("record", SecureDataClass.PROFILE_ARTIFACT, byteArrayOf(1, 2, 3))
        var captured: ByteArray? = null
        var returned = false
        assertThrows(java.nio.channels.ClosedChannelException::class.java) {
            store.reopen("record", SecureDataClass.PROFILE_ARTIFACT) { plaintext ->
                captured = plaintext
                assertArrayEquals(byteArrayOf(1, 2, 3), plaintext)
                // Fault the real leased channel, not a replacement lock or a throwing callback.
                val registryField = ProcessFileLock::class.java.getDeclaredField("entries").also { it.isAccessible = true }
                val registry = registryField.get(null) as Map<*, *>
                val entry = checkNotNull(registry[File(parent, "phase9-v1").canonicalFile.toPath()])
                val channelField = entry.javaClass.getDeclaredField("channel").also { it.isAccessible = true }
                (channelField.get(entry) as FileChannel).close()
            }
            returned = true
        }
        assertFalse(returned)
        assertNotNull(captured)
        assertArrayEquals(ByteArray(3), captured)
        assertArrayEquals(byteArrayOf(1, 2, 3), store.reopen("record", SecureDataClass.PROFILE_ARTIFACT))
    }

    @Test fun staleTemporaryRecoveryNeverPromotesAndPreservesCorruptFinal() = fixture { parent ->
        val store = store(parent)
        val root = File(parent, "phase9-v1")
        val final = File(root, "record.1.blob")
        val temporary = File(root, ".record.1.blob.staging")
        val unknown = File(root, "unrecognized.tmp").also { it.writeBytes(byteArrayOf(7)) }
        temporary.writeBytes(byteArrayOf(99))
        store.stage("record", SecureDataClass.PROFILE_ARTIFACT, byteArrayOf(1))
        assertFalse(temporary.exists())
        assertArrayEquals(byteArrayOf(1), store.reopen("record", SecureDataClass.PROFILE_ARTIFACT))
        temporary.writeBytes(byteArrayOf(99))
        store.stage("record", SecureDataClass.PROFILE_ARTIFACT, byteArrayOf(2))
        assertFalse(temporary.exists())
        final.writeBytes(byteArrayOf(98))
        temporary.writeBytes(byteArrayOf(99))
        assertThrows(Exception::class.java) { store.stage("record", SecureDataClass.PROFILE_ARTIFACT, byteArrayOf(3)) }
        assertArrayEquals(byteArrayOf(98), final.readBytes())
        assertArrayEquals(byteArrayOf(99), temporary.readBytes())
        assertArrayEquals(byteArrayOf(7), unknown.readBytes())
    }

    @Test fun rotationFailureKeepsOldReadableValueAndResetKeepsLockIdentity() = fixture { parent ->
        val store = store(parent)
        store.stage("record", SecureDataClass.PROFILE_ARTIFACT, byteArrayOf(1))
        val replacement = object : KeyEncryptionKey by FixtureKek() {
            override val generation = 2
            override fun wrap(recordId: String, dataClass: SecureDataClass, key: ByteArray): WrappedKey = error("synthetic wrap failure")
        }
        assertThrows(IllegalStateException::class.java) { store.rotate("record", SecureDataClass.PROFILE_ARTIFACT, replacement) }
        assertArrayEquals(byteArrayOf(1), store.reopen("record", SecureDataClass.PROFILE_ARTIFACT))
        val path = File(parent, "phase9-v1/.store.lock").toPath()
        val identity = hostIdentity(path)
        store.deleteAll()
        assertTrue(Files.exists(path))
        assertEquals(identity, hostIdentity(path))
        assertFalse(store.exists("record", SecureDataClass.PROFILE_ARTIFACT))
    }

    @Test fun directorySyncFailureCannotReportWriteOrDeleteSuccess() = fixture { parent ->
        var failSync = false
        var syncs = 0
        val store = store(parent) { syncs++; if (failSync) error("synthetic directory sync") }
        store.stage("record", SecureDataClass.PROFILE_ARTIFACT, byteArrayOf(1))
        assertEquals(1, syncs)
        failSync = true
        assertThrows(IllegalStateException::class.java) { store.stage("record", SecureDataClass.PROFILE_ARTIFACT, byteArrayOf(2)) }
        assertArrayEquals(byteArrayOf(2), store.reopen("record", SecureDataClass.PROFILE_ARTIFACT))
        assertThrows(IllegalStateException::class.java) { store.delete("record", SecureDataClass.PROFILE_ARTIFACT) }
        assertEquals(3, syncs)
    }

    @Test fun rotationRequiresAllRecordsAndStaleInstanceFailsClosed() = fixture { parent ->
        val store = store(parent)
        val stale = store(parent)
        store.stage("record", SecureDataClass.PROFILE_ARTIFACT, byteArrayOf(1))
        store.stage("second", SecureDataClass.PROFILE_ARTIFACT, byteArrayOf(2))
        val replacement = FixtureKek(2)
        store.rotate("record", SecureDataClass.PROFILE_ARTIFACT, replacement)
        assertThrows(IllegalArgumentException::class.java) { store.activateReplacement(replacement) }
        assertThrows(MissingKeyException::class.java) { stale.reopen("record", SecureDataClass.PROFILE_ARTIFACT) }
        store.rotate("second", SecureDataClass.PROFILE_ARTIFACT, replacement)
        store.activateReplacement(replacement)
        assertArrayEquals(byteArrayOf(1), store.reopen("record", SecureDataClass.PROFILE_ARTIFACT))
        assertArrayEquals(byteArrayOf(2), store.reopen("second", SecureDataClass.PROFILE_ARTIFACT))
    }

    @Test fun readModifyWriteIsSerializedAcrossInstances() = fixture { parent ->
        val first = store(parent)
        val second = store(parent)
        first.stage("record", SecureDataClass.PROFILE_ARTIFACT, byteArrayOf(1))
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        val holder = executor.submit { update(first) { previous ->
            entered.countDown()
            check(release.await(5, TimeUnit.SECONDS))
            byteArrayOf((checkNotNull(previous)[0] + 1).toByte())
        } }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val waiter = executor.submit { update(second) { previous -> byteArrayOf((checkNotNull(previous)[0] + 1).toByte()) } }
            release.countDown()
            holder.get(5, TimeUnit.SECONDS)
            waiter.get(5, TimeUnit.SECONDS)
            assertArrayEquals(byteArrayOf(3), first.reopen("record", SecureDataClass.PROFILE_ARTIFACT))
        } finally {
            release.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test fun oversizeEnvelopeIsRejectedBeforeKeyAccess() = fixture { parent ->
        val store = store(parent)
        java.io.RandomAccessFile(File(parent, "phase9-v1/record.1.blob"), "rw").use { it.setLength(MAX_SECURE_BLOB_BYTES.toLong() + 2049) }
        assertThrows(IllegalArgumentException::class.java) { store.reopen("record", SecureDataClass.PROFILE_ARTIFACT) }
    }

    @Test fun replacedRootIsRejectedBeforeCallback() = fixture { parent ->
        val root = File(parent, "root").also { check(it.mkdir()) }
        val lock = ProcessFileLock(root, ::hostIdentity)
        Files.move(root.toPath(), File(parent, "prior-root").toPath())
        check(root.mkdir())
        assertThrows(IllegalStateException::class.java) { lock.withLock { fail("replaced root admitted") } }
    }

    @Test fun symbolicLinkLockCannotRedirectAcquisition() = fixture { parent ->
        val root = File(parent, "root").also { check(it.mkdir()) }
        val outside = File(parent, "outside").also { it.writeBytes(byteArrayOf(3)) }
        Files.createSymbolicLink(File(root, ".store.lock").toPath(), outside.toPath())
        assertThrows(IllegalStateException::class.java) { locked(root) { fail("symlink admitted") } }
        assertArrayEquals(byteArrayOf(3), outside.readBytes())
    }

    @Test fun changedLockIdentityAcrossOpenRejectsCallbackAndReleasesChannel() = fixture { root ->
        val path = File(root, ".store.lock").toPath()
        Files.createFile(path)
        var replace = true
        val lock = ProcessFileLock(root) { candidate ->
            val identity = hostIdentity(candidate)
            if (candidate == path && replace) {
                replace = false
                Files.move(path, File(root, "old-lock").toPath())
                Files.createFile(path)
            }
            identity
        }
        assertThrows(IllegalStateException::class.java) { lock.withLock { fail("replaced lock admitted") } }
        assertEquals("ACQUIRED", probe(root))
        assertEquals(5, locked(root) { 5 })
    }

    @Test fun interruptedWaiterDoesNotCloseHolderChannel() = fixture { root ->
        val holderEntered = CountDownLatch(1)
        val holderRelease = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        val holder = executor.submit { locked(root) { holderEntered.countDown(); check(holderRelease.await(15, TimeUnit.SECONDS)) } }
        val admitted = CountDownLatch(1)
        val outcome = java.util.concurrent.atomic.AtomicReference<Throwable>()
        var preserved = false
        val waiter = Thread {
            var reads = 0
            val lock = ProcessFileLock(root) { path -> hostIdentity(path).also { if (++reads == 4) admitted.countDown() } }
            try { lock.withLock { fail("interrupted waiter entered") } }
            catch (failure: Throwable) { outcome.set(failure); preserved = Thread.currentThread().isInterrupted }
        }
        try {
            assertTrue(holderEntered.await(5, TimeUnit.SECONDS))
            waiter.start()
            assertTrue(admitted.await(5, TimeUnit.SECONDS))
            waiter.interrupt()
            waiter.join(5000)
            assertFalse(waiter.isAlive)
            assertEquals("STORAGE_LOCKED", outcome.get()?.message)
            assertTrue(preserved)
            assertEquals("CONTENDED", probe(root))
        } finally {
            holderRelease.countDown()
            waiter.interrupt()
            waiter.join(5000)
            try { holder.get(5, TimeUnit.SECONDS) } finally { executor.shutdownNow() }
        }
        assertEquals("ACQUIRED", probe(root))
    }

    @Test fun resetDoesNotDeleteUnknownRoleEntries() = fixture { parent ->
        val store = store(parent)
        val unknown = File(parent, "phase9-v1/future.999.blob").also { it.writeBytes(byteArrayOf(8)) }
        store.deleteAll()
        assertArrayEquals(byteArrayOf(8), unknown.readBytes())
    }

    @Test fun atomicPublicationExposesOnlyCompleteOldOrNewEnvelope() = fixture { parent ->
        val store = store(parent)
        val codec = SecureEnvelopeCodec()
        store.stage("record", SecureDataClass.PROFILE_ARTIFACT, byteArrayOf(1))
        val target = File(parent, "phase9-v1/record.1.blob")
        val reading = java.util.concurrent.atomic.AtomicBoolean(true)
        val started = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        val reader = executor.submit<Int> {
            var observed = 0
            while (reading.get()) {
                val encoded = Files.readAllBytes(target.toPath())
                val plaintext = try { codec.open(encoded, "record", FixtureKek()).plaintext } finally { encoded.fill(0) }
                try { assertTrue(plaintext.contentEquals(byteArrayOf(1)) || plaintext.contentEquals(byteArrayOf(2))) }
                finally { plaintext.fill(0) }
                observed++
                started.countDown()
            }
            observed
        }
        try {
            assertTrue(started.await(5, TimeUnit.SECONDS))
            repeat(3) {
                val before = Files.readAllBytes(target.toPath())
                try {
                    try { store.stage("record", SecureDataClass.PROFILE_ARTIFACT, byteArrayOf(2)) }
                    catch (failure: java.nio.file.AccessDeniedException) {
                        if (!System.getProperty("os.name").orEmpty().startsWith("Windows")) throw failure
                        val after = Files.readAllBytes(target.toPath())
                        try { assertArrayEquals(before, after) } finally { after.fill(0) }
                    }
                } finally { before.fill(0) }
            }
        } finally {
            reading.set(false)
            try { assertTrue(reader.get(5, TimeUnit.SECONDS) > 0) } finally { executor.shutdownNow() }
        }
        store.stage("record", SecureDataClass.PROFILE_ARTIFACT, byteArrayOf(2))
        assertArrayEquals(byteArrayOf(2), store.reopen("record", SecureDataClass.PROFILE_ARTIFACT))
    }

    private fun store(parent: File, sync: (File) -> Unit = {}): SecureBlobStore {
        return SecureBlobStore(File(parent, "phase9-v1"), SecureEnvelopeCodec(), FixtureKek(), sync, ::hostIdentity)
    }

    private fun update(store: SecureBlobStore, transform: (ByteArray?) -> ByteArray) {
        store.update("record", SecureDataClass.PROFILE_ARTIFACT, transform)
    }

    private fun fixture(block: (File) -> Unit) {
        // Production canonicalizes its owner path, including Windows short-name TEMP roots.
        val root = Files.createTempDirectory("legacy-lock-").toFile().canonicalFile
        try { block(root) } finally { check(root.deleteRecursively()) }
    }

    private fun probe(root: File): String {
        val child = child(root, "probe")
        try {
            val result = line(child)
            assertTrue(child.waitFor(5, TimeUnit.SECONDS))
            assertEquals(0, child.exitValue())
            return result
        } finally { if (child.isAlive) child.destroyForcibly().waitFor(5, TimeUnit.SECONDS) }
    }

    private fun child(root: File, mode: String): Process {
        val classpath = listOf(ProcessFileLockTest::class.java, kotlin.Unit::class.java)
            .map { File(checkNotNull(it.protectionDomain).codeSource.location.toURI()).absolutePath }
            .joinToString(File.pathSeparator)
        val executable = if (System.getProperty("os.name").orEmpty().startsWith("Windows")) "java.exe" else "java"
        return ProcessBuilder(File(System.getProperty("java.home"), "bin/$executable").absolutePath,
            "-Xms16m", "-Xmx64m", "-XX:ActiveProcessorCount=2",
            "-cp", classpath, ProcessFileLockTest::class.java.name, root.absolutePath, mode)
            .redirectErrorStream(true).start()
    }

    private fun line(child: Process): String {
        val executor = Executors.newSingleThreadExecutor()
        try { return executor.submit<String> { child.inputStream.bufferedReader().readLine() ?: "EOF" }.get(5, TimeUnit.SECONDS) }
        finally { executor.shutdownNow() }
    }

    companion object {
        private fun hostIdentity(path: java.nio.file.Path): Any {
            if (!System.getProperty("os.name").orEmpty().startsWith("Windows")) return checkNotNull(
                Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes::class.java, java.nio.file.LinkOption.NOFOLLOW_LINKS).fileKey())
            val systemRootValue = checkNotNull(System.getenv("SystemRoot")) { "system root unavailable" }
            check(systemRootValue.isNotBlank()) { "system root unavailable" }
            val systemRoot = File(systemRootValue)
            check(systemRoot.isAbsolute && systemRoot.isDirectory) { "invalid system root" }
            val executable = File(systemRoot, "System32/fsutil.exe")
            check(executable.isFile) { "identity command unavailable" }
            val process = ProcessBuilder(executable.absolutePath, "file", "queryfileid", path.toString())
                .redirectErrorStream(true).start()
            try {
                check(process.waitFor(2, TimeUnit.SECONDS)) { "identity command timed out" }
                val output = process.inputStream.readNBytes(4097)
                check(output.size <= 4096 && process.exitValue() == 0) { "identity command failed" }
                val matches = Regex("0x[0-9a-fA-F]{32}").findAll(output.toString(Charsets.UTF_8)).toList()
                check(matches.size == 1) { "identity command ambiguous" }
                return path.toFile().canonicalFile.toPath().root.toString().lowercase() + matches.single().value.lowercase()
            } finally { if (process.isAlive) { process.destroyForcibly(); check(process.waitFor(5, TimeUnit.SECONDS)) } }
        }

        @JvmStatic fun main(args: Array<String>) {
            hostIdentity(File(args[0]).toPath())
            FileChannel.open(File(args[0], ".store.lock").toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE).use { channel ->
                hostIdentity(File(args[0], ".store.lock").toPath())
                val lock = channel.tryLock()
                if (lock == null) { println("CONTENDED"); return }
                lock.use {
                    println("ACQUIRED")
                    System.out.flush()
                    if (args[1] == "hold") System.`in`.read()
                }
            }
        }
    }

    private class FixtureKek(override val generation: Int = 1) : KeyEncryptionKey {
        override val hardwareSecurityLevel = "test"
        private val key = javax.crypto.spec.SecretKeySpec(ByteArray(32) { 11 }, "AES")
        override fun wrap(recordId: String, dataClass: SecureDataClass, key: ByteArray): WrappedKey {
            val nonce = ByteArray(12) { 5 }
            return WrappedKey(nonce, aesGcmEncrypt(this.key, nonce, "$recordId:${dataClass.wireValue}".encodeToByteArray(), key))
        }
        override fun unwrap(recordId: String, dataClass: SecureDataClass, wrapped: WrappedKey): ByteArray =
            aesGcmDecrypt(key, wrapped.nonce, "$recordId:${dataClass.wireValue}".encodeToByteArray(), wrapped.ciphertext)
    }
}
