// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.Os
import android.system.OsConstants
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade

/** Installed native-filesystem tests, never host-only evidence. The separately authorized
 * runner must create and supply an empty invocation-owned disposable cache root. These tests do not
 * initialize product storage, create keys, repair state, connect, or delete their root.
 * Child evidence is preserved. A successful process run still does not prove power-loss
 * durability; that requires the independent crash/observer journey and terminal verifier. */
class Phase17ProtectedStateIntegrityDeviceTest {
    @Test
    fun protectedStateFailureDiagnosticsUseTheProductionRootLeaf() {
        val productionRoot = ProtectedStateApplicationFacade::class.java.getDeclaredField("ROOT").apply {
            isAccessible = true
        }.get(null) as String
        val observed = Phase17FieldHarness.protectedStateDiagnosticRoot(File("/synthetic-credential-root"))
        assertEquals("no_backup", observed.parentFile?.name)
        assertEquals(productionRoot, observed.name)
    }

    @Test
    fun nativeLeafAndOwnerChecksCannotEscapeTheSuppliedDirectory() = withRoot("leaf-owner") { root, native ->
        val before = native.list(root.directory, DurableBounds.MAX_ENTRIES)
        assertEquals(DurableCode.OK, before.code)
        for (leaf in listOf("", ".", "..", "../escape", "child/escape", "bad\\leaf", "a\u0000b", "x".repeat(256))) {
            assertEquals(DurableCode.INVALID, native.read(root.directory, leaf, 64).code)
        }
        val wrongOwner = root.directory.copy(expectedUid = root.directory.expectedUid + 1)
        assertNotEquals(DurableCode.OK, native.read(wrongOwner, "record", 64).code)
        assertEquals(before.entries, native.list(root.directory, DurableBounds.MAX_ENTRIES).entries)
    }

    @Test
    fun nativeWriterReplacementSyncAndDeletionRequireExactOldIdentity() = withRoot("writer-replacement") { root, native ->
        val lock = native.bootstrapLock(root.directory, "writer.lock")
        assertEquals(DurableCode.OK, lock.code)
        val identity = checkNotNull(lock.identity)
        assertNotEquals(DurableCode.OK, native.bootstrapLock(root.directory, "writer.lock").code)
        val opened = native.openWriter(root.directory, "writer.lock", identity)
        assertEquals(DurableCode.OK, opened.code)
        val writer = checkNotNull(opened.writer)
        try {
            assertNotEquals(DurableCode.OK, native.openWriter(root.directory, "writer.lock", identity).code)
            assertEquals(DurableCode.OK, writer.replace("record", "temporary-one", null, byteArrayOf(1, 2, 3), 64).code)
            val first = checkNotNull(writer.read("record", 64).snapshot)
            assertArrayEquals(byteArrayOf(1, 2, 3), first.bytes)
            val forged = DurableSnapshot(first.identity, byteArrayOf(9))
            assertEquals(DurableCode.CONFLICT, writer.replace("record", "temporary-two", forged, byteArrayOf(4), 64).code)
            assertEquals(DurableCode.OK, writer.replace("record", "temporary-three", first, byteArrayOf(4, 5), 64).code)
            val second = checkNotNull(writer.read("record", 64).snapshot)
            assertNotEquals(first.identity, second.identity)
            assertArrayEquals(byteArrayOf(4, 5), second.bytes)
            val synchronized = writer.syncAndObserveExisting("record", second, 64)
            assertEquals(DurableCode.OK, synchronized.code)
            assertEquals(second.identity, synchronized.snapshot?.identity)
            assertEquals(DurableCode.CONFLICT, writer.delete("record", first, 64).code)
            // This is the explicitly exercised deletion primitive, not fixture cleanup.
            assertEquals(DurableCode.OK, writer.delete("record", second, 64).code)
            assertEquals(DurableCode.ABSENT, writer.read("record", 64).code)
        } finally {
            assertEquals(DurableCode.OK, writer.closeResult())
            assertEquals(DurableCode.CLOSED, writer.closeResult())
        }
        assertEquals(root.directory.identity.inode, Os.fstat(root.descriptor.fileDescriptor).st_ino)
    }

    @Test
    fun nativeReadsRejectSymlinkHardLinkAndChangedDirectoryIdentity() = withRoot("read-link-identity") { root, native ->
        val lock = checkNotNull(native.bootstrapLock(root.directory, "writer.lock").identity)
        val writer = checkNotNull(native.openWriter(root.directory, "writer.lock", lock).writer)
        try { assertEquals(DurableCode.OK, writer.replace("record", "temporary-one", null, byteArrayOf(7), 64).code) }
        finally { assertEquals(DurableCode.OK, writer.closeResult()) }
        // Only synthetic names under the already validated test-owned root are used.
        // No fallback or deletion is attempted if the platform denies these operations.
        Os.symlink("record", root.child("symbolic-record"))
        assertEquals(DurableCode.UNSAFE, native.read(root.directory, "symbolic-record", 64).code)
        Os.link(root.child("record"), root.child("hard-record"))
        assertEquals(DurableCode.UNSAFE, native.read(root.directory, "record", 64).code)
        assertEquals(DurableCode.UNSAFE, native.read(root.directory, "hard-record", 64).code)
        val substituted = root.directory.copy(identity = DurableFileIdentity(root.directory.identity.device,
            Math.addExact(root.directory.identity.inode, 1)))
        assertNotEquals(DurableCode.OK, native.list(substituted, 64).code)
    }

    @Test
    fun existingDirectoryOpenNeverCreatesOrAdoptsAnUnprovenLeaf() = withRoot("existing-directory") { root, native ->
        val absent = native.openChildDirectory(root.directory, "absent-child")
        assertEquals(DurableCode.ABSENT, absent.code)
        val created = native.createChildDirectoryExclusive(root.directory, "child")
        assertEquals(DurableCode.OK, created.code)
        val child = checkNotNull(created.owner)
        val identity = checkNotNull(child.borrow()).identity
        assertEquals(DurableCode.OK, child.closeResult())
        assertEquals(DurableCode.CLOSED, child.closeResult())
        val reopened = native.openChildDirectory(root.directory, "child", identity)
        assertEquals(DurableCode.OK, reopened.code)
        assertEquals(DurableCode.OK, checkNotNull(reopened.owner).closeResult())
        assertEquals(DurableCode.CONFLICT, native.createChildDirectoryExclusive(root.directory, "child").code)
        assertNotEquals(DurableCode.OK, native.openChildDirectory(root.directory, "child",
            DurableFileIdentity(identity.device, Math.addExact(identity.inode, 1))).code)
    }

    private fun withRoot(role: String, block: (SuppliedRoot, DurableFilePrimitives) -> Unit) {
        // Each invocation needs a fresh root supplied by its controller. There is no
        // fallback, mkdir, product-path discovery, automatic cleanup, or network access.
        val args = InstrumentationRegistry.getArguments()
        val supplied = checkNotNull(args.getString("phase17.disposableRoot")) { "EXPLICIT_DISPOSABLE_ROOT_REQUIRED" }
        val authorization = checkNotNull(args.getString("phase17.filesystemAuthorization"))
        val children = listOf("existing-directory", "leaf-owner", "read-link-identity", "writer-replacement")
        require(role in children)
        // Instrumentation executes in the target application process. Keep the
        // synthetic root under that process's cache UID, never under protected
        // product storage or the separately installed test APK's data directory.
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val parent = context.cacheDir
        val base = File(supplied)
        require(base.isAbsolute) { "EXPLICIT_DISPOSABLE_ROOT_NOT_ABSOLUTE" }
        require(base.name.matches(Regex("phase17-disposable-[0-9a-f]{32}"))) {
            "EXPLICIT_DISPOSABLE_ROOT_LEAF_INVALID"
        }
        // Android may expose the same package data directory through /data/data or
        // /data/user/0. Bind the supplied root to the target cache by canonical parent,
        // then reject a substituted root entry independently with lstat below.
        require(base.parentFile?.canonicalFile == parent.canonicalFile) {
            "EXPLICIT_DISPOSABLE_ROOT_PARENT_MISMATCH"
        }
        val baseBefore = Os.lstat(base.absolutePath)
        require(OsConstants.S_ISDIR(baseBefore.st_mode) && baseBefore.st_uid == Process.myUid() &&
            baseBefore.st_mode and 511 == 448
        ) { "EXPLICIT_DISPOSABLE_ROOT_ENTRY_UNSAFE" }
        val preimage = "kurdistan-phase17-filesystem-authorization-v1\u0000" + supplied + "\u0000" +
            children.joinToString("\u0000")
        val expectedAuthorization = MessageDigest.getInstance("SHA-256")
            .digest(preimage.toByteArray(StandardCharsets.UTF_8)).joinToString("") {
                "%02x".format(it.toInt() and 0xff)
            }
        require(authorization == expectedAuthorization)
        val file = File(base, role)
        require(file.parentFile?.absolutePath == base.absolutePath) { "EXPLICIT_DISPOSABLE_CHILD_ESCAPED" }
        var raw: java.io.FileDescriptor? = null
        var descriptor: ParcelFileDescriptor? = null
        try {
            val before = Os.lstat(file.absolutePath)
            require(OsConstants.S_ISDIR(before.st_mode) && before.st_uid == Process.myUid() && before.st_mode and 511 == 448)
            val flagsMethod = ProtectedStateApplicationFacade.Companion::class.java
                .getDeclaredMethod("credentialParentOpenFlags").apply { isAccessible = true }
            val flags = flagsMethod.invoke(ProtectedStateApplicationFacade.Companion) as Int
            val linuxODirectory = 0x00010000
            val linuxOCloexec = 0x00080000
            assertEquals(linuxOCloexec, flags and linuxOCloexec)
            assertEquals(linuxODirectory, flags and linuxODirectory)
            assertEquals(OsConstants.O_NOFOLLOW, flags and OsConstants.O_NOFOLLOW)
            if (Build.VERSION.SDK_INT >= 27) {
                assertEquals(OsConstants::class.java.getField("O_CLOEXEC").getInt(null), linuxOCloexec)
            }
            val descriptorsBefore = descriptorsForPath(file.absolutePath)
            raw = Os.open(file.absolutePath, flags, 0)
            if (Build.VERSION.SDK_INT >= 30) {
                val descriptorFlags = Os.fcntlInt(checkNotNull(raw), OsConstants.F_GETFD, 0)
                assertEquals(OsConstants.FD_CLOEXEC, descriptorFlags and OsConstants.FD_CLOEXEC)
            } else {
                val openedDescriptor = (descriptorsForPath(file.absolutePath) - descriptorsBefore).single()
                val descriptorFlags = File("/proc/self/fdinfo/$openedDescriptor").useLines { lines ->
                    checkNotNull(lines.firstOrNull { it.startsWith("flags:") }) { "FDINFO_FLAGS_UNAVAILABLE" }
                        .substringAfter(':').trim().toLong(8)
                }
                assertEquals(linuxOCloexec.toLong(), descriptorFlags and linuxOCloexec.toLong())
            }
            val observed = Os.fstat(checkNotNull(raw))
            require(observed.st_dev == before.st_dev && observed.st_ino == before.st_ino && observed.st_uid == before.st_uid && observed.st_mode == before.st_mode)
            descriptor = ParcelFileDescriptor.dup(checkNotNull(raw))
            val retiring = raw; raw = null; Os.close(checkNotNull(retiring)) // never retry close
            val root = SuppliedRoot(file, descriptor, DurableDirectory(descriptor.fd.toLong(), observed.st_uid.toLong(),
                DurableFileIdentity(observed.st_dev, observed.st_ino)))
            val native = NativeBridge().durableFiles()
            assertTrue(checkNotNull(native.list(root.directory, 1).entries).isEmpty())
            block(root, native)
        } finally {
            var failure: Throwable? = null
            try { val retiring = raw; raw = null; if (retiring != null) Os.close(retiring) } catch (error: Throwable) { failure = error }
            try { val retiring = descriptor; descriptor = null; retiring?.close() } catch (error: Throwable) { if (failure == null) failure = error else failure.addSuppressed(error) }
            if (failure != null) throw IllegalStateException("TEST_DIRECTORY_CLEANUP_UNPROVEN", failure)
        }
    }
    private fun descriptorsForPath(path: String): Set<Int> = checkNotNull(File("/proc/self/fd").list()).mapNotNull { leaf ->
        val descriptor = leaf.toIntOrNull() ?: return@mapNotNull null
        val target = try { Os.readlink("/proc/self/fd/$leaf") } catch (_: Throwable) { return@mapNotNull null }
        descriptor.takeIf { target == path }
    }.toSet()
    private class SuppliedRoot(private val file: File, val descriptor: ParcelFileDescriptor, val directory: DurableDirectory) {
        fun child(leaf: String): String { require(DurableBounds.leaf(leaf) != null); return File(file, leaf).absolutePath }
    }
}
