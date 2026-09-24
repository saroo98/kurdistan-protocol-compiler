// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.content.Context
import android.content.ContextWrapper
import android.content.pm.ApplicationInfo
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.nio.file.Files
import java.security.KeyStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kurdistanvpn.core.nativeapi.DurableChildDirectoryResult
import org.kurdistanvpn.core.nativeapi.DurableCode
import org.kurdistanvpn.core.nativeapi.DurableDirectory
import org.kurdistanvpn.core.nativeapi.DurableFileIdentity
import org.kurdistanvpn.core.nativeapi.DurableFilePrimitives
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.kurdistanvpn.data.protectedstate.ProtectedStateProcessOwner

/** Owned temporary fixtures only. No application-root reset, initialization or key creation. */
class CredentialStorageStartupDeviceTest {
    @Test
    fun directoryOpenUsesCurrentAbiAndRejectsFilesAndSymlinks() = withOwnedDirectory(listOf(
        FixtureEntry("payload", 384, "owned nonsecret directory-open fixture"),
        FixtureEntry("link", linkTarget = "."),
    )) { directory, _ ->
        val flagsMethod = ProtectedStateApplicationFacade.Companion::class.java
            .getDeclaredMethod("credentialParentOpenFlags").apply { isAccessible = true }
        val flags = flagsMethod.invoke(ProtectedStateApplicationFacade.Companion) as Int
        val expected = Os.lstat(directory.path)
        val descriptor = try {
            Os.open(directory.path, flags, 0)
        } catch (_: ErrnoException) {
            null
        }
        assertNotNull("CURRENT_ABI_DIRECTORY_OPEN_FAILED", descriptor)
        val opened = checkNotNull(descriptor)
        try {
            val actual = Os.fstat(opened)
            assertTrue("OPENED_OBJECT_IS_NOT_DIRECTORY", OsConstants.S_ISDIR(actual.st_mode))
            assertEquals(expected.st_dev, actual.st_dev)
            assertEquals(expected.st_ino, actual.st_ino)
            assertEquals(expected.st_uid, actual.st_uid)
            assertEquals(448, actual.st_mode and 511)
            assertTrue("DIRECTORY_DESCRIPTOR_NOT_CLOSE_ON_EXEC",
                Os.fcntlInt(opened, OsConstants.F_GETFD, 0) and OsConstants.FD_CLOEXEC != 0)
        } finally {
            Os.close(opened)
        }

        val payload = "owned nonsecret directory-open fixture".encodeToByteArray()
        val regular = File(directory, "payload")
        val link = File(directory, "link")
        for (candidate in listOf(regular, link)) {
            val unexpected = try {
                Os.open(candidate.path, flags, 0)
            } catch (_: ErrnoException) {
                null
            }
            if (unexpected != null) Os.close(unexpected)
            assertTrue("NON_DIRECTORY_OR_SYMLINK_OPEN_ACCEPTED", unexpected == null)
        }
        assertArrayEquals(payload, regular.readBytes())
        assertTrue("SYMLINK_TARGET_CHANGED", directory.path == Os.readlink(link.path))
    }

    @Test
    fun readOnlyStartupUsesOwnedEmptyDirectoryWithoutMutatingIt() {
        // Wrong absence/error classification or startup provisioning breaks this contract.
        val missing = ProtectedStateApplicationFacade.OpenResult.Missing
        val migration = ProtectedStateApplicationFacade.OpenResult.MigrationRequired
        val unproven = ProtectedStateApplicationFacade.OpenResult.Unproven
        val cases = listOf(
            StartupCase("EMPTY", missing),
            StartupCase("FRAMEWORK_0771_EMPTY", missing, listOf(
                FixtureEntry("databases", 505), FixtureEntry("no_backup", 505))),
            StartupCase("LEGACY_DATABASE", migration, listOf(
                FixtureEntry("databases", 505),
                FixtureEntry("databases/phase9-metadata.db", 384, "synthetic legacy database"))),
            StartupCase("LEGACY_BLOBS", migration, listOf(
                FixtureEntry("no_backup", 505), FixtureEntry("no_backup/phase9-v1"),
                FixtureEntry("no_backup/phase9-v1/fixture.blob", 384, "synthetic legacy blob"))),
            StartupCase("PRIVATE_LEGACY", migration, listOf(
                FixtureEntry("no_backup"), FixtureEntry("no_backup/phase9-v1"),
                FixtureEntry("no_backup/phase9-v1/fixture.blob", 384, "synthetic private legacy blob"))),
            StartupCase("FRAMEWORK_0771_PROTECTED_PARTIAL", unproven, listOf(
                FixtureEntry("no_backup", 505), FixtureEntry("no_backup/protected-state-v1"),
                FixtureEntry("no_backup/protected-state-v1/partial.blob", 384, "synthetic partial state"))),
            StartupCase("UNSAFE_FRAMEWORK_MODE", unproven, listOf(FixtureEntry("no_backup", 511))),
            StartupCase("SYMLINK_FRAMEWORK_PARENT", unproven, listOf(
                FixtureEntry("framework-target"), FixtureEntry("no_backup", linkTarget = "framework-target"))),
            StartupCase("PROTECTED_ROOT_WITHOUT_LOCK", unproven, listOf(
                FixtureEntry("no_backup"), FixtureEntry("no_backup/protected-state-v1"))),
            StartupCase("UNSAFE_PROTECTED_MODE", unproven, listOf(
                FixtureEntry("no_backup"), FixtureEntry("no_backup/protected-state-v1", 511))),
            StartupCase("SYMLINK_PROTECTED_ROOT", unproven, listOf(
                FixtureEntry("no_backup"), FixtureEntry("protected-target"),
                FixtureEntry("no_backup/protected-state-v1", linkTarget = "protected-target"))),
            StartupCase("CHILD_IO_FAILURE", unproven, childFailure = DurableCode.IO_FAILURE),
            StartupCase("CHILD_CLOSE_UNPROVEN", unproven, childFailure = DurableCode.CLOSE_UNPROVEN),
        )
        fun keyAliases(): Set<String> = KeyStore.getInstance("AndroidKeyStore")
            .apply { load(null) }.aliases().toList().toSet()
        val failures = mutableListOf<String>()
        for (case in cases) withOwnedDirectory(case.entries) { directory, fixturePaths ->
            val target = InstrumentationRegistry.getInstrumentation().targetContext
            val info = ApplicationInfo(target.applicationInfo).apply {
                dataDir = directory.path
                javaClass.getField("credentialProtectedDataDir").set(this, directory.path)
            }
            val context = object : ContextWrapper(target) {
                override fun getApplicationContext(): Context = this
                override fun getApplicationInfo(): ApplicationInfo = info
                override fun getDataDir(): File = directory
            }
            val beforeKeys = keyAliases()
            val before = fixturePaths.map(::observe)
            val native = NativeBridge()
            val realPrimitives = native.durableFiles()
            val expectedParent = before.first()
            val primitives = if (case.childFailure == null) realPrimitives else
                object : DurableFilePrimitives by realPrimitives {
                    override fun openChildDirectory(parent: DurableDirectory, leaf: String,
                        expectedChild: DurableFileIdentity?): DurableChildDirectoryResult {
                        if (parent.identity.device == expectedParent.device &&
                            parent.identity.inode == expectedParent.inode && leaf == "no_backup")
                            return DurableChildDirectoryResult(checkNotNull(case.childFailure))
                        return realPrimitives.openChildDirectory(parent, leaf, expectedChild)
                    }
                }
            val owner = ProtectedStateProcessOwner(monotonicMillis = SystemClock::elapsedRealtime)
            var facade: ProtectedStateApplicationFacade? = null
            try {
                val result = ProtectedStateApplicationFacade.openExistingReadOnly(context, primitives, native, owner)
                if (result is ProtectedStateApplicationFacade.OpenResult.Ready) facade = result.facade
                if (result !== case.expected) failures += "${case.name}:${result.javaClass.simpleName}"
            } finally {
                try { facade?.close() } finally { owner.close() }
            }
            assertTrue("${case.name}:READ_ONLY_STARTUP_CHANGED_FIXTURE", before == fixturePaths.map(::observe))
            assertTrue("${case.name}:READ_ONLY_STARTUP_CHANGED_KEY_ALIASES", beforeKeys == keyAliases())
        }
        assertTrue("STARTUP_CLASSIFICATION_MISMATCH:${failures.joinToString(",")}", failures.isEmpty())
    }

    private data class FixtureEntry(val relative: String, val mode: Int = 448,
        val contents: String? = null, val linkTarget: String? = null)
    private data class StartupCase(val name: String, val expected: ProtectedStateApplicationFacade.OpenResult,
        val entries: List<FixtureEntry> = emptyList(), val childFailure: DurableCode? = null)
    private data class Observation(val device: Long, val inode: Long, val uid: Int, val mode: Int,
        val size: Long, val links: Long, val modified: Long, val changed: Long,
        val contents: List<Byte>?, val children: List<String>?, val linkTarget: String?)

    private fun observe(file: File): Observation {
        check(file.parentFile?.canonicalFile == file.parentFile?.absoluteFile) { "FIXTURE_OBSERVATION_PARENT_CHANGED" }
        val stat = Os.lstat(file.path)
        check(!OsConstants.S_ISREG(stat.st_mode) || stat.st_size <= 1_024) { "FIXTURE_CONTENT_BOUNDS_CHANGED" }
        return Observation(stat.st_dev, stat.st_ino, stat.st_uid, stat.st_mode,
            stat.st_size, stat.st_nlink, stat.st_mtime, stat.st_ctime,
            if (OsConstants.S_ISREG(stat.st_mode)) file.readBytes().toList() else null,
            if (OsConstants.S_ISDIR(stat.st_mode)) checkNotNull(file.list()).sorted() else null,
            if (OsConstants.S_ISLNK(stat.st_mode)) Os.readlink(file.path) else null)
    }

    private fun withOwnedDirectory(entries: List<FixtureEntry>, block: (File, List<File>) -> Unit) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val cache = context.cacheDir.canonicalFile
        val directory = Files.createTempDirectory(cache.toPath(), "credential-startup-").toFile().absoluteFile
        check(directory.parentFile == cache && directory.canonicalFile == directory) { "FIXTURE_PATH_NOT_OWNED" }
        Os.chmod(directory.path, 448)
        val owned = linkedMapOf(directory to Os.lstat(directory.path))
        try {
            for (entry in entries) {
                check(entry.relative.split('/').all { it.matches(Regex("[a-z0-9._-]+")) && it !in setOf(".", "..") })
                val file = File(directory, entry.relative)
                val parent = file.parentFile
                check(parent in owned && parent?.canonicalFile == parent?.absoluteFile) { "FIXTURE_PARENT_NOT_OWNED" }
                when {
                    entry.linkTarget != null -> {
                        val target = if (entry.linkTarget == ".") directory else File(directory, entry.linkTarget)
                        check(target in owned && target.canonicalFile == target.absoluteFile) { "FIXTURE_LINK_NOT_OWNED" }
                        Os.symlink(target.path, file.path)
                    }
                    entry.contents != null -> {
                        Files.createFile(file.toPath())
                        owned[file] = Os.lstat(file.path)
                        file.writeBytes(entry.contents.encodeToByteArray())
                        Os.chmod(file.path, entry.mode)
                    }
                    else -> { Files.createDirectory(file.toPath()); Os.chmod(file.path, entry.mode) }
                }
                owned[file] = Os.lstat(file.path)
            }
            block(directory, owned.keys.toList())
        } finally {
            // Delete only registered identities in reverse creation order, never unknown descendants.
            for ((file, identity) in owned.entries.reversed()) {
                val rootIdentity = owned.getValue(directory)
                val currentRoot = Os.lstat(directory.path)
                check(directory.parentFile == cache && directory.canonicalFile == directory &&
                    file.parentFile?.canonicalFile == file.parentFile?.absoluteFile &&
                    currentRoot.st_dev == rootIdentity.st_dev && currentRoot.st_ino == rootIdentity.st_ino &&
                    currentRoot.st_uid == rootIdentity.st_uid && OsConstants.S_ISDIR(currentRoot.st_mode)) {
                    "FIXTURE_CLEANUP_PATH_CHANGED"
                }
                val current = Os.lstat(file.path)
                check(current.st_uid == context.applicationInfo.uid && current.st_dev == identity.st_dev &&
                    current.st_ino == identity.st_ino && (current.st_mode and OsConstants.S_IFMT) ==
                    (identity.st_mode and OsConstants.S_IFMT)) { "FIXTURE_CLEANUP_IDENTITY_CHANGED" }
                if (OsConstants.S_ISDIR(current.st_mode)) {
                    check(checkNotNull(file.list()).isEmpty()) { "FIXTURE_CLEANUP_UNEXPECTED_ENTRY" }
                }
                Files.delete(file.toPath())
            }
        }
    }
}
