// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.content.Context
import androidx.room.Room
import java.io.File
import java.io.FileOutputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.kurdistanvpn.core.model.RuntimeAvailability
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.data.metadata.KurdistanMetadataDatabase
import org.kurdistanvpn.data.secure.AndroidKeystoreKek
import org.kurdistanvpn.data.secure.KeyInvalidatedException
import org.kurdistanvpn.data.secure.MissingKeyException
import org.kurdistanvpn.data.secure.ProfileAdmissionJournal
import org.kurdistanvpn.data.secure.SecureBlobStore
import org.kurdistanvpn.data.secure.SecureEnvelopeCodec
import org.kurdistanvpn.data.secure.SecureRoutingPolicyStore
import org.kurdistanvpn.data.secure.EncryptedDiagnosticEventStore
import org.kurdistanvpn.data.settings.Phase9SettingsStore
import org.kurdistanvpn.runtime.api.UnavailableRuntime

class Phase9CompositionRoot private constructor(
    private val context: Context,
    val nativeCore: KurdNativeCore,
    private var database: KurdistanMetadataDatabase,
    admissionJournal: ProfileAdmissionJournal?,
    sensitiveRoutingStore: SecureRoutingPolicyStore?,
    diagnosticEventStore: EncryptedDiagnosticEventStore?,
    storageFailure: StorageFailure?,
    val runtime: UnavailableRuntime,
    val settingsStore: Phase9SettingsStore,
) {
    var admissionJournal: ProfileAdmissionJournal? = admissionJournal
        private set
    var sensitiveRoutingStore: SecureRoutingPolicyStore? = sensitiveRoutingStore
        private set
    var diagnosticEventStore: EncryptedDiagnosticEventStore? = diagnosticEventStore
        private set
    var storageFailure: StorageFailure? = storageFailure
        private set

    enum class StorageFailure {
        KEY_INVALIDATED,
        DEGRADED,
    }

    suspend fun resetProtectedState(): Boolean = withContext(Dispatchers.IO) {
        val journal = admissionJournal ?: return@withContext false
        if (!journal.resetAll()) {
            return@withContext false
        }
        val marker = resetMarker(context)
        try {
            writeResetMarker(marker)
            database.close()
            AndroidKeystoreKek.deleteForExplicitReset(KEK_ALIAS)
            deleteDatabase(context)
            val replacement = initializeProtectedStorage(context, nativeCore)
            database = replacement.database
            admissionJournal = replacement.journal
            sensitiveRoutingStore = replacement.routingStore
            diagnosticEventStore = replacement.diagnosticStore
            storageFailure = replacement.failure
            check(
                replacement.journal != null &&
                    replacement.routingStore != null &&
                    replacement.diagnosticStore != null &&
                    replacement.failure == null,
            )
            check(marker.delete()) { "explicit-reset marker deletion failed" }
            true
        } catch (_: Throwable) {
            admissionJournal = null
            sensitiveRoutingStore = null
            diagnosticEventStore = null
            storageFailure = StorageFailure.DEGRADED
            false
        }
    }

    companion object {
        private const val DATABASE_NAME = "phase9-metadata.db"
        private const val KEK_ALIAS = "kurdistan-phase9-availability-kek-v1"
        private const val RESET_MARKER = "phase9-explicit-reset-v1.marker"

        fun create(context: Context): Phase9CompositionRoot {
            check(context.applicationContext === context)
            val nativeCore = NativeBridge()
            recoverInterruptedReset(context)
            val storage = initializeProtectedStorage(context, nativeCore)
            if (storage.failure == null) {
                val marker = resetMarker(context)
                check(!marker.exists() || marker.delete()) {
                    "explicit-reset marker deletion failed"
                }
            }
            return Phase9CompositionRoot(
                context = context,
                nativeCore = nativeCore,
                database = storage.database,
                admissionJournal = storage.journal,
                sensitiveRoutingStore = storage.routingStore,
                diagnosticEventStore = storage.diagnosticStore,
                storageFailure = storage.failure,
                runtime = UnavailableRuntime(RuntimeAvailability.PHASE_9_NO_RUNTIME),
                settingsStore = Phase9SettingsStore(context),
            )
        }

        private fun initializeProtectedStorage(
            context: Context,
            nativeCore: KurdNativeCore,
        ): ProtectedStorage {
            val databaseExisted = context.getDatabasePath(DATABASE_NAME).exists()
            val database = Room.databaseBuilder(
                context,
                KurdistanMetadataDatabase::class.java,
                DATABASE_NAME,
            ).build()
            var failure: StorageFailure? = null
            val kek = try {
                AndroidKeystoreKek.loadExisting(KEK_ALIAS, generation = 1)
            } catch (_: MissingKeyException) {
                if (databaseExisted) {
                    failure = StorageFailure.KEY_INVALIDATED
                    null
                } else {
                    AndroidKeystoreKek.createForFirstUse(
                        KEK_ALIAS,
                        generation = 1,
                        preferStrongBox = true,
                    )
                }
            } catch (_: KeyInvalidatedException) {
                failure = StorageFailure.KEY_INVALIDATED
                null
            } catch (_: Throwable) {
                failure = StorageFailure.DEGRADED
                null
            }
            val blobStore = kek?.let { SecureBlobStore(context, SecureEnvelopeCodec(), it) }
            val journal = blobStore?.let {
                ProfileAdmissionJournal(
                    nativeCore = nativeCore,
                    catalog = database.profileCatalog(),
                    blobs = it,
                    productionTrust = false,
                )
            }
            return ProtectedStorage(
                database = database,
                journal = journal,
                routingStore = blobStore?.let(::SecureRoutingPolicyStore),
                diagnosticStore = blobStore?.let(::EncryptedDiagnosticEventStore),
                failure = failure,
            )
        }

        private fun recoverInterruptedReset(context: Context) {
            if (!resetMarker(context).isFile) {
                return
            }
            AndroidKeystoreKek.deleteForExplicitReset(KEK_ALIAS)
            deleteDatabase(context)
            val secureRoot = File(context.noBackupFilesDir, "phase9-v1")
            if (secureRoot.exists()) {
                check(secureRoot.canonicalFile.parentFile == context.noBackupFilesDir.canonicalFile)
                secureRoot.listFiles().orEmpty().forEach { child ->
                    check(child.canonicalFile.parentFile == secureRoot.canonicalFile)
                    check(child.isFile && child.delete()) {
                        "interrupted-reset blob deletion failed"
                    }
                }
            }
        }

        private fun deleteDatabase(context: Context) {
            val path = context.getDatabasePath(DATABASE_NAME)
            val related = listOf(
                path,
                File("${path.path}-journal"),
                File("${path.path}-shm"),
                File("${path.path}-wal"),
            )
            context.deleteDatabase(DATABASE_NAME)
            related.forEach { file ->
                check(!file.exists() || file.delete()) {
                    "metadata database deletion failed"
                }
            }
        }

        private fun resetMarker(context: Context): File =
            File(context.noBackupFilesDir, RESET_MARKER)

        private fun writeResetMarker(marker: File) {
            FileOutputStream(marker).use { stream ->
                stream.write("kurdistan-phase9-explicit-reset-v1\n".encodeToByteArray())
                stream.fd.sync()
            }
        }

        private data class ProtectedStorage(
            val database: KurdistanMetadataDatabase,
            val journal: ProfileAdmissionJournal?,
            val routingStore: SecureRoutingPolicyStore?,
            val diagnosticStore: EncryptedDiagnosticEventStore?,
            val failure: StorageFailure?,
        )
    }
}
