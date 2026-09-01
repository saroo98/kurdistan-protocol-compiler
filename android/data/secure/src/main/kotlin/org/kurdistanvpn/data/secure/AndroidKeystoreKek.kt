// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

class KeyInvalidatedException(cause: Throwable) :
    IllegalStateException("Android Keystore key is invalidated", cause)

class MissingKeyException :
    IllegalStateException("Android Keystore key is missing")

class AndroidKeystoreKek private constructor(
    private val alias: String,
    override val generation: Int,
    private val key: SecretKey,
    override val hardwareSecurityLevel: String,
) : KeyEncryptionKey {

    override fun wrap(recordId: String, dataClass: SecureDataClass, key: ByteArray): WrappedKey {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, this.key)
            val nonce = cipher.iv.clone()
            require(nonce.size == 12) { "Android Keystore returned an invalid GCM nonce" }
            cipher.updateAAD(wrapAAD(recordId, dataClass))
            WrappedKey(
                nonce = nonce,
                ciphertext = cipher.doFinal(key),
            )
        } catch (error: KeyPermanentlyInvalidatedException) {
            throw KeyInvalidatedException(error)
        }
    }

    override fun unwrap(
        recordId: String,
        dataClass: SecureDataClass,
        wrapped: WrappedKey,
    ): ByteArray = try {
        aesGcmDecrypt(
            key,
            wrapped.nonce,
            wrapAAD(recordId, dataClass),
            wrapped.ciphertext,
        )
    } catch (error: KeyPermanentlyInvalidatedException) {
        throw KeyInvalidatedException(error)
    }

    private fun wrapAAD(recordId: String, dataClass: SecureDataClass): ByteArray =
        "kurdistan-kek-v1\u0000$alias\u0000$generation\u0000${dataClass.wireValue}\u0000$recordId"
            .encodeToByteArray()

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"

        @Synchronized fun loadExisting(alias: String, generation: Int): AndroidKeystoreKek {
            require(alias.isNotBlank() && generation > 0)
            val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            val key = store.getKey(alias, null) as? SecretKey ?: throw MissingKeyException()
            return AndroidKeystoreKek(
                alias = alias,
                generation = generation,
                key = key,
                hardwareSecurityLevel = securityLevel(key),
            )
        }

        @Synchronized fun createForFirstUse(
            alias: String,
            generation: Int,
            preferStrongBox: Boolean = true,
        ): AndroidKeystoreKek {
            require(alias.isNotBlank() && generation > 0)
            val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            val key = FirstUseKeyCreation.create(
                preferStrongBox = preferStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P,
                exists = { store.containsAlias(alias) },
                generate = { generate(alias, it) },
                isStrongBoxUnavailable = { failure ->
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                        failure is StrongBoxUnavailableException
                },
            )
            return AndroidKeystoreKek(
                alias = alias,
                generation = generation,
                key = key,
                hardwareSecurityLevel = securityLevel(key),
            )
        }

        @Synchronized fun deleteForExplicitReset(alias: String) {
            require(alias.isNotBlank())
            val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            if (store.containsAlias(alias)) {
                store.deleteEntry(alias)
            }
        }

        private fun generate(alias: String, strongBox: Boolean): SecretKey {
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(false)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(strongBox)
            }
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).run {
                init(builder.build())
                generateKey()
            }
        }

        @Suppress("DEPRECATION")
        private fun securityLevel(key: SecretKey): String = runCatching {
            val info = SecretKeyFactory.getInstance(key.algorithm, KEYSTORE)
                .getKeySpec(key, KeyInfo::class.java) as KeyInfo
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
                    else -> "unknown"
                }
            } else if (info.isInsideSecureHardware) {
                "hardware"
            } else {
                "software"
            }
        }.getOrDefault("unknown")
    }
}

/** Testable first-use admission. The broker must also hold the cross-process writer lease. */
internal object FirstUseKeyCreation {
    fun <T> create(
        preferStrongBox: Boolean,
        exists: () -> Boolean,
        generate: (Boolean) -> T,
        isStrongBoxUnavailable: (Exception) -> Boolean,
    ): T {
        check(!exists()) { "refusing to replace an existing Keystore key" }
        return try { generate(preferStrongBox) }
        catch (failure: Exception) {
            // A generic failure can follow partial publication. Never replace that key,
            // and never silently change hardware policy after an unrelated provider error.
            if (!preferStrongBox || !isStrongBoxUnavailable(failure) || exists()) throw failure
            generate(false)
        }
    }
}
