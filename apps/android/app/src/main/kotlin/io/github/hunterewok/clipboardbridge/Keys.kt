// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import io.github.hunterewok.clipboardbridge.kit.CertificateSigner
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * The phone's keys in the Android Keystore, which never lets them out: in
 * StrongBox where the phone has it, else in the TEE.
 *
 * - The member key signs the TLS handshakes with the computers; it needs no
 *   unlock, so the phone syncs in the background.
 * - The root key (the group CA's, on the phone that made the group) and the
 *   admin key (a phone the root made an admin) sign certificates and
 *   records. They sign only for [AUTH_SECONDS] after the user passed the
 *   fingerprint, the face or the screen lock, as Face ID guards them on the
 *   iPhone.
 */
object Keys {
    const val MEMBER = "clipboardbridge.member"
    const val ROOT = "clipboardbridge.ca"
    const val ADMIN = "clipboardbridge.admin"

    /** How long one authentication lets the root and admin keys sign: one action's signatures, and the renewals right after. */
    const val AUTH_SECONDS = 300

    private const val PROVIDER = "AndroidKeyStore"

    /** The phone has no screen lock, which the root and admin keys need. */
    class NoScreenLock : Exception("set a screen lock first: the group's keys need it")

    private fun store(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    /** The signer of the key under alias, or null when there is none. */
    fun load(alias: String): KeystoreSigner? {
        val entry = store().getEntry(alias, null) as? KeyStore.PrivateKeyEntry ?: return null
        return KeystoreSigner(entry.privateKey, entry.certificate.publicKey.encoded)
    }

    /** The signer of the key under alias, made now when there is none. */
    fun loadOrCreate(context: Context, alias: String): KeystoreSigner = load(alias) ?: create(context, alias)

    /**
     * Makes a P-256 key under alias, replacing one that was there. The root
     * and admin keys need the user's authentication; a debug build on a
     * device without a screen lock, such as a fresh emulator, makes them
     * without, so the app can be tried there.
     */
    fun create(context: Context, alias: String): KeystoreSigner {
        val auth = alias != MEMBER
        if (auth && !context.getSystemService(KeyguardManager::class.java).isDeviceSecure && !isDebuggable(context)) throw NoScreenLock()
        val secure = auth && context.getSystemService(KeyguardManager::class.java).isDeviceSecure
        remove(alias)
        val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (strongBox) {
            try {
                return generate(alias, secure, strongBox = true)
            } catch (e: StrongBoxUnavailableException) {
                // Some StrongBox chips lack P-256 or are busy: the TEE then.
            }
        }
        return generate(alias, secure, strongBox = false)
    }

    private fun generate(alias: String, auth: Boolean, strongBox: Boolean): KeystoreSigner {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            // Conscrypt signs the TLS handshake over a digest it computed, which needs NONE.
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
            .setIsStrongBoxBacked(strongBox)
            .apply { if (auth) authenticate(this) }
            .build()
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        kpg.initialize(spec)
        val kp = kpg.generateKeyPair()
        return KeystoreSigner(kp.private, kp.public.encoded)
    }

    @Suppress("DEPRECATION")
    private fun authenticate(b: KeyGenParameterSpec.Builder) {
        b.setUserAuthenticationRequired(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            b.setUserAuthenticationParameters(
                AUTH_SECONDS,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
        } else {
            b.setUserAuthenticationValidityDurationSeconds(AUTH_SECONDS)
        }
    }

    fun remove(alias: String) {
        val s = store()
        if (s.containsAlias(alias)) s.deleteEntry(alias)
    }

    private fun isDebuggable(context: Context): Boolean =
        context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0
}

/** A Keystore key as a CertificateSigner, and as the private key of the phone's TLS identity. */
class KeystoreSigner(val privateKey: PrivateKey, override val publicKeyDER: ByteArray) : CertificateSigner {
    override fun signature(data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }

    /** An ECDSA signature, ASN.1 DER, of a SHA-256 digest: the member key signs the hub's TLS to its forwarder so (cbbtun's Signer). */
    fun signDigest(digest: ByteArray): ByteArray =
        Signature.getInstance("NONEwithECDSA").run {
            initSign(privateKey)
            update(digest)
            sign()
        }
}
