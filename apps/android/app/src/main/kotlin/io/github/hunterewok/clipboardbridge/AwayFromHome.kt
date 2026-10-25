// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.hunterewok.clipboardbridge.kit.FrameTransport
import io.github.hunterewok.clipboardbridge.kit.Member
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * What sync away from home keeps on this phone (docs/protocol.md, section
 * 11): its WireGuard private key, made on the phone, and the last offer of
 * the group's hub with the hub's device ID.
 */
class AwayState(val key: ByteArray, val hub: String? = null, val offer: Member.TunnelOffer? = null) {
    fun withOffer(hub: String, offer: Member.TunnelOffer) = AwayState(key, hub, offer)

    fun encode(): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).run {
            writeByte(VERSION)
            write(key)
            val o = offer
            if (hub == null || o == null) {
                writeBoolean(false)
            } else {
                writeBoolean(true)
                writeUTF(hub)
                write(o.hubKey)
                write(o.psk)
                writeByte(o.endpoints.size)
                o.endpoints.forEach { writeUTF(it) }
                writeUTF(o.obfuscation ?: "")
                writeUTF(o.vless ?: "")
            }
        }
        return out.toByteArray()
    }

    companion object {
        private const val VERSION = 3

        /** The state in b, or null when it is not one this version wrote. */
        fun decode(b: ByteArray): AwayState? = try {
            DataInputStream(ByteArrayInputStream(b)).run {
                val version = readByte().toInt()
                if (version !in 1..VERSION) return null
                val key = ByteArray(32).also { readFully(it) }
                if (!readBoolean()) return AwayState(key)
                val hub = readUTF()
                val hubKey = ByteArray(32).also { readFully(it) }
                val psk = ByteArray(32).also { readFully(it) }
                val endpoints = List(readUnsignedByte()) { readUTF() }
                // Version 1 had no obfuscation settings.
                val obfuscation = if (version == 1) "" else readUTF()
                // Nor had version 2 the way over VLESS.
                val vless = if (version <= 2) "" else readUTF()
                val o = Member.TunnelOffer(hubKey, psk, endpoints, obfuscation.takeIf { it.isNotEmpty() }, vless.takeIf { it.isNotEmpty() })
                if (!o.isValid) return null
                AwayState(key, hub, o)
            }
        } catch (e: IOException) {
            null
        }
    }
}

/** A running tunnel to the hub: a loopback port that leads to the hub's member port. */
interface OpenTunnel {
    val port: Int
    fun setEndpoint(endpoint: String)
    fun close()
}

/** Makes keys and tunnels; the app's comes from mobile/cbbtun, the tests' from a fake. */
interface Tunnels {
    fun newKey(): ByteArray
    fun publicKey(private: ByteArray): ByteArray
    /**
     * Starts a tunnel; obfuscation is the offer's settings as JSON, "" for plain WireGuard, and vless its
     * way over VLESS as JSON, "" without it.
     */
    fun start(
        private: ByteArray, psk: ByteArray, hubKey: ByteArray, device: String, hub: String, endpoint: String,
        obfuscation: String, vless: String,
    ): OpenTunnel
}

/** The tunnel of mobile/cbbtun, WireGuard in the app's process. */
object GoTunnels : Tunnels {
    override fun newKey(): ByteArray = cbbtun.Cbbtun.newKey()
    override fun publicKey(private: ByteArray): ByteArray = cbbtun.Cbbtun.publicKey(private)
    override fun start(
        private: ByteArray, psk: ByteArray, hubKey: ByteArray, device: String, hub: String, endpoint: String,
        obfuscation: String, vless: String,
    ): OpenTunnel {
        val t = cbbtun.Cbbtun.start(private, psk, hubKey, device, hub, endpoint, obfuscation, vless)
        return object : OpenTunnel {
            override val port: Int = t.port().toInt()
            override fun setEndpoint(endpoint: String) = t.setEndpoint(endpoint)
            override fun close() {
                t.close()
            }
        }
    }
}

/**
 * A small file encrypted with an AES key in the Keystore, under alias,
 * that never leaves it and needs no unlock, so the phone syncs in the
 * background as at home.
 */
class SealedFile(private val file: File, private val alias: String) {
    /** The file's contents, or null when there is none. */
    fun read(): ByteArray? {
        if (!file.exists()) return null
        val b = file.readBytes()
        if (b.size < IV) return null
        val c = Cipher.getInstance(CIPHER)
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, b, 0, IV))
        return c.doFinal(b, IV, b.size - IV)
    }

    fun write(data: ByteArray) {
        val c = Cipher.getInstance(CIPHER)
        c.init(Cipher.ENCRYPT_MODE, key())
        val tmp = File(file.path + ".tmp")
        tmp.writeBytes(c.iv + c.doFinal(data))
        if (!tmp.renameTo(file)) throw IOException("cannot replace $file")
    }

    /** Deletes the file and its key. */
    fun delete() {
        file.delete()
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        g.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return g.generateKey()
    }

    companion object {
        private const val PROVIDER = "AndroidKeyStore"
        private const val CIPHER = "AES/GCM/NoPadding"
        private const val IV = 12
    }
}

/** The state of sync away from home in its sealed file. */
class AwayFile(file: File) {
    private val sealed = SealedFile(file, "clipboardbridge.away")

    fun read(): AwayState? = sealed.read()?.let(AwayState::decode)

    fun write(s: AwayState) = sealed.write(s.encode())

    fun delete() = sealed.delete()
}

/**
 * Sync away from home on this phone: off until the user turns it on. Then
 * the hellos offer the phone's WireGuard key, the hub's answer is kept, and
 * while the hub is not on the home network the phone reaches it through
 * the tunnel, in the app's own process, with the same member TLS as at
 * home (docs/design.md, "Sync away from home"). It fails closed: without a
 * tunnel there is no connection.
 */
class AwayFromHome(
    private val device: String,
    private val tunnels: Tunnels,
    private val load: () -> AwayState?,
    private val save: (AwayState?) -> Unit,
    /** Whether the hub is found on the home network, where it is dialed directly. */
    private val atHome: (String) -> Boolean,
    /** Dials the hub's member TLS through the loopback port, checking that the peer is the hub. */
    private val dial: (port: Int, hub: String) -> FrameTransport,
    /** Runs a connection to the hub until it ends. */
    private val serve: (FrameTransport, String) -> Unit,
    /** Whether a device may be the hub: the group's root or an admin (Records.mayHost). */
    private val mayHost: (String) -> Boolean,
    private val log: (String, Throwable?) -> Unit = { _, _ -> },
    private val firstWaitMS: Long = 1_000,
    private val maxWaitMS: Long = 30_000,
    private val homeCheckMS: Long = 5_000,
) {
    /** What the screens show. */
    enum class Status { OFF, WAITING_FOR_HUB, AT_HOME, CONNECTING, CONNECTED }

    private val lock = Object()
    private var state: AwayState? = runCatching { load() }.onFailure { log("cannot read the tunnel's state", it) }.getOrNull()
    private var tunnel: OpenTunnel? = null
    private var thread: Thread? = null
    private var stopped = false

    @Volatile var status: Status = Status.OFF
        private set

    @Volatile var lastError: Throwable? = null
        private set

    val isOn: Boolean get() = synchronized(lock) { state != null }

    /** The public key the hellos offer the hub; null while it is off. */
    val publicKey: ByteArray?
        get() = synchronized(lock) { state?.key }?.let { runCatching { tunnels.publicKey(it) }.getOrNull() }

    /** Turns it on with a new key; the hub's offer comes at home, on the next connection to it. */
    fun turnOn() {
        val s = AwayState(tunnels.newKey())
        save(s)
        synchronized(lock) {
            state = s
            lock.notifyAll()
        }
    }

    /** Turns it off: forgets the key and the offer and closes the tunnel. */
    fun turnOff() {
        save(null)
        synchronized(lock) {
            state = null
            closeTunnelLocked()
            lock.notifyAll()
        }
    }

    /**
     * Keeps the offer a peer, the group's hub, sent for this phone's key.
     * Only the group's root or an admin may be the hub, and once a hub is
     * kept, offers from another device are ignored: the hub changes only
     * when the user turns sync away from home off and on again.
     */
    fun keep(from: String?, offer: Member.TunnelOffer) {
        if (from == null || !offer.isValid || !mayHost(from)) return
        val next = synchronized(lock) {
            val s = state ?: return
            if (s.hub != null && s.hub != from) return
            if (s.hub == from && s.offer == offer) return
            s.withOffer(from, offer).also {
                state = it
                // A new preshared key or new endpoints: start again with them.
                closeTunnelLocked()
                lock.notifyAll()
            }
        }
        runCatching { save(next) }.onFailure { log("cannot keep the hub's offer", it) }
    }

    /** Starts the loop that reaches the hub through the tunnel while it is away. */
    fun start() = synchronized(lock) {
        if (thread != null) return
        stopped = false
        thread = Thread(::run, "cbb global").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        val t = synchronized(lock) {
            stopped = true
            closeTunnelLocked()
            lock.notifyAll()
            thread.also { thread = null }
        }
        t?.interrupt()
    }

    private fun closeTunnelLocked() {
        val t = tunnel ?: return
        tunnel = null
        runCatching { t.close() }
    }

    private fun run() {
        var wait = firstWaitMS
        var endpoint = 0
        try {
            while (true) {
                val (s, open) = synchronized(lock) {
                    if (stopped) return
                    state to tunnel
                }
                if (s == null) {
                    status = Status.OFF
                    idle(0)
                    continue
                }
                val hub = s.hub
                val offer = s.offer
                if (hub == null || offer == null || offer.endpoints.isEmpty()) {
                    status = Status.WAITING_FOR_HUB
                    idle(0)
                    continue
                }
                if (atHome(hub)) {
                    status = Status.AT_HOME
                    synchronized(lock) { if (tunnel === open) closeTunnelLocked() }
                    wait = firstWaitMS
                    idle(homeCheckMS)
                    continue
                }
                status = Status.CONNECTING
                val t = open ?: try {
                    tunnels.start(
                        s.key, offer.psk, offer.hubKey, device, hub, offer.endpoints[endpoint % offer.endpoints.size],
                        offer.obfuscation ?: "", offer.vless ?: "",
                    )
                } catch (e: Exception) {
                    fail("the tunnel to the hub could not start", e)
                    wait = backoff(wait)
                    continue
                }
                if (t !== open) {
                    val kept = synchronized(lock) {
                        (!stopped && state === s).also { if (it) tunnel = t }
                    }
                    if (!kept) {
                        runCatching { t.close() }
                        continue
                    }
                }
                val started = System.nanoTime()
                try {
                    val conn = dial(t.port, hub)
                    status = Status.CONNECTED
                    lastError = null
                    serve(conn, hub)
                    if ((System.nanoTime() - started) / 1_000_000 > maxWaitMS) wait = firstWaitMS
                } catch (e: Exception) {
                    fail("the hub does not answer through the tunnel", e)
                    // The next of the hub's endpoints, in turn.
                    endpoint++
                    runCatching { t.setEndpoint(offer.endpoints[endpoint % offer.endpoints.size]) }
                }
                if (synchronized(lock) { stopped }) return
                wait = backoff(wait)
            }
        } catch (e: InterruptedException) {
            // stopped
        } finally {
            status = Status.OFF
        }
    }

    private fun fail(what: String, e: Exception) {
        lastError = e
        log(what, e)
    }

    private fun backoff(wait: Long): Long {
        idle(wait)
        return minOf(wait * 2, maxWaitMS)
    }

    /** Waits ms, or until something changes; 0 waits for a change only. */
    private fun idle(ms: Long) = synchronized(lock) {
        if (!stopped) lock.wait(ms)
    }
}
