// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import java.security.SecureRandom

/**
 * The phone as the group's hub while its app is open (docs/design.md, "The
 * phone as the hub", D-64): the clients it admits by the tunnel keys their
 * hellos offer, and the offers it answers with (docs/protocol.md, section
 * 11), by the same rules as a computer's hub. The tunnel itself is cbbtun's
 * Hub, which takes clientsJson.
 *
 * publicKey is the hub's WireGuard public key. The methods are thread-safe.
 */
class PhoneHub(val publicKey: ByteArray, clients: List<Client> = emptyList()) {
    /** A client: its device ID, the tunnel key it offered and the preshared key the hub gave it. */
    class Client(val device: String, val key: ByteArray, val psk: ByteArray) {
        fun toJson(): JsonObject = Wire.obj("device" to Wire.str(device), "key" to Wire.bytes(key), "psk" to Wire.bytes(psk))

        companion object {
            fun fromJson(o: JsonObject): Client = Client(
                o.optString("device") ?: throw WireTypeException("device: missing"),
                o.optBytes("key") ?: throw WireTypeException("key: missing"),
                o.optBytes("psk") ?: throw WireTypeException("psk: missing"),
            )
        }
    }

    class Refused(message: String) : Exception(message)

    private val lock = Any()
    private val list = clients.toMutableList()

    /**
     * Where the clients reach the hub away from home, "ip:port": the
     * forwarder's endpoint, which the offers carry.
     */
    @Volatile var endpoints: List<String> = emptyList()

    /** The group's obfuscation settings as JSON text, null for plain WireGuard. */
    @Volatile var obfuscation: String? = null

    /**
     * Whether the clients may come only over VLESS: the offers then wait for
     * vless, the way to the forwarder that its answer gives (cbbtun's
     * Status).
     */
    @Volatile var vlessOnly: Boolean = false

    /** The way to the forwarder over VLESS as JSON text, null without it. */
    @Volatile var vless: String? = null

    init {
        require(publicKey.size == 32) { "a WireGuard key is 32 bytes" }
    }

    val clients: List<Client> get() = synchronized(lock) { list.toList() }

    /**
     * Admits device with the tunnel key it offered, as the hub keeps it. A
     * client that keeps its key keeps its preshared key; a new key gets a
     * new one. changed tells whether the clients must be saved and handed
     * to the tunnel again. It throws Refused for a key that is not 32
     * bytes, the hub's own, or another client's, and for a 257th client.
     */
    fun admit(device: String, key: ByteArray): Pair<Client, Boolean> = synchronized(lock) {
        if (!GroupCertificates.isDeviceID(device)) throw Refused("$device is not a device ID")
        if (key.size != 32 || key.all { it == 0.toByte() } || key.contentEquals(publicKey)) throw Refused("a client offered no key or the hub's own")
        val i = list.indexOfFirst { it.device == device }
        list.withIndex().firstOrNull { (j, o) -> j != i && o.key.contentEquals(key) }?.let { (_, o) ->
            throw Refused("$device offered the key of ${o.device}")
        }
        if (i >= 0) {
            val c = list[i]
            if (c.key.contentEquals(key)) return c to false
            return Client(device, key.copyOf(), newPSK()).also { list[i] = it } to true
        }
        if (list.size >= MAX_CLIENTS) throw Refused("the hub has too many clients")
        Client(device, key.copyOf(), newPSK()).also { list += it } to true
    }

    /** The offer for a client admitted with admit, or null while the offers wait for VLESS. */
    fun offer(c: Client): Member.TunnelOffer? {
        val v = vless
        if (vlessOnly && v == null) return null
        return Member.TunnelOffer(publicKey, c.psk, endpoints.take(8), obfuscation, v)
    }

    /**
     * Admits a peer and returns its offer, for MemberNode's hub: null when
     * it is refused (refused tells why) or the offers wait. changed gets
     * the clients when they changed.
     */
    fun offer(device: String, key: ByteArray, changed: (List<Client>) -> Unit = {}, refused: (String) -> Unit = {}): Member.TunnelOffer? {
        val (c, fresh) = try {
            admit(device, key)
        } catch (e: Refused) {
            refused(e.message ?: "refused")
            return null
        }
        if (fresh) changed(clients)
        return offer(c)
    }

    /**
     * The offer the client device gets when the hub moves to newHub, whose
     * offer without a preshared key is offer (a hub command's result): with
     * the client's own preshared key and newHub named (docs/protocol.md,
     * section 11, "Moving the hub"); null for a device that is no client,
     * or newHub itself.
     */
    fun movedOffer(device: String, newHub: String, offer: Member.TunnelOffer): Member.TunnelOffer? =
        if (device == newHub) null else clients.firstOrNull { it.device == device }?.let { offer.with(it.psk, newHub) }

    /** Forgets the clients keep refuses, removed devices for one, and returns their devices. */
    fun prune(keep: (Client) -> Boolean): List<String> = synchronized(lock) {
        val gone = list.filterNot(keep)
        list.removeAll(gone)
        gone.map { it.device }
    }

    /** The clients as cbbtun's StartHub and SetClients take them. */
    val clientsJson: String get() = JsonArray(clients.map { it.toJson() }).toString()

    companion object {
        /** The most clients a hub keeps, as a computer's hub. */
        const val MAX_CLIENTS = 256

        private val random = SecureRandom()

        private fun newPSK(): ByteArray = ByteArray(32).also { random.nextBytes(it) }

        /** The clients clientsJson gave; it throws IllegalArgumentException on anything else. */
        fun clientsFromJson(s: String): List<Client> {
            if (s.isEmpty()) return emptyList()
            try {
                val a = Json.parseToJsonElement(s) as? JsonArray ?: throw IllegalArgumentException("the clients are not an array")
                return a.map { Client.fromJson(it as? JsonObject ?: throw IllegalArgumentException("a client is not an object")) }
            } catch (e: WireTypeException) {
                throw IllegalArgumentException("the clients: ${e.message}", e)
            } catch (e: kotlinx.serialization.SerializationException) {
                throw IllegalArgumentException("the clients: ${e.message}", e)
            }
        }
    }
}
