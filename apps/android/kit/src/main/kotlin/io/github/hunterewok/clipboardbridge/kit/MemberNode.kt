// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import java.io.IOException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Keeps the group's signed records for a node (docs/protocol.md, section
 * 10). Its methods are called with the node's lock held.
 */
interface RecordStore {
    /** The digest a hello carries; null without records. */
    val digest: String?

    /** Every record, for a peer whose digest differs. */
    val all: List<Member.Record>

    /** Takes records a peer sent and returns those that were new and valid. */
    fun add(records: List<Member.Record>): List<Member.Record>

    /**
     * Why the records refuse a peer's certificate chain (leaf first), as
     * RecordSet.refused, or null: a removed device is dropped by its key, not
     * only by its ID.
     */
    fun refused(chain: List<ByteArray>): String? = null

    /** Whether the peer with this verified chain may be the group's hub, as RecordSet.mayHost. */
    fun mayHost(device: String, chain: List<ByteArray>): Boolean = true
}

/**
 * The phone as a member: its sync engine and its connections to the
 * computers, which it dials (docs/protocol.md, section 9). Each connection
 * runs the member protocol of section 4: a hello first, then events, a
 * ping after 5 s without a write, and a close after 15 s without a read.
 *
 * serve blocks its thread for the life of a connection; each connection
 * has a writer thread and a watchdog thread of its own.
 */
class MemberNode(
    private val engine: SyncEngine,
    val name: String?,
    val role: Member.Role = Member.Role.PHONE,
    private val records: RecordStore? = null,
    /**
     * On an admin, gets each peer's certificate chain (leaf first) after its
     * hello and returns a renewal when it is due, which the peer then gets
     * in a cert message (section 2).
     */
    private val renew: ((List<ByteArray>) -> Renewal?)? = null,
    /**
     * On the root, gets the admin key a computer's hello offers and returns
     * the admin CA this phone issued for it, which the computer then gets in
     * an admin message, so one that missed it gets it again.
     */
    private val adminCA: ((ByteArray) -> ByteArray?)? = null,
    /** Gets the new current event when a peer's event becomes it. */
    private val onChange: (Member.Event) -> Unit = {},
    /** Gets a renewed member certificate a peer sent for this phone. */
    private val onCert: (ByteArray) -> Unit = {},
    /**
     * The WireGuard public key the hellos offer the group's hubs (section
     * 11) and the preshared key this phone chose for its tunnels, asked for
     * each connection; null while sync away from home is off.
     */
    private val tunnelKey: () -> Pair<ByteArray, ByteArray>? = { null },
    /**
     * Gets a valid tunnel offer a peer that may be a hub sent, with the
     * device ID the caller of serve named it by: a hub's answer to the
     * tunnel key, its own or another hub's passed on. A node with hub set
     * gets none.
     */
    private val onTunnel: (String?, Member.TunnelOffer) -> Unit = { _, _ -> },
    /**
     * On the phone while it is one of the group's hubs (docs/design.md,
     * "The phone as the hub"): gets the device ID the caller of serve named
     * a peer by, the tunnel key and preshared key its hello offers (the
     * preshared key null from an older member) and its certificate chain
     * (leaf first), and returns the offers the peer then gets in tunnel
     * messages: this hub's own, then the other hubs' it passes on.
     */
    private val hub: ((String, ByteArray, ByteArray?, List<ByteArray>) -> List<Member.TunnelOffer>)? = null,
    /**
     * On a hub: what it shares with a peer after its hello (section 11,
     * "Several hubs"), null for nothing; the peer's device ID, where the
     * caller of serve named it, and its chain.
     */
    private val hubShare: ((String, List<ByteArray>) -> Member.HubShare?)? = null,
    /** Gets what a peer that may be a hub shared, with its device ID and chain. */
    private val onHubs: (String, List<ByteArray>, Member.HubShare) -> Unit = { _, _, _ -> },
    /** This device's operating system, which the hellos state. */
    val os: String? = null,
    /** This phone's sync mode, which the hellos state; null for a phone without one, which shares. */
    private val mode: () -> String? = { null },
    /**
     * Carries out a command a peer sent (docs/protocol.md, section 15), with
     * the device ID the caller of serve named the peer by, and returns the
     * result the peer gets; without it every command is refused.
     */
    private val onCommand: ((String?, Member.Record) -> Member.CommandResult)? = null,
    /** This device's form, system version and version, which the hellos state too. */
    device: Member.DeviceInfo? = null,
    /** The attestations of this phone's keys, which every peer gets after its hello (section 17, "Evidence"). */
    private val evidence: () -> List<Member.Evidence> = { emptyList() },
    /** Gets the evidence a peer sent, with the device ID the caller of serve named it by and its chain (leaf first). */
    private val onEvidence: (String?, List<ByteArray>, Member.Evidence) -> Unit = { _, _, _ -> },
) {
    val device: Member.DeviceInfo? = device?.cleaned
    private val lock = Any()
    private val conns = mutableSetOf<Conn>()
    private val waiting = mutableMapOf<String, Waiting>()

    /** A command sent to peer, through the members in via, waiting for its result. */
    private class Waiting(val peer: String, val via: Set<String>, val got: CompletableFuture<Member.CommandResult>)

    /** A command passed on to the member to for the connection from, kept until it expires; from is null once the result went back. */
    private class Passing(var from: Conn?, val to: String, val expiresMS: Long)

    /** The commands passed on for other members, by ID (section 15). */
    private val passed = mutableMapOf<String, Passing>()

    /** A renewed member certificate for a peer, DER, and the admin CA that issued it; null when a root did. */
    class Renewal(val cert: ByteArray, val issuer: ByteArray? = null)

    class ProtocolException(message: String) : Exception(message)

    /** The current event with its age as of now. */
    val current: Member.Event? get() = synchronized(lock) { engine.currentEvent }

    /** The current text while it is usable. */
    val usable: Pair<String, Member.Kind>? get() = synchronized(lock) { engine.usable }

    /** The number of connections whose peer sent its hello. */
    val peers: Int get() = synchronized(lock) { conns.count { it.peerRole != null } }

    /** The device IDs of the connected members that sent their hello, where the caller of serve named them. */
    val connected: Set<String> get() = synchronized(lock) { conns.filter { it.peerRole != null }.mapNotNull { it.peer }.toSet() }

    /**
     * The admin keys that the connected computers offer in their hello, by
     * device ID, where the caller of serve named them: the computers the
     * root can make admins (section 10, "A computer as admin").
     */
    val offeredAdminKeys: Map<String, ByteArray>
        get() = synchronized(lock) {
            conns.mapNotNull { c -> val p = c.peer; val k = c.adminKey; if (p != null && k != null) p to k else null }.toMap()
        }

    /** Where the connected members' hellos say their keys live, by device ID, where the caller of serve named them. */
    val keyStores: Map<String, String>
        get() = synchronized(lock) {
            conns.mapNotNull { c -> val p = c.peer; val s = c.keyStore; if (p != null && s != null) p to s else null }.toMap()
        }

    /**
     * What the connected members' hellos say about their devices, their
     * invalid fields dropped, by device ID where the caller of serve named them.
     */
    val devices: Map<String, Member.DeviceInfo>
        get() = synchronized(lock) {
            conns.mapNotNull { c -> val p = c.peer; val d = c.device; if (p != null && d != null) p to d else null }.toMap()
        }

    /** The sync modes the connected members' hellos report, by device ID where the caller of serve named them. */
    val modes: Map<String, String>
        get() = synchronized(lock) {
            conns.mapNotNull { c -> val p = c.peer; val m = c.mode; if (p != null && m != null) p to m else null }.toMap()
        }

    /**
     * Sends the member peer a command signed for it (section 15) and waits
     * for its result, at most timeoutMS: on the connection to peer, or, with
     * via and without one, to every connected member, one of which passes it
     * on. It throws when it reaches no member, the connection to peer ends
     * first or no result comes in time.
     */
    fun command(peer: String, command: Member.Record, timeoutMS: Long = 10_000, via: Boolean = false): Member.CommandResult {
        val id = Commands.idOf(command) ?: throw IllegalArgumentException("the command has no ID")
        val got = CompletableFuture<Member.CommandResult>()
        val direct: Boolean
        synchronized(lock) {
            val helloed = conns.filter { it.peer != null && it.peerRole != null }
            val to = helloed.firstOrNull { it.peer == peer }?.let { listOf(it) } ?: if (via) helloed else emptyList()
            if (to.isEmpty()) throw ProtocolException("the device is not connected")
            direct = to.size == 1 && to[0].peer == peer
            waiting[id] = Waiting(peer, to.mapNotNull { it.peer }.toSet(), got)
            if (direct) to[0].waiters += got
            to.forEach { it.enqueue(Member.Message.Command(command)) }
        }
        try {
            return got.get(timeoutMS, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            if (!direct) throw ProtocolException("the device did not answer in time: it is not connected to this one, and no member connected to it passed the command on")
            throw ProtocolException("the device did not answer in time")
        } catch (e: ExecutionException) {
            throw ProtocolException("the connection to the device closed before it answered")
        } finally {
            synchronized(lock) { waiting.remove(id) }
        }
    }

    /**
     * Passes a command for the member to on, once by its ID, when to is
     * connected, and later its result back to from (section 15). The
     * receiver checks the signature, so this node can neither forge nor
     * change it.
     */
    private fun pass(from: Conn, command: Member.Record, id: String, to: String, expiresMS: Long) = synchronized(lock) {
        val now = System.currentTimeMillis()
        passed.entries.removeIf { it.value.expiresMS <= now }
        val dst = conns.firstOrNull { it.peer == to && it.peerRole != null }
        if (dst == null || dst === from || id.isEmpty() || expiresMS <= now || expiresMS - now > Commands.LIFETIME_MS + Commands.AHEAD_MS) return@synchronized
        if (passed.containsKey(id) || passed.size >= MAX_PASSED) return@synchronized
        passed[id] = Passing(from, to, expiresMS)
        dst.enqueue(Member.Message.Command(command))
    }

    /**
     * Sends each connected member the offer offerFor returns for it, the
     * old hub passing on the new hub's offer (section 11, "Moving the
     * hub"), and returns the members that got one.
     */
    fun sendTunnel(offerFor: (String) -> Member.TunnelOffer?): List<String> = sendTunnels { listOfNotNull(offerFor(it)) }

    /** Sends each connected member the offers offerFor returns for it, and returns the members that got any. */
    fun sendTunnels(offerFor: (String) -> List<Member.TunnelOffer>): List<String> = synchronized(lock) {
        conns.mapNotNull { c ->
            val p = c.peer ?: return@mapNotNull null
            if (c.peerRole == null) return@mapNotNull null
            val offers = offerFor(p)
            offers.forEach { c.enqueue(Member.Message.Tunnel(it)) }
            p.takeIf { offers.isNotEmpty() }
        }
    }

    /** Sends each connected member what shareFor returns for it, its device ID and chain, as a hub's share. */
    fun sendHubs(shareFor: (String, List<ByteArray>) -> Member.HubShare?) = synchronized(lock) {
        for (c in conns) {
            val p = c.peer ?: continue
            if (c.peerRole == null) continue
            shareFor(p, c.transport.peerChain)?.let { c.enqueue(Member.Message.Hubs(it)) }
        }
    }

    /** Sends a computer the admin CA the root issued for it. */
    fun sendAdminCA(adminCA: ByteArray, peer: String) = synchronized(lock) {
        for (c in conns) if (c.peer == peer && c.peerRole != null) c.enqueue(Member.Message.Admin(adminCA))
    }

    /** Sends a text this phone copied to every connected member. */
    fun send(text: String, kind: Member.Kind, via: Member.Via = Member.Via.COPY): Member.Event = synchronized(lock) {
        val e = engine.local(text, kind, via)
        for (c in conns) c.enqueue(Member.Message.Event(e))
        e
    }

    /**
     * Runs a connection whose TLS handshake is done until it ends, and
     * closes it. It returns normally when the peer says goodbye or this side
     * closed it (closeAll); it throws when the connection failed.
     */
    fun serve(t: FrameTransport, peer: String? = null) {
        val c = Conn(t, peer)
        synchronized(lock) {
            conns.add(c)
            val keys = tunnelKey()
            // A phone's keys are in the Secure Enclave or the Keystore.
            val hello = engine.hello(name).copy(
                records = records?.digest, tunnelKey = keys?.first, tunnelPSK = keys?.second, os = os, device = device, mode = mode(),
                keyStore = Records.HARDWARE,
            )
            c.enqueue(Member.Message.Hello(role, hello))
        }
        c.start()
        try {
            var first = true
            while (true) {
                val m = try {
                    c.readMessage()
                } catch (e: Exception) {
                    if (c.closing) return // closed on this side; nothing more counts
                    throw e
                }
                if (first) {
                    if (m !is Member.Message.Hello) throw ProtocolException("the peer's first message is no hello")
                    first = false
                    records?.refused(t.peerChain)?.let { why -> throw ProtocolException("the peer is refused: $why") }
                    synchronized(lock) {
                        c.adminKey = m.hello.adminKey
                        c.keyStore = m.hello.keyStore
                        c.device = m.hello.device?.cleaned
                        c.mode = m.hello.mode
                        c.peerRole = m.role
                        apply(engine.reconcile(m.hello), c)
                        val store = records
                        val mine = store?.digest
                        if (store != null && mine != null && mine != m.hello.records) c.enqueue(Member.Message.Records(store.all))
                    }
                    val chain = t.peerChain
                    val renewed = if (chain.isNotEmpty()) renew?.invoke(chain) else null
                    if (renewed != null) c.enqueue(Member.Message.Cert(renewed.cert, renewed.issuer))
                    val key = m.hello.adminKey
                    val ca = key?.let { adminCA?.invoke(it) }
                    if (ca != null) c.enqueue(Member.Message.Admin(ca))
                    val offered = m.hello.tunnelKey
                    if (offered != null && c.peer != null && chain.isNotEmpty()) {
                        val psk = m.hello.tunnelPSK?.takeIf { it.size == 32 }
                        hub?.invoke(c.peer, offered, psk, chain)?.forEach { c.enqueue(Member.Message.Tunnel(it)) }
                    }
                    if (c.peer != null && chain.isNotEmpty()) hubShare?.invoke(c.peer, chain)?.let { c.enqueue(Member.Message.Hubs(it)) }
                    for (e in evidence()) c.enqueue(Member.Message.Evidence(e))
                    continue
                }
                when (m) {
                    is Member.Message.Event -> {
                        val e = m.event
                        if (e != null) synchronized(lock) { apply(engine.received(e), c) }
                    }
                    is Member.Message.Cert -> onCert(m.cert)
                    is Member.Message.Evidence -> if (t.peerChain.isNotEmpty()) onEvidence(c.peer, t.peerChain, m.evidence)
                    // Only the root or an admin, by the records and its key.
                    // A hub is no client yet: it gets the other hubs' offers in their shares.
                    is Member.Message.Tunnel -> m.offer?.takeIf { hub == null && it.isValid && c.peer != null && records?.mayHost(c.peer, t.peerChain) != false }
                        ?.let { onTunnel(c.peer, it) }
                    is Member.Message.Hubs -> if (c.peer != null && records?.mayHost(c.peer, t.peerChain) != false) onHubs(c.peer, t.peerChain, m.share)
                    is Member.Message.Records -> if (m.records.isNotEmpty()) {
                        synchronized(lock) {
                            val fresh = records?.add(m.records).orEmpty()
                            if (fresh.isNotEmpty()) {
                                sendRecords(fresh, c)
                                dropRefusedLocked()
                            }
                        }
                    }
                    is Member.Message.Command -> {
                        val o = Wire.parse(m.command.body)
                        val to = o?.optString("to")
                        if (to != null && to != engine.device) {
                            pass(c, m.command, o.optString("id") ?: "", to, o.optLong("expires_ms") ?: 0)
                        } else {
                            val r = onCommand?.invoke(c.peer, m.command)
                                ?: Member.CommandResult(Commands.idOf(m.command) ?: "", "refused", "this device takes no commands")
                            c.enqueue(Member.Message.Result(r.copy(by = engine.device)))
                        }
                    }
                    is Member.Message.Result -> synchronized(lock) {
                        val r = m.result
                        val w = waiting[r.id]
                        // A member the command went to so that it passes it on answers only with the receiver's result.
                        if (w != null && c.peer in w.via && (c.peer == w.peer || r.by == w.peer)) {
                            w.got.complete(r)
                        } else {
                            val p = passed[r.id]
                            if (p != null && p.to == c.peer) p.from?.let { from -> p.from = null; from.enqueue(Member.Message.Result(r)) }
                        }
                    }
                    Member.Message.Bye -> return
                    else -> {} // a ping, an event that did not decode, or a newer type
                }
            }
        } finally {
            synchronized(lock) {
                conns.remove(c)
                c.waiters.forEach { it.completeExceptionally(ProtocolException("the connection closed")) }
            }
            c.finish()
            t.close()
        }
    }

    /** Says goodbye on every connection and closes it. */
    fun closeAll() = synchronized(lock) { conns.forEach { it.goodbye() } }

    /** Closes the connections to a device, for example one just removed. */
    fun close(peer: String) = synchronized(lock) { conns.filter { it.peer == peer }.forEach { it.goodbye() } }

    /**
     * Says goodbye, after what is queued for them, on the connections to
     * peers, and waits up to timeoutMS until they ended: an old hub's
     * clients then have the new hub's offer before its tunnel stops.
     */
    fun sayGoodbye(peers: Collection<String>, timeoutMS: Long) {
        val closing = synchronized(lock) { conns.filter { it.peer in peers }.onEach { it.goodbye() } }
        val deadline = System.nanoTime() + timeoutMS * 1_000_000
        while (synchronized(lock) { closing.any { it in conns } } && System.nanoTime() < deadline) Thread.sleep(50)
    }

    /** Sends records made on this phone to every connected member. */
    fun sendRecords(rs: List<Member.Record>) = synchronized(lock) {
        sendRecords(rs, null)
        dropRefusedLocked()
    }

    /** Closes the connections whose peers the records now refuse, as a device just removed. */
    private fun dropRefusedLocked() {
        val store = records ?: return
        for (c in conns) if (store.refused(c.transport.peerChain) != null) c.goodbye()
    }

    private fun sendRecords(rs: List<Member.Record>, except: Conn?) {
        for (c in conns) if (c !== except && c.peerRole != null) c.enqueue(Member.Message.Records(rs))
    }

    private fun apply(r: SyncEngine.Result, from: Conn) {
        val e = r.forward
        if (e != null) for (c in conns) if (c !== from) c.enqueue(Member.Message.Event(e))
        if (r.changed) engine.currentEvent?.let(onChange)
    }

    /** One connection: a queue the writer drains, and the times of the last read and write for the ping and the timeout. */
    private class Conn(val transport: FrameTransport, val peer: String?) {
        private val queue = LinkedBlockingQueue<Any>()
        @Volatile var peerRole: Member.Role? = null

        /** The admin key the peer's hello offered. */
        @Volatile var adminKey: ByteArray? = null

        /** Where the peer's hello says its keys live. */
        @Volatile var keyStore: String? = null
        @Volatile var device: Member.DeviceInfo? = null
        @Volatile var mode: String? = null

        /** The commands sent on it that wait for their result. */
        val waiters = mutableListOf<CompletableFuture<Member.CommandResult>>()

        /** Whether this side ended the connection. */
        @Volatile var closing = false
        @Volatile private var done = false
        @Volatile private var lastRead = now()
        @Volatile private var lastWrite = now()
        private val threads = mutableListOf<Thread>()

        fun enqueue(m: Member.Message) {
            if (!done) queue.put(m)
        }

        fun start() {
            threads += Thread(::runWriter, "cbb-writer").apply { isDaemon = true; start() }
            threads += Thread(::runWatchdog, "cbb-watchdog").apply { isDaemon = true; start() }
        }

        /** Ends the writer, after a goodbye. */
        fun goodbye() {
            closing = true
            finish()
        }

        fun finish() {
            done = true
            queue.put(END)
        }

        private fun runWriter() {
            try {
                while (true) {
                    val m = queue.take()
                    if (m === END) break
                    transport.write(Member.encode(m as Member.Message))
                    lastWrite = now()
                }
                if (closing) {
                    runCatching { transport.write(Member.encode(Member.Message.Bye)) }
                    transport.close()
                }
            } catch (e: IOException) {
                transport.close()
            } catch (e: InterruptedException) {
                transport.close()
            }
        }

        /** Sends a ping after a quiet write side, and closes a connection silent for the timeout. */
        private fun runWatchdog() {
            try {
                while (!done) {
                    Thread.sleep(500)
                    val t = now()
                    if (t - lastRead > Member.TIMEOUT_MS) {
                        transport.close()
                        return
                    }
                    if (t - lastWrite >= Member.PING_EVERY_MS) {
                        lastWrite = t // one ping per quiet spell
                        enqueue(Member.Message.Ping)
                    }
                }
            } catch (e: InterruptedException) {
                // finished
            }
        }

        fun readMessage(): Member.Message {
            val n = Member.length(transport.read(4))
            val body = transport.read(n)
            lastRead = now()
            return Member.decode(body)
        }

        companion object {
            private val END = Any()

            fun now(): Long = System.nanoTime() / 1_000_000
        }
    }
}

/** The most commands a member passes on at a time, as Go. */
private const val MAX_PASSED = 4096
