// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import java.io.IOException
import java.util.concurrent.LinkedBlockingQueue

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
) {
    private val lock = Any()
    private val conns = mutableSetOf<Conn>()

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
            val hello = engine.hello(name).copy(records = records?.digest)
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
                    synchronized(lock) {
                        c.adminKey = m.hello.adminKey
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
                    continue
                }
                when (m) {
                    is Member.Message.Event -> {
                        val e = m.event
                        if (e != null) synchronized(lock) { apply(engine.received(e), c) }
                    }
                    is Member.Message.Cert -> onCert(m.cert)
                    is Member.Message.Records -> if (m.records.isNotEmpty()) {
                        synchronized(lock) {
                            val fresh = records?.add(m.records).orEmpty()
                            if (fresh.isNotEmpty()) sendRecords(fresh, c)
                        }
                    }
                    Member.Message.Bye -> return
                    else -> {} // a ping, an event that did not decode, or a newer type
                }
            }
        } finally {
            synchronized(lock) { conns.remove(c) }
            c.finish()
            t.close()
        }
    }

    /** Says goodbye on every connection and closes it. */
    fun closeAll() = synchronized(lock) { conns.forEach { it.goodbye() } }

    /** Closes the connections to a device, for example one just removed. */
    fun close(peer: String) = synchronized(lock) { conns.filter { it.peer == peer }.forEach { it.goodbye() } }

    /** Sends records made on this phone to every connected member. */
    fun sendRecords(rs: List<Member.Record>) = synchronized(lock) { sendRecords(rs, null) }

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
