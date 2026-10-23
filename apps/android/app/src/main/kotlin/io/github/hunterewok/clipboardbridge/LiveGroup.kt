// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.content.Context
import android.os.Build
import android.provider.Settings as SystemSettings
import io.github.hunterewok.clipboardbridge.kit.FoundMember
import io.github.hunterewok.clipboardbridge.kit.GroupCertificates
import io.github.hunterewok.clipboardbridge.kit.HybridClock
import io.github.hunterewok.clipboardbridge.kit.JoinCode
import io.github.hunterewok.clipboardbridge.kit.LocalAddresses
import io.github.hunterewok.clipboardbridge.kit.Member
import io.github.hunterewok.clipboardbridge.kit.MemberDialer
import io.github.hunterewok.clipboardbridge.kit.MemberNode
import io.github.hunterewok.clipboardbridge.kit.Pairing
import io.github.hunterewok.clipboardbridge.kit.PairingJoiner
import io.github.hunterewok.clipboardbridge.kit.PairingMember
import io.github.hunterewok.clipboardbridge.kit.PhoneGroup
import io.github.hunterewok.clipboardbridge.kit.RecordStore
import io.github.hunterewok.clipboardbridge.kit.SyncEngine
import io.github.hunterewok.clipboardbridge.kit.TLSListener
import io.github.hunterewok.clipboardbridge.kit.TLSTransport
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.io.IOException
import java.net.SocketException
import java.net.SocketTimeoutException
import java.time.Instant
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The phone's group (docs/protocol.md, section 9): its root or admin key
 * in the Keystore, signing only after the fingerprint, the face or the
 * screen lock (Keys, Authenticator), its member key there too, the group in
 * the app's files. While there is a group it finds the computers, keeps a
 * connection to each, and syncs with them.
 *
 * The group is read and changed under one lock: the screens' actions run on
 * the main thread and the network work on Dispatchers.IO, the node's
 * connections on threads of their own.
 */
class LiveGroup(private val context: Context, private val file: File = defaultFile(context)) {
    /** The failures the app says something about. */
    class Failure(val kind: Kind) : Exception(kind.name) {
        enum class Kind { UNREACHABLE, NOT_CONFIRMED, NO_NETWORK, TIMED_OUT, TOO_MANY_WRONG_CODES, NOT_ADMIN, NO_COMPUTERS, NO_SCREEN }
    }

    /** A device of the group, as the screens show it: a computer, or this phone. */
    data class Device(
        val id: String,
        val name: String,
        val online: Boolean,
        val role: String = "linux",
        val isSelf: Boolean = false,
        /** An admin: it may add and remove devices. */
        val admin: Boolean = false,
        /** The phone that holds the group's root. */
        val isRoot: Boolean = false,
        /** A computer this phone, the root, can make an admin: it offers an admin key. */
        val canMakeAdmin: Boolean = false,
    )

    enum class SyncResult { SENT, FETCHED, NOTHING_NEW }

    private val lock = Any()
    private var state: PhoneGroup? = runCatching { PhoneGroup.load(file) }.getOrNull()
    private var node: MemberNode? = null
    private var browser: NsdBrowser? = null
    private var dialer: MemberDialer? = null
    private var found: Set<FoundMember> = emptySet()

    /** The node, read under the lock; its methods are called outside it, as it calls back into the group under its own. */
    private val currentNode: MemberNode? get() = synchronized(lock) { node }

    /** Asks for the fingerprint, the face or the screen lock before the root or admin key signs. */
    val authenticator = Authenticator()

    /** The activity that shows the authentication prompt; null while the app is in the background. */
    @Volatile var activity: Context? = null

    val hasGroup: Boolean get() = synchronized(lock) { state != null }

    /**
     * Whether this phone may add and remove devices: it made the group, or
     * the phone that did made it an admin. A phone without a group makes
     * one when it adds a computer.
     */
    val isAdmin: Boolean get() = synchronized(lock) { state?.isAdmin ?: true }

    /** Every device of the group, this phone included. */
    val devices: List<Device>
        get() {
            // The node calls back into the group under its own lock, so it is asked outside this one.
            val (g, n) = synchronized(lock) { (state ?: return emptyList()) to node }
            val online = n?.connected.orEmpty()
            val offers = n?.offeredAdminKeys.orEmpty()
            val root = g.records.rootDevice
            return g.devices.map {
                Device(
                    id = it.id, name = it.name, online = it.id == g.device || it.id in online, role = it.role, isSelf = it.id == g.device,
                    admin = it.admin || it.id == root, isRoot = it.id == root,
                    canMakeAdmin = g.isRoot && !it.admin && it.role in setOf("linux", "mac") && offers[it.id] != null,
                )
            }
        }

    val computers: List<Device> get() = devices.filter { !it.isSelf }

    init {
        startSync()
    }

    /** This phone's name for the other devices: the one in the system's settings, else the model. */
    val deviceName: String
        get() = SystemSettings.Global.getString(context.contentResolver, SystemSettings.Global.DEVICE_NAME)?.takeIf { it.isNotBlank() }
            ?: Build.MODEL

    // Keys

    /** Makes this phone's own key, which proves it to the other devices, unless it has one. */
    fun prepare() {
        memberSigner()
    }

    private fun memberSigner(): KeystoreSigner = Keys.loadOrCreate(context, Keys.MEMBER)

    /** The alias of the key this phone signs with: the root key, or the admin key of a phone that joined. */
    private fun signingAlias(g: PhoneGroup?): String = if (g?.isRoot == false) Keys.ADMIN else Keys.ROOT

    /**
     * The signer of this phone's root or admin key for an action the user
     * asked for: after the fingerprint, the face or the screen lock, asked
     * once and good for the signatures of the next few minutes. A phone
     * that is no admin has no such key.
     */
    private suspend fun caSigner(reason: Int): KeystoreSigner {
        if (!isAdmin) throw Failure(Failure.Kind.NOT_ADMIN)
        return signer(signingAlias(synchronized(lock) { state }), reason)
    }

    private suspend fun signer(alias: String, reason: Int): KeystoreSigner {
        val ui = activity ?: throw Failure(Failure.Kind.NO_SCREEN)
        authenticator.authenticate(ui, ui.getString(reason))
        return withContext(Dispatchers.IO) { Keys.loadOrCreate(context, alias) }
    }

    // Admitting

    /** Admits the device whose QR code the user scanned. */
    suspend fun admit(code: JoinCode) {
        val ca = caSigner(R.string.reason_add)
        val member = withContext(Dispatchers.IO) { memberSigner() }
        val name = deviceName
        val g = withContext(Dispatchers.IO) {
            copyOfState() ?: PhoneGroup.create(ca, member.publicKeyDER, Instant.now(), PhoneGroup.validName(name))
        }
        var failure: Exception? = null
        for (addr in SyncRule.ordered(code.addrs)) {
            currentCoroutineContext().ensureActive()
            val (host, port) = SyncRule.split(addr) ?: continue
            try {
                val admitted = withTimeoutOrNull(PAIRING_DEADLINE_MS) {
                    val t = withContext(Dispatchers.IO) {
                        TLSTransport.dial(host, port, Pairing.ALPN, member.privateKey, g.memberChain) { chain ->
                            chain.firstOrNull()?.let { Pairing.fingerprint(it) } == code.fingerprint
                        }
                    }
                    // Closing the connection ends a pairing that takes too
                    // long or that the user cancelled: the pending read fails.
                    closingOnCancel({ t.close() }) {
                        try {
                            val leaf = t.peerCertificate ?: throw Failure(Failure.Kind.UNREACHABLE)
                            val sid = t.exportKeyingMaterial(Pairing.EXPORTER_LABEL, 32)
                            g.admit(t, code.code, leaf, sid, ca, Instant.now())
                        } finally {
                            t.close()
                        }
                    }
                } ?: throw Failure(Failure.Kind.UNREACHABLE)
                withContext(Dispatchers.IO) { adopt(g) }
                currentNode?.sendRecords(g.records.records)
                if (!admitted.confirmed) throw Failure(Failure.Kind.NOT_CONFIRMED)
                return
            } catch (e: CancellationException) {
                throw e
            } catch (e: PairingMember.Failure) {
                throw e // the computer answered: a wrong code is not worth another address
            } catch (e: Failure) {
                if (e.kind == Failure.Kind.NOT_CONFIRMED) throw e
                failure = telling(failure, e)
            } catch (e: Exception) {
                failure = telling(failure, e)
            }
        }
        throw failure ?: Failure(Failure.Kind.UNREACHABLE)
    }

    /** A deep copy of the group, to change it outside the lock and keep it only when the change works. */
    private fun copyOfState(): PhoneGroup? = synchronized(lock) { state?.let { PhoneGroup.fromJson(it.toJson()) } }

    /**
     * Saves a changed copy of the group and makes it the group, keeping the
     * records the node took in meanwhile; starts syncing when this is the
     * first group, and passes the change to the parts that run with it.
     */
    private fun adopt(g: PhoneGroup) {
        synchronized(lock) {
            state?.let { g.add(it.records.records) }
            g.save(file)
            state = g
        }
        startSync()
        relay()
    }

    // Joining

    /**
     * Joins another phone's group (docs/protocol.md, section 6, "The joiner
     * listens"): makes this phone's admin key, listens, hands show the QR
     * code to put on screen, and waits up to five minutes for an admin
     * phone to scan it and admit this one. Three wrong codes end it, as
     * does cancelling.
     */
    suspend fun join(show: (JoinCode) -> Unit) {
        if (hasGroup) return
        val listening = withContext(Dispatchers.IO) {
            val member = memberSigner()
            // The admin key, behind the screen lock like the root key;
            // reading its public key asks for nothing.
            val admin = Keys.load(Keys.ADMIN) ?: Keys.create(context, Keys.ADMIN)
            val device = SyncEngine.newID()
            val cert = GroupCertificates.selfSigned(device, member)
            val listener = TLSListener(0, Pairing.ALPN, member.privateKey, listOf(cert)) { it.isNotEmpty() }
            val addrs = LocalAddresses.current().map { JoinCode.address(it, listener.port) }
            if (addrs.isEmpty()) {
                listener.stop()
                throw Failure(Failure.Kind.NO_NETWORK)
            }
            Triple(listener, cert, admin) to JoinCode(JoinCode.newCode(), addrs, Pairing.fingerprint(cert))
        }
        val (parts, code) = listening
        val (listener, cert, admin) = parts
        show(code)
        val info = Pairing.Info(PhoneGroup.validName(deviceName), "android", admin.publicKeyDER)
        val stopped = AtomicBoolean(false)
        val stop = {
            stopped.set(true)
            listener.stop()
        }
        val joined = try {
            withTimeoutOrNull(JOIN_WINDOW_MS) {
                closingOnCancel(stop) { accept(listener, stopped, code, info, cert) }
            }
        } finally {
            stop()
        }
        if (joined == null) throw Failure(Failure.Kind.TIMED_OUT)
        withContext(Dispatchers.IO) {
            synchronized(lock) { state = PhoneGroup.joined(joined) }
            startSync()
        }
    }

    /** Takes connections until an admin phone admits this one; blocks. */
    private fun accept(listener: TLSListener, stopped: AtomicBoolean, code: JoinCode, info: Pairing.Info, cert: ByteArray): PairingJoiner.Joined {
        var wrong = 0
        while (true) {
            val t = try {
                listener.accept()
            } catch (e: IOException) {
                if (stopped.get()) throw e
                continue // a handshake that failed: another device, or a dropped connection
            }
            try {
                val leaf = t.peerCertificate ?: continue
                val sid = t.exportKeyingMaterial(Pairing.EXPORTER_LABEL, 32)
                return PairingJoiner.accept(t, code.code, info, leaf, cert, sid, Instant.now()) { PhoneGroup.joined(it).save(file) }
            } catch (e: PairingJoiner.Failure) {
                if (e.code == Pairing.ErrorCode.WRONG_CODE) {
                    wrong++
                    if (wrong >= JOIN_ATTEMPTS) throw Failure(Failure.Kind.TOO_MANY_WRONG_CODES)
                }
            } catch (e: Exception) {
                if (stopped.get()) throw e
                // a dropped connection: the code is not spent
            } finally {
                t.close()
            }
        }
    }

    // Removing

    /**
     * Removes a device from the group: a revocation signed with this
     * phone's root or admin key, sent to every connected computer, which
     * refuse the device from then on. The phone stops dialing it. Removing
     * the phone that holds the root hands the group to this one.
     */
    suspend fun remove(id: String) {
        val current = synchronized(lock) { state } ?: return
        if (!current.isRoot && id == current.records.rootDevice) {
            takeOver(id)
            return
        }
        val ca = caSigner(R.string.reason_remove)
        val g = copyOfState() ?: return
        val r = withContext(Dispatchers.IO) { g.revoke(id, ca, Instant.now()) }
        withContext(Dispatchers.IO) { adopt(g) }
        currentNode?.sendRecords(listOf(r))
        currentNode?.close(id)
    }

    /**
     * Makes a computer an admin (docs/protocol.md, section 10, "A computer
     * as admin"): the root key certifies the admin key the computer offers;
     * the computer gets its admin CA and every member the new record.
     */
    suspend fun makeAdmin(id: String) {
        val n = synchronized(lock) { if (state?.isRoot == true) node else null }
        val key = n?.offeredAdminKeys?.get(id) ?: throw Failure(Failure.Kind.NOT_ADMIN)
        val root = caSigner(R.string.reason_make_admin)
        val g = copyOfState() ?: return
        val (ca, r) = withContext(Dispatchers.IO) { g.makeAdmin(id, key, root, Instant.now()) }
        withContext(Dispatchers.IO) { adopt(g) }
        currentNode?.sendRecords(listOf(r))
        currentNode?.sendAdminCA(ca, id)
    }

    /**
     * Removes the phone that holds the group's root, when it is lost: this
     * admin phone makes a new root key and takes the group over
     * (docs/protocol.md, section 10, "Handing the group over"). From then
     * on it signs with that key.
     */
    private suspend fun takeOver(id: String) {
        val admin = signer(Keys.ADMIN, R.string.reason_take_over)
        val rs = withContext(Dispatchers.IO) {
            // A root key left from a group this phone made before goes.
            val root = Keys.create(context, Keys.ROOT)
            val g = copyOfState() ?: return@withContext null
            val rs = g.takeOver(id, admin, root, Instant.now())
            adopt(g)
            rs
        } ?: return
        currentNode?.sendRecords(rs)
        currentNode?.close(id)
        withContext(Dispatchers.IO) { restartSync() }
    }

    // Syncing

    /** Starts finding and dialing the computers, once there is a group. */
    private fun startSync() {
        val b = startBrowsing() ?: return
        b.start()
    }

    private fun startBrowsing(): NsdBrowser? = synchronized(lock) {
        val g = state ?: return null
        if (node != null) return null
        val member = runCatching { memberSigner() }.getOrNull() ?: return null
        val n = MemberNode(
            SyncEngine(g.device, HybridClock()),
            deviceName,
            records = Records(),
            renew = ::renew,
            adminCA = { key -> synchronized(lock) { state?.computerAdminCA(key) } },
            // A copy of a moment ago from another device; an older one, as a
            // hello brings it on connecting, would overwrite what the phone
            // copied since.
            onChange = { e ->
                if (!e.isMark && e.text.isNotEmpty() && e.origin != g.device && e.ageMS < SyncRule.RECENT_COPY_MS) onCopy?.invoke(e.text, e.kind)
            },
        )
        val b = NsdBrowser(context) { members ->
            synchronized(lock) { found = members }
            relay()
        }
        dialer = MemberDialer(n, g.tag, dial = b.dialer(member, g.memberChain, g.trusted))
        node = n
        browser = b
        b
    }

    /** Connects again, as after the user allowed the local network. */
    fun reconnect() = restartSync()

    /** Stops syncing and starts again, with a new certificate or new roots. */
    private fun restartSync() {
        val (d, b, n) = synchronized(lock) {
            Triple(dialer, browser, node).also {
                dialer = null
                browser = null
                node = null
            }
        }
        d?.stop()
        b?.stop()
        n?.closeAll()
        startSync()
    }

    /**
     * Passes what the browser finds to the dialer, only the devices that
     * are in the group's list: a removed computer is not dialed. A phone
     * that joined has no records until a computer sends them, so it dials
     * every member of the group until then; TLS still checks each against
     * the group's roots.
     */
    private fun relay() {
        val (d, members) = synchronized(lock) {
            val g = state ?: return
            val allowed = if (g.records.records.isEmpty()) null else g.devices.map { it.id }.toSet()
            dialer to (allowed?.let { a -> found.filter { it.device in a }.toSet() } ?: found)
        }
        d?.update(members)
    }

    /** The group's records for the node, which exchanges them with the computers. */
    private inner class Records : RecordStore {
        override val digest: String? get() = synchronized(lock) { state?.records?.digest }
        override val all: List<Member.Record> get() = synchronized(lock) { state?.records?.records.orEmpty() }

        /**
         * Takes in records a computer sent, and the roots they lead to: a
         * new root, after another admin phone took the group over, means
         * connecting again with it trusted.
         */
        override fun add(records: List<Member.Record>): List<Member.Record> {
            val (fresh, rooted) = synchronized(lock) {
                val g = state ?: return emptyList()
                val roots = g.roots.size
                val fresh = g.add(records)
                if (fresh.isNotEmpty()) runCatching { g.save(file) }
                fresh to (g.roots.size != roots)
            }
            if (fresh.isNotEmpty()) relay()
            if (rooted) Thread({ restartSync() }, "restart sync").start()
            return fresh
        }
    }

    /**
     * Issues a renewed member certificate with the root or admin key for a
     * peer that is due, without asking: only while the user's last
     * authentication lasts, so a computer that connects before that gets
     * its renewal on a later connection (docs/protocol.md, section 2).
     */
    private fun renew(chain: List<ByteArray>): MemberNode.Renewal? {
        val g = synchronized(lock) { state } ?: return null
        val cert = chain.firstOrNull() ?: return null
        if (!g.isAdmin || !authenticator.isFresh || !GroupCertificates.isDue(cert, g.adminCA ?: g.currentRoot, Instant.now())) return null
        val signer = Keys.load(signingAlias(g)) ?: return null
        return synchronized(lock) { state?.renewal(chain, signer, Instant.now()) }
    }

    /**
     * Renews this phone's own member certificate when it is due, which asks
     * for the screen lock, and then connects again with it.
     */
    suspend fun renewOwnCertificate() {
        val g = copyOfState() ?: return
        if (!GroupCertificates.isDue(g.memberCert, g.adminCA ?: g.currentRoot, Instant.now())) return
        val ca = runCatching { caSigner(R.string.reason_renew) }.getOrNull() ?: return
        val renewed = withContext(Dispatchers.IO) { runCatching { g.renewOwnCertificate(ca, Instant.now()) }.getOrDefault(false) }
        if (!renewed) return
        withContext(Dispatchers.IO) {
            adopt(g)
            restartSync()
        }
    }

    /**
     * The one button, by SyncRule: given what the phone's clipboard holds
     * now, sends it or returns the text to put there.
     */
    fun sync(board: String?): Pair<SyncResult, Pair<String, Member.Kind>?> {
        val (n, device) = synchronized(lock) { (node ?: throw Failure(Failure.Kind.NO_COMPUTERS)) to (state?.device ?: "") }
        val online = n.connected.isNotEmpty()
        val usable = n.usable
        return when (SyncRule.decide(board, n.current, usable, device)) {
            SyncRule.Action.FETCH -> SyncResult.FETCHED to usable
            SyncRule.Action.SEND -> {
                if (!online) throw Failure(Failure.Kind.NO_COMPUTERS)
                n.send(board!!, Member.Kind.TEXT)
                SyncResult.SENT to null
            }
            SyncRule.Action.NOTHING -> {
                if (!online) throw Failure(Failure.Kind.NO_COMPUTERS)
                SyncResult.NOTHING_NEW to null
            }
        }
    }

    /** Whether a computer is connected now. */
    val online: Boolean get() = currentNode?.connected?.isNotEmpty() == true

    /** Sends a text the user shared or selected, unless it is the group's current text already. */
    fun send(text: String): SyncResult {
        val n = currentNode ?: throw Failure(Failure.Kind.NO_COMPUTERS)
        if (n.connected.isEmpty()) throw Failure(Failure.Kind.NO_COMPUTERS)
        if (n.usable?.first == text) return SyncResult.NOTHING_NEW
        n.send(text, Member.Kind.TEXT)
        return SyncResult.SENT
    }

    /**
     * Gets each text a computer copied, as it arrives, to put on the
     * phone's clipboard; on the node's thread.
     */
    @Volatile var onCopy: ((String, Member.Kind) -> Unit)? = null

    companion object {
        /** How long admitting a device may take once it is dialed: a computer that stops answering mid-pairing fails then. */
        const val PAIRING_DEADLINE_MS = 30_000L

        /** How long the join QR code is good for, and how many wrong codes it takes, as for cbb join (docs/protocol.md, section 6). */
        const val JOIN_WINDOW_MS = 300_000L
        const val JOIN_ATTEMPTS = 3

        fun defaultFile(context: Context) = File(context.filesDir, "clipboardbridge/group.json")

        /**
         * Of two failures on different addresses, the one that says more: an
         * address that answered, as with a failed handshake, over one that
         * did not.
         */
        fun telling(earlier: Exception?, later: Exception): Exception {
            if (earlier == null) return later
            if (unreachable(earlier) && !unreachable(later)) return later
            return earlier
        }

        private fun unreachable(e: Exception): Boolean =
            (e is Failure && e.kind == Failure.Kind.UNREACHABLE) || e.cause is SocketException || e.cause is SocketTimeoutException

        /**
         * Runs block on Dispatchers.IO and calls close when the caller is
         * cancelled or times out, which ends the blocking read in block.
         */
        suspend fun <T> closingOnCancel(close: () -> Unit, block: () -> T): T = coroutineScope {
            val done = AtomicBoolean(false)
            val watch = launch {
                try {
                    awaitCancellation()
                } finally {
                    if (!done.get()) close()
                }
            }
            try {
                withContext(Dispatchers.IO) { block() }
            } finally {
                done.set(true)
                watch.cancel()
            }
        }
    }
}
