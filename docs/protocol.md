<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# clipbridge protocol

This document specifies protocol version 1 of clipbridge as the Go code in this repository
implements it, so that another implementation (an iPhone or Android app, a Rust lite member)
can interoperate with it. The Go code is the source of truth; where [design.md](design.md)
says something different, a "Note:" line says so. [design.md](design.md) explains why the
protocol is the way it is; this document only says what it is.

Conventions: "MUST" marks what a peer has to do to interoperate. Byte strings in JSON are
standard base64 with padding (Go's encoding of `[]byte`). Durations on the wire are integer
milliseconds unless a field says otherwise. Local durations (ages, windows, timeouts) are
measured on a clock that counts the time the machine sleeps and does not jump when the wall
clock is set (`CLOCK_BOOTTIME` on Linux, `CLOCK_MONOTONIC` on macOS; package `uptime`).

## 1. Identifiers, names and ports

| Item | Value | Source |
|------|-------|--------|
| Device ID | 128 random bits as exactly 32 lowercase hex characters (`[0-9a-f]{32}`) | `internal/group/cert.go` |
| Event ID | same format as a device ID, random per event | `internal/clip/clip.go` |
| Phone ID | 16 random bytes, shown as 32 lowercase hex characters; embedded in the token | `internal/phone/token.go` |
| Group tag | first 8 bytes of SHA-256 over the group CA certificate (DER), as 16 lowercase hex characters | `group.Tag` |
| Member host name | `cb-<device ID>.local` (mDNS host name and the only DNS name in the member certificate) | `DeviceID.HostName` |
| Service instance | `<device ID>._clipbridge._tcp.local` | `internal/mdns/zone.go` |
| Shared iPhone name | `clipbridge.local` | `group.PhoneName` |
| Member port | TCP 8764 when free, otherwise one the OS chooses, all addresses; published in the SRV record. Linux members only | `internal/service/service.go` |
| iPhone port | TCP 8765, HTTPS, all addresses. Linux members only | `internal/service/iphone.go` |
| Profile port | TCP 8766, plain HTTP, only while an iPhone pairing window is open | `internal/service/iphone.go` |
| mDNS | UDP 5353, groups 224.0.0.251 and ff02::fb | `internal/mdns/mdns.go` |
| Member ALPN | `clipbridge/1` | `group.MemberProtocol` |
| Pairing ALPN | `clipbridge-pair/1` | `pair.Protocol` |
| Pairing code | six ASCII digits; users may type spaces and dashes, which are removed | `pair.NormalizeCode` |
| Join QR text | `clipbridge://join?code=` followed by the six-digit code; unknown query fields are ignored | `phone.JoinQR`, `phone.ParseJoinQR` |

Device IDs, event IDs and group tags compare as byte strings. Accepting peers: the member
port and the iPhone port accept TCP connections only from addresses that mDNS would publish
(private IPv4, unique-local IPv6, link-local IPv6) or loopback; others are closed (member
port) or get HTTP 403 (iPhone port). At most 32 connections to the member port may be in
their TLS handshake or in a pairing attempt at once; more are closed at accept.

## 2. Certificates

All keys are ECDSA P-256; all signatures are ECDSA with SHA-256 (Go's default for P-256).
Serial numbers are random. Go also adds subject and authority key identifiers; peers do not
rely on them. Source: `internal/group/cert.go`, `internal/group/tls.go`, `internal/pair/join.go`.

| Certificate | Subject CN | SAN | Validity | Extensions |
|-------------|-----------|-----|----------|------------|
| Group CA | `clipbridge group CA YYYY-MM-DD` (UTC creation date) | none | NotBefore = creation - 24 h; NotAfter = creation + 20 years | CA, path length 0 (MaxPathLen 0); key usage certSign, cRLSign |
| iPhone CA | `clipbridge iPhone CA YYYY-MM-DD` | none | as the group CA | as the group CA, plus critical name constraints (below) |
| Member certificate (from the group CA) | the device ID | DNS `cb-<device ID>.local`, exactly one | NotBefore = the group CA's NotBefore; NotAfter = min(issue + 2 years, CA NotAfter) | key usage digitalSignature; EKU serverAuth and clientAuth; not a CA |
| `clipbridge.local` server certificate (from the iPhone CA) | `clipbridge.local` | DNS `clipbridge.local` | NotBefore = max(issue - 24 h, CA NotBefore); NotAfter = min(NotBefore + 397 days, CA NotAfter) | key usage digitalSignature; EKU serverAuth; not a CA |
| Joiner's self-signed certificate (pairing only) | the joiner's new device ID | none | 1970-01-01T00:00:00Z to 9999-12-31T23:59:59Z | none set |

iPhone CA name constraints, marked critical: permitted DNS domains `clipbridge.local` (the
name and names below it); permitted e-mail and URI domains `clipbridge.invalid` (a domain
that never exists, so no such name is valid); excluded IP ranges `0.0.0.0/0` and `::/0`.

A device has one key. The member certificate and, on a Linux member, the `clipbridge.local`
certificate certify the same key. A CA refuses to issue when the local clock is outside its
own validity. A Linux member holds both CA keys; a Mac holds neither and has no
`clipbridge.local` certificate. The joiner's certificate carries the key that the member
certifies in the welcome (section 6).

Checking a member certificate (`checkPeer`, `DeviceOf`): the chain MUST verify to the group
CA at the time max(now, group CA NotBefore), so a device whose clock is behind still accepts
it, while an expired certificate is rejected. The subject CN MUST be a device ID, and the
certificate MUST carry exactly one DNS name, `cb-<that ID>.local`.

Renewal rules (`Identity.Renew`): a member certificate is renewed when less than 240 days
remain, a `clipbridge.local` certificate when less than 60 days remain or when its NotBefore
is in the future; neither is renewed when it already ends with its CA.

When renewal runs: a member that holds the CA keys checks its own certificates when the group
starts and every 12 hours, saves renewed ones and presents them on new connections at once
(running connections keep theirs). It renews the certificates of other members too: when a
peer's hello arrives, and every 12 hours for the running connections, it checks the
certificate the peer presented in the handshake and, when it is due, sends a `cert` message
(section 4) with a new certificate for the same device ID and key, at most once per
connection. A member without the CA keys keeps a certificate from a `cert` message only when
it verifies to the group CA, names its own device ID and key, has client and server use and
ends later than its current one; otherwise it logs and ignores it. A certificate that has
already expired cannot be renewed this way, since the handshake fails; the device pairs again.

Fingerprint (shown to the user): SHA-256 over the certificate DER as upper-case hex bytes
separated by spaces; the short form is the first 8 bytes (23 characters).

## 3. Discovery (mDNS)

Linux members publish and browse; Macs and joining devices only browse. RFC 6762 and
RFC 6763 apply where this section is silent. Source: `internal/mdns`.

### Records a Linux member publishes

| Name | Type | Data | TTL | Cache-flush |
|------|------|------|-----|-------------|
| `_clipbridge._tcp.local` | PTR | `<id>._clipbridge._tcp.local` | 4500 s | no (shared) |
| `<id>._clipbridge._tcp.local` | SRV | priority 0, weight 0, member port, target `cb-<id>.local` | 120 s | yes |
| `<id>._clipbridge._tcp.local` | TXT | see below | 4500 s | yes |
| `cb-<id>.local` | A / AAAA | the addresses of the interface | 120 s | yes |
| `cb-<id>.local` | NSEC | see below | 120 s | yes |
| `clipbridge.local` (holder only) | A / AAAA | the addresses of the interface | 10 s | yes |
| `clipbridge.local` (holder only) | NSEC | see below | 10 s | yes |
| `_services._dns-sd._udp.local` | PTR | `_clipbridge._tcp.local` | 4500 s | no; only in answers, never announced |

TXT strings (each at most 255 bytes):

| Key | Value | Meaning |
|-----|-------|---------|
| `v` | `1` | protocol version |
| `g` | group tag | members of another group, or of a replaced CA, are ignored |
| `p` | `1` | present only while a computer pairing window is open |

The Go code publishes them in the order `v=1`, `g=<tag>`, `p=1`. Keys are matched without
regard to case; the value is what follows the first `=`.

Note: browsers check only `g` (when dialing) and `p` (when joining); nothing checks `v`
(`internal/service/members.go:99`, `internal/service/socket.go:502`).

NSEC (RFC 6762 section 6.1): owner the host name; RDATA is the host name itself in
uncompressed wire format, then window 0 with a bitmap that has bit A (type 1, byte 0 mask
0x40) and/or AAAA (type 28, byte 3 mask 0x08), trimmed of trailing zero bytes.

Addresses: only private IPv4, unique-local IPv6 and link-local IPv6 addresses are published,
and each answer carries the addresses of the interface the query arrived on. Interfaces that
are down, cannot multicast, are loopback or point-to-point are not used; the list is
rescanned every 10 s.

### Responding

- Only packets whose source is on the link (inside a prefix of the receiving interface, or an
  IPv6 link-local address) are processed. Only PTR, SRV, TXT, A and AAAA records are read;
  a record that does not decode, such as an instance name with a dot in a label, is skipped
  alone. At most 32 questions of a query are answered.
- A PTR question for `_clipbridge._tcp.local` gets the PTR as answer and SRV, TXT, A/AAAA
  and NSEC of the host as additionals. A question for the instance gets SRV (with the host
  addresses as additionals) and/or TXT. A question for the host name, or for
  `clipbridge.local` on the holder, gets its A or AAAA records, or the NSEC record when the
  name has no address of the asked type. Type ANY gets everything that matches.
- Known-answer suppression: a record listed in the query with at least half of its TTL is
  left out. A record already multicast on the interface within the last second is left out.
- A multicast answer that contains a shared record (a PTR) is delayed 20 to 119 ms; other
  answers go at once, to the group of the query's address family.
- A legacy unicast query (source port not 5353) gets a unicast answer that repeats the ID and
  the questions, TTLs capped at 10 s, no cache-flush bits, at most 5 answers a second per
  source. An answer over 9000 bytes drops its additionals.
- Names are never probed.

### Announcements and goodbyes

- All records are announced twice, one second apart, at start, on a new interface or new
  addresses, after a TXT change and when the member becomes the holder.
- Addresses that go away get a goodbye (TTL 0) for the host name and, on the holder, for
  `clipbridge.local`.
- Giving up `clipbridge.local` sends a goodbye for its A/AAAA and NSEC records.
- On stop, every record gets a goodbye. Goodbyes never carry the cache-flush bit, so they end
  only their own record. A service that stops sends its mDNS goodbyes before the member
  goodbyes (section 4).

### Browsing

- Query PTR `_clipbridge._tcp.local` at start, then after 1 s, doubling up to one hour,
  listing the PTR records known with more than half their TTL as known answers.
- Each cached record of a found member (its PTR, SRV, TXT and host addresses) is queried
  again at 80, 85, 90 and 95 percent of its lifetime, plus 0 to 2 percent at random.
- Received records are kept only if relevant: PTR of the service, SRV/TXT of an instance
  whose first label is a device ID, A/AAAA of `cb-<device ID>.local`. Their TTL is capped at
  what clipbridge itself uses (4500 s for PTR and TXT, 120 s otherwise). A goodbye expires the
  record after 1 s; a cache-flush record expires older records of its name and type after
  1 s.
- A member is found when a live PTR names an instance that has a live SRV; its addresses
  are the live A/AAAA records of the SRV target that would be published. TXT is optional.

### The holder of `clipbridge.local`

Election (`electLocked`, `internal/service/members.go`): a Linux member holds
`clipbridge.local` when no connected peer that has sent its hello has role `linux` and a
lower device ID. A member alone holds it at once. Macs never hold it, nor do Linux members
without the CA keys. A group's Linux members either all hold the keys (its root is a Linux
member) or none do (its root is the phone), so the rule needs to know no more about peers. The election runs
whenever the set of connected peers changes, so a holder that leaves with a goodbye is
replaced at once and one that falls silent after the 15-second timeout. Two holders for a
moment are harmless.

## 4. Member protocol

Source: `internal/node`, `internal/clip`, `internal/group/tls.go`,
`internal/service/members.go`.

### Who dials whom

- A Linux member dials every found member whose device ID is greater than its own and whose
  `g` matches its group tag; the other side accepts. A Mac dials every found Linux member
  with a matching `g`. Macs accept nothing, and Macs never connect to each other.
- Addresses come from discovery, never from resolving a `.local` name. They are tried IPv4
  first, then routable IPv6, then link-local IPv6. After a round of failures the dialer waits
  1 s, doubling to 30 s; a connection that lasted more than 30 s resets the wait.
- TCP keepalive is off; the protocol has its own heartbeat.

### TLS

- TLS 1.3 only, ALPN `clipbridge/1` on both sides. Both sides present their member
  certificate (leaf only).
- Server: requires and verifies a client certificate from the group CA; session tickets off.
- Client: verifies the server against the group CA with server name `cb-<peer ID>.local`,
  where the peer ID is the one found in discovery, and MUST check that the certificate names
  exactly that device.
- Both sides check the peer as in section 2, and that the negotiated version is TLS 1.3 and
  the ALPN protocol is `clipbridge/1`. A connection to one's own device ID is closed.
- The handshake must finish within 10 s.
- The member port serves both ALPN protocols: a ClientHello that offers `clipbridge-pair/1`
  gets the pairing configuration (section 6), whether or not a window is open.

### Framing

Each frame is a 4-byte big-endian length followed by that many bytes of a JSON object (UTF-8,
no trailing newline). A frame MUST NOT exceed 7 MiB (7 340 032 bytes); a larger length closes
the connection. The Go code writes JSON without HTML escaping; receivers MUST accept any valid
JSON.

Message object:

| Field | Type | In | Meaning |
|-------|------|----|---------|
| `t` | string | all | `hello`, `event`, `ping`, `bye`, `cert` or `records` |
| `role` | string | hello | `linux`, `mac`, `phone` (a phone app) or `lite` (a lite member) |
| `hello` | object | hello | Hello (below) |
| `event` | object | event | Event (below) |
| `cert` | string | cert | a renewed member certificate for the receiver, DER in base64 (section 2) |
| `records` | array | records | signed records (section 10) |

```json
{"t":"hello","role":"linux","hello":{"wall_ms":1761024000000,"current":{"id":"9f0c...","origin":"3b1e...","time":"1761023990000.0","age_ms":10000,"kind":"text","text":"hello"}}}
{"t":"event","event":{"id":"77aa...","origin":"3b1e...","via":"iphone","time":"1761024001234.2","age_ms":15,"kind":"secret","text":"hunter2"}}
{"t":"ping"}
{"t":"bye"}
{"t":"cert","cert":"MIIB..."}
```

### Message order

1. After the TLS handshake each side sends its hello first, without waiting for the other's.
2. Then events follow, in any number, interleaved with pings, records messages and at most
   one `cert`.
3. A side that has written nothing for 5 s sends `ping`. Every frame written resets that
   timer.
4. A side that stops (service stop, Rejoin) sends what is queued and then `bye`, within one
   second, and closes the socket. Receiving `bye` ends the connection without an error.

Rules for the receiver:

- The first frame MUST be a hello with one of the four roles; otherwise the connection is
  closed. A hello whose `hello` object does not decode closes the connection. A `current`
  that does not decode (for example an unknown `kind` or `via` from a newer version) counts
  as no current event. A `current` that decodes but fails validation, or that is a secret
  with its text, closes the connection (`internal/node/node.go:575`).
  Note: design.md (lines 207-209) mentions only the case that does not decode.
- An `event` that does not decode or fails validation is dropped; the connection stays.
- Unknown `t` values and `ping` are ignored.
- Timeouts: each frame must start arriving within 15 s of the previous one; once its length
  is known, the frame gets 15 s plus 1 s per full 16 KiB (16 384 bytes). Writes have the same
  allowance. A connection silent for 15 s is closed.
- A new connection from a device replaces its old one, which is closed without a goodbye.
- A peer whose outgoing queue (256 messages) is full is disconnected; it gets the current
  event again in the next hello.

Roles: a `phone` or `lite` member dials Linux members as a Mac does, publishes nothing and is
never dialed; the Linux members treat it as a Mac (it never holds `clipbridge.local`).

### Hello

| Field | Type | Meaning |
|-------|------|---------|
| `wall_ms` | integer | the sender's wall clock, milliseconds since the Unix epoch; for skew reports only (`clipbridge status` shows `skew_ms`); 0 or absent means unknown |
| `current` | Event or absent | the sender's current event with its age as of sending; for a secret only its mark (text `""`), whatever its age; absent when there is none |
| `records` | string or absent | the digest of the sender's records (section 10) |
| `name` | string or absent | the sender's device name, 1-64 bytes; a receiver ignores an invalid one |

### Event

| Field | Type | Meaning |
|-------|------|---------|
| `id` | string | event ID, 32 lowercase hex characters |
| `origin` | string | device ID of the member that made the event |
| `via` | string | `copy` (copied on that member), `iphone` (the iPhone button) or `universal-clipboard` (reached a Mac through Universal Clipboard). Omitted for `copy`; absent means `copy` |
| `time` | string | hybrid timestamp `"<wall>.<logical>"` (section 5) |
| `age_ms` | integer | milliseconds since the copy, as of the moment the frame is written |
| `kind` | string | `text` or `secret`; always present |
| `text` | string | the text; `""` only in the mark of a secret |

Validation (`Event.Validate`): `id` and `origin` are 32 lowercase hex characters; `time` is
not `0.0` and its wall time is at most 253402300799999; `kind` and `via` are known;
`age_ms` is not negative; and, unless the event is a mark (kind `secret` with empty text),
`text` is non-empty, at most 1 MiB (1 048 576 bytes) and valid UTF-8. Unknown fields are
ignored.

Ages: a sender adds the time an event waited in its outgoing queue to `age_ms` (saturating at
the largest int64). A receiver caps `age_ms` at 365 days and turns it into a local time:
copied at = now - age. The hybrid clock is never used for durations.

## 5. Sync semantics

The parts marked "wire" are needed for convergence; the rest is the Go engine's local policy,
which another full member should copy so that users see the same behaviour. Source:
`internal/clip/clip.go`, `internal/hlc/hlc.go`, `internal/node/node.go`.

### Hybrid logical clock (wire)

A timestamp is `(wall, logical)`: `wall` is milliseconds since the Unix epoch, 0 to
253402300799999 (the last millisecond of 9999); `logical` is a uint32. Text form: the two
numbers in decimal separated by a dot, with no sign or spaces, for example
`1761024000000.3`. Order: by `wall`, then by `logical`. The zero timestamp sorts first and is
invalid in an event. No timestamp is ever refused for being ahead of the local clock.

- `Now()` for a local event: `pt = min(wall clock in ms, MaxWall)`. If `pt > last.wall`, then
  `last = (pt, 0)`; otherwise `logical` is incremented (if it is at its maximum, `last =
  (wall + 1, 0)`, stopping at MaxWall).
- `Observe(r)` for a received event, done only the first time its ID is seen:
  `w = max(last.wall, r.wall, pt)`; if `w` equals both `last.wall` and `r.wall`, `logical =
  max(last.logical, r.logical) + 1`; else if `w == last.wall`, `logical + 1`; else if
  `w == r.wall`, `last = r` then `logical + 1`; else `last = (w, 0)`.
- Persistence: before the clock reaches the last saved mark, the service saves a new mark
  10 000 ms ahead (file `hlc.mark` in the state directory, text form) and uses it as the
  floor after a restart, so it never issues a timestamp below one it issued before.

### Ordering and the current event (wire)

Event E is later than F when `E.time > F.time`, or the times are equal and `E.id > F.id`
compared as strings. The group's current event is the latest event a member has seen; every
member converges on the same one (last writer wins).

### Forwarding and reconciliation (wire)

A member remembers the last 4096 event IDs. For each received event (from an `event` frame,
or the `current` of a hello), after validation:

1. If its ID was seen before: if it is the current event, the current event is a mark and the
   received one has the text, the text is taken (and forwarded); otherwise nothing happens
   (except the rejoin case below).
2. Otherwise: observe its timestamp, record the ID, and forward it to every other connection
   (also when it is older than the current event, and also a mark). If it is later than the
   current event, it becomes the current event.

A member sends its current event in every hello, so a newly connected pair converges at
once. A local event is sent to all connections; a mark (from a hello) travels in `event`
frames like any other event.

### Local events

- A new event gets a random ID, `origin` = own device ID, `time = Now()`, `age_ms` 0 at
  creation, and becomes the current event and the member's own clipboard text.
- Reported copies (a clipboard watcher, `copied`) make no event when: the member's own
  clipboard already holds that text; the text was written to the local clipboard within the
  last 10 s (echo; the last 8 written texts are remembered); `via` is
  `universal-clipboard` and the text equals the live current event (a Mac receiving the
  group's own text back); or the text is a remembered secret reported as `text` (a clipboard
  manager restoring it), which also clears the known local text.
- Deliberate actions (`copy` on the control socket, the iPhone button) always make an event;
  a text remembered as a secret is sent as a secret. The text is also written to the
  member's own clipboard unless it already holds it.

### Writing the member's own clipboard (local policy)

When an event becomes current (or a mark gets its text) it is written to the local clipboard
when all of these hold: the current event is live (it has a text, and a secret is younger
than the secret TTL); the local clipboard does not already hold the text; and either it was
copied at most 60 s ago (live window), or the member is within 30 s of its last Rejoin
(rejoin window) and made no copy of its own before it was back in sync. A write increments
the write sequence number (section 8).

- Rejoin: on service start, and when the machine slept (the clock that counts sleep moved
  more than 3 s further than the one that does not, checked every 2 s), the member closes all
  connections, waits up to 2 s for them to end, and then records the Rejoin; connections that
  start meanwhile wait. "Back in sync" means a hello was reconciled while at least one
  connection is up. A copy made while not in sync, or with no peers, is an offline copy; it
  blocks rejoin-window writes until the member is in sync and the window has closed.
- A current event that a hello brought before the member noticed it had slept is written
  when the same event arrives again inside the rejoin window while not yet in sync.
- Losing all peers without a sleep or restart does not open the rejoin window: such a member
  takes the group's text again only if it is live.

### Secrets (wire and local)

- Secret TTL: a secret event is usable for 60 s after the copy, judged by its age. After that
  it is neither the member's usable current text nor returned to the iPhone, but it stays the
  current event for ordering.
- Marks (wire): a hello carries a secret only as its mark: the event with `text` `""`. A hello
  that carries a secret's text closes the connection. Full secret events travel in `event`
  frames.
- Secret memory (local): each member remembers keyed hashes (HMAC-SHA-256 with a random
  per-process key, memory only) of secret texts it sent, received or was told about by a
  watcher, up to 4096 entries for 12 hours. Such a text reported again as `text` makes no
  event; sent deliberately, it becomes a secret again.

## 6. Pairing a computer

Source: `internal/pair`, `internal/third_party/cpace`, `internal/service/socket.go`.

### Window

A Linux member that holds the CA keys opens a window with a six-digit code. While it is open
the member publishes `p=1`. The window lives 5 minutes (counting sleep); an attempt that has
started may finish after that. One attempt at a time; another gets `busy`. The window closes
after a success or after the third failed attempt (`too-many`). An attempt fails (counts)
when it fails after the member sent its CPace message; errors before that (bad AD, bad
certificate, a dropped connection) do not count. Each attempt has 30 s on both sides.

### TLS

- Joiner (client): TLS 1.3, ALPN `clipbridge-pair/1`, presents its self-signed certificate
  (section 2) for the P-256 key it will keep, with its new device ID as CN; it does not
  verify the server's certificate during the handshake.
- Member (server): TLS 1.3, ALPN `clipbridge-pair/1`, presents its member certificate (leaf
  only), requires any client certificate, session tickets off. It rejects the connection
  unless the client sent exactly one certificate with a P-256 key and a device ID as CN that
  differs from its own.

### Channel binding and CPace

Suite CPACE-X25519-SHA512 of draft-irtf-cfrg-cpace-21, as implemented in
`internal/third_party/cpace`, with explicit key confirmation.

| Input | Value |
|-------|-------|
| Roles | joiner = initiator, member = responder |
| PRS (password) | the six ASCII digits of the code |
| CI (channel identifier) | `"clipbridge pair v1"` + one zero byte + SHA-256(member certificate DER) + SHA-256(joiner certificate DER); 19 + 32 + 32 = 83 bytes |
| sid | 32 bytes of TLS exporter output, label `EXPERIMENTAL-clipbridge-pair-v1`, empty context |
| ADa (joiner) | JSON `{"name":"<device name>","os":"linux"\|"darwin"}` |
| ADb (member) | JSON `{"device":"<member device ID>","group":"<group tag>"}` |
| Ya, Yb | 32-byte X25519 u-coordinates |
| Tags Ta, Tb | HMAC-SHA-512, 64 bytes |

The AD bytes are used exactly as they travel in the `ad` field. The member checks ADa: `os`
is `linux` or `darwin`; `name` is 1 to 64 bytes of printable UTF-8.

### Frames

Frames are a 4-byte big-endian length and a JSON object of at most 64 KiB (65 536 bytes).
Fields, all optional, each frame using some: `msg` (bytes), `ad` (bytes), `tag` (bytes),
`welcome` (object), `error` (string), `ok` (bool).

| # | Direction | Frame |
|---|-----------|-------|
| 1 | joiner to member | `{"msg": Ya, "ad": ADa}` |
| 2 | member to joiner | `{"msg": Yb, "ad": ADb}`, or `{"error": code}` |
| 3 | joiner to member | `{"tag": Ta}` |
| 4 | member to joiner | `{"tag": Tb, "welcome": Welcome}`, or `{"error": code}` |
| 5 | joiner to member | `{"ok": true}`, or `{"error": "refused"}` |

- The member always reads frame 1 before it answers, also when it refuses at once (no window:
  `closed`; busy; expired; too many).
- The member sends frame 2 before it processes Ya. If processing Ya fails, or Ta does not
  verify (`wrong-code`), it sends `{"error": code}` instead of frame 4.
- The joiner checks Tb and that a welcome is present. Once it has sent frame 3 the code is
  spent: a joiner that fails after that MUST NOT try the same code at another address.
- Sending frame 4 is the point of no return: the window records the device and closes,
  whether or not frame 5 arrives. Frame 5 only reports whether the joiner stored its
  identity.

Error codes: `wrong-code`, `closed`, `busy`, `expired`, `too-many`, `refused`. An unknown
code is treated as `refused`. Errors carry no free text, so an unauthenticated peer cannot
put words in front of the user.

### Welcome

| Field | Type | Present |
|-------|------|---------|
| `cert` | bytes, DER | always: a member certificate from the group CA for the key of the joiner's TLS certificate and its device ID |
| `group_ca` | bytes, DER | always |
| `group_ca_key` | bytes, PKCS #8 DER | only when ADa `os` is `linux`, and not in a group whose root is the phone |
| `phone_ca` | bytes, DER | likewise |
| `phone_ca_key` | bytes, PKCS #8 DER | likewise |

The joiner checks: the tag of `group_ca` equals ADb `group`; the member's TLS certificate is
signed by `group_ca` and names ADb `device` (section 2); the three CA fields are all present
or all absent, and a `darwin` joiner refuses them; when present, the keys are P-256 and
match. A Linux joiner that got them then issues its own `clipbridge.local` certificate from
the iPhone CA; one that did not is a member without CA keys, as in a group whose root is the
phone (section 9): it publishes and listens, but admits nobody, serves no iPhone and never
holds `clipbridge.local`.

Note: design.md (lines 100-103) says the new member also receives the group state and, on
Linux, the token hashes; the Welcome has neither (`internal/pair/pair.go:181`). Tokens need no
hashes (section 7), and the group state arrives in the first hello.

### Joining side behaviour

Without an address the joiner browses up to 10 s for a member with `p=1`, refuses when more
than one announces a window, and tries that member's addresses in order, at most three,
stopping after the first attempt whose code was spent. A whole join is bounded by 2 minutes
plus the browse time.

### The joiner listens (for the phone)

`clipbridge join` without `-code` turns the direction round, so that the device that scans
the QR code dials the computer, and nothing is announced:

- The joiner listens on TCP 8767 when free, otherwise on a port the OS chooses (all
  addresses; only home network addresses may connect, as on the member port) for up to
  5 minutes, and shows the QR code
  `clipbridge://join?code=<code>&addr=<host:port>&fp=<fingerprint>` (section 7): its
  addresses that mDNS would publish, IPv4 first, without link-local ones, at most four; and
  the fingerprint of its self-signed certificate, SHA-256 over the DER in base64url without
  padding.
- The member dials and is the TLS client. It presents its member certificate and MUST
  check that the server sent exactly one certificate whose fingerprint is `fp`, with a
  P-256 key and a device ID as CN. The joiner (server) requires any client certificate and
  checks it as in the other direction, through the exchange and the Welcome.
- The CPace inputs, roles and the Welcome are those above. The member, which dialed,
  confirms first:

| # | Direction | Frame |
|---|-----------|-------|
| 1 | joiner to member | `{"msg": Ya, "ad": ADa}` |
| 2 | member to joiner | `{"msg": Yb, "ad": ADb, "tag": Tb}` |
| 3 | joiner to member | `{"tag": Ta}`, or `{"error": "wrong-code"}` when Tb does not verify |
| 4 | member to joiner | `{"welcome": Welcome}`, or `{"error": code}` |
| 5 | joiner to member | `{"ok": true}`, or `{"error": "refused"}` |

- A device that does not know the code gets the joiner's refusal and nothing to test
  guesses with, so a failed attempt never spends the code: the joiner takes further
  attempts, one at a time, and gives up after the third wrong code or the 5 minutes.
- On the member the window counts attempts as above. It is not announced (`p` stays unset)
  and takes no pairing connections on the member port, so the code is good only against the
  computer whose certificate `fp` names.

## 7. iPhone endpoints

Source: `internal/phone`, `internal/service/iphone.go`.

### iPhone port 8765

HTTPS, TLS 1.3 only, no client certificate; the server presents the `clipbridge.local`
certificate followed by the iPhone CA certificate. Server timeouts: 10 s for the request
header, 30 s for reading and writing; headers at most 16 KiB. The client MUST trust only the
iPhone CA for `clipbridge.local`. Paths are exact; others get 404.

### Tokens

```
token = "cb1." base64url_nopad( phone_id[16] || HMAC-SHA-256(K, phone_id)[0:16] )
K     = HKDF-SHA-256(IKM = iPhone CA private scalar (32 bytes, big-endian),
                     salt = SHA-256(iPhone CA certificate DER),
                     info = "clipbridge iPhone token v1", length 32)
```

Every Linux member holds the iPhone CA key, so each checks any token without a stored list:
trim spaces, require the prefix `cb1.`, decode to exactly 32 bytes, compare the MAC in
constant time. A new iPhone CA ends every token. The Authorization header carries
`Bearer <token>` (scheme in any case) or the bare token.

Note: design.md (line 133) says a hash of each token is stored and spread to every Linux
member; the code derives tokens from the iPhone CA key instead (`internal/phone/token.go:21`).

### POST /sync

Request body (at most 7 MiB), with `Authorization`:

| Field | Type | Meaning |
|-------|------|---------|
| `v` | number or string | MUST be `1` |
| `text` | string | the iPhone clipboard; may be empty |
| `secret` | bool, optional | make a secret event |

Reply, always HTTP 200, `Content-Type: application/json`, `Cache-Control: no-store`:

| Field | Type | Meaning |
|-------|------|---------|
| `v` | integer | 1 |
| `direction` | string | `to_iphone`, `from_iphone`, `none`, `unpaired` or `error` |
| `copy` | string | the text for the iPhone clipboard; omitted when empty |
| `expires_in` | integer | seconds a secret copy may stay: max(1, floor((60 s - age) / 1 s)); 0 for normal text; always present |
| `message` | string | a human message for a notification; never contains a secret |

```json
{"v":1,"direction":"to_iphone","copy":"some text","expires_in":0,"message":"Copied to the iPhone"}
```

Order of checks: not POST gives `error`; a missing or unknown token gives `unpaired` (the
client MUST delete its token, so the next run pairs again); a body over 7 MiB, invalid JSON
or `v` other than 1 gives `error`. Then the direction, in order (`phone.decide`):

1. The group's current event is live, has `via` `copy`, is younger than 45 s and differs from
   `text`: `to_iphone` with that text (and its kind's expiry).
2. `text` is non-empty and differs from both the current event's text and the member's own
   clipboard text: a deliberate event with `via` `iphone` (secret if `secret` is true, or if
   the text is a remembered secret), also written to the member's own clipboard;
   `from_iphone`.
3. The member's own clipboard holds a live text that differs from `text`: `to_iphone` with it.
4. Otherwise `none`.

Note: design.md (line 286) lists the directions without `unpaired`.

The client writes `copy` to its clipboard only on `to_iphone`, for this device only (not
through Universal Clipboard).

### GET and POST /pair

Needs no token. An iPhone pairing window is opened by `pair-phone` on the control socket, on
the holder of `clipbridge.local` only; it has the limits of a computer window (5 minutes,
one success, three wrong codes; any code that is not six digits counts as wrong).

- `GET /pair`: an HTML form that posts the field `code`.
- `POST /pair` with a `Content-Type` that does not contain `json`: the form field `code`;
  the answer is an HTML page that shows the token or the error.
- `POST /pair` with a `Content-Type` that contains `json`: body (at most 4096 bytes)
  `{"v": 1, "code": "123456"}`; `v` may be a number or a string; `code` may be a string or a
  number (a number is left-padded with zeros to six digits). Reply, always HTTP 200:

| Field | Type | Meaning |
|-------|------|---------|
| `v` | integer | 1 |
| `ok` | bool | the iPhone is paired |
| `token` | string | the new token; only when `ok` |
| `message` | string | a human message |

### POST /admit

Lets a paired phone add a computer. Request body (at most 4096 bytes), with
`Authorization`: `{"v": 1, "code": "clipbridge://join?code=123456&addr=...&fp=..."}` (the
scanned QR text; unknown query fields are ignored, at most four `addr` are used). The member
opens an unannounced window with that code and dials the addresses in order, pairing with
the computer whose certificate `fp` names (section 6, "The joiner listens"). The reply has
the shape of a `/sync` reply, always HTTP 200, and comes as soon as the dialing starts:
`none`, `unpaired` for a missing or unknown token, `error` otherwise (wrong method, bad body
or version, not a join QR code, no `addr` or `fp`, a window already open).

### Profile port 8766

Plain HTTP, open only while an iPhone pairing window is open, same address restriction:

| Path | Content |
|------|---------|
| `GET /` | an HTML page with the steps and the iPhone CA fingerprint |
| `GET /clipbridge.mobileconfig` | the configuration profile, `application/x-apple-aspen-config` |
| `GET /clipbridge.shortcut` | the signed sync shortcut, `application/octet-stream` (404 if the build has none) |
| `GET /clipbridge-add.shortcut` | the signed shortcut that adds a computer (404 if none) |

The profile has the fixed identifier `io.github.hunterewok.clipbridge` with one payload of
type `com.apple.security.root` (identifier `io.github.hunterewok.clipbridge.ca`) carrying
the iPhone CA certificate. Its UUIDs are derived from SHA-256 of the CA certificate, so a new
CA's profile replaces the old one.

Note: requests from outside the home network get HTTP 403 with a text body, not a JSON
reply with status 200 (`internal/service/iphone.go:53`).

## 8. Local control socket

Source: `internal/control`, `internal/service/socket.go`, `internal/connector/connector.go`.

### Socket and permissions

| Platform | Path | Group |
|----------|------|-------|
| Linux | `/run/clipbridge/control.sock` | `clipbridge` |
| macOS | `/Library/Application Support/clipbridge/control.sock` | `_clipbridge` |

`CLIPBRIDGE_SOCKET` overrides the path for clients. The socket is a Unix stream socket with
mode 0660, made in a private temporary directory and renamed into place, so only root, the
service's user and members of the group can connect; secrets travel only to them.

### Framing

Each message is a JSON header on one line ending in `\n`, at most 64 KiB, followed by exactly
`len` bytes of raw payload (at most 1 MiB + 64 bytes), usually a clipboard text in UTF-8.
Header fields (all omitted when empty):

| Field | Type | Meaning |
|-------|------|---------|
| `op` | string | the operation |
| `kind` | string | `text` (default) or `secret` |
| `via` | string | `copy` (default), `iphone` or `universal-clipboard` |
| `seq` | integer | order of writes |
| `ttl_ms` | integer | how long a written secret may stay in the clipboard |
| `len` | integer | payload length |
| `error` | string | a failed request, human text |
| `done` | bool | the last answer to a request |
| `code` | string | pairing code |
| `fingerprint` | string | iPhone CA fingerprint |
| `address` | string | `host:port` |
| `name` | string | a device name, or a phone ID |
| `expires` | integer | seconds a window stays open; for a listening `join`, seconds to wait (at most 300) |
| `listen` | bool | `join`: listen for a member instead of dialing one |
| `addrs` | array of strings | the first answer of a listening `join`: where it listens |
| `status` | object | for `status` |
| `devices` | array | reserved |

A connection carries one request: the service reads the first message and dispatches on
`op`; an unknown `op` fails. Every answer has `op` `reply`. A failure is
`{"op":"reply","error":"...","done":true}`.

### Operations

| `op` | Request | Answers |
|------|---------|---------|
| `copy` | payload = text; `kind`, `via` | `{done}`. A deliberate action: always an event, also written to the member's own clipboard |
| `paste` | none | `{kind, done}` + payload = the member's own clipboard text; error `the clipboard is empty` when unknown or an expired secret |
| `status` | none | `{status, done}`; `status` = `{device, group, role, holder, peers: [{id, role, skew_ms}], version}` |
| `pair` | none | first `{code, expires: 300, address}` (the member port at the first private IPv4 address), then `{name: <joined device name>, done}` or an error. A Linux device in no group creates one first. Hanging up closes the window |
| `pair-phone` | none | first `{code, expires: 300, fingerprint, address}` (the profile port), then `{name: <phone ID>, done}` or an error. Only on the holder of `clipbridge.local`. Hanging up closes the window |
| `join` | `{code, address?}` or `{code, listen, expires}` | `{done}` or an error. Without `address` it browses for `p=1`. With `listen` it first answers `{addrs, fingerprint}` for the QR code, then `{done}` or an error when a member admitted it, or after `expires` seconds. Hanging up cancels |
| `watch` | `{kind, via}` + payload = what the clipboard holds now (may be empty) | `{"op":"reply"}` without `done`; then the watcher protocol below |

### Watcher protocol

A desktop connector or the Mac's pasteboard agent keeps a `watch` connection open.

- The watch request's payload is recorded as the member's own clipboard text without making
  an event. If a write was pending (decided while no watcher was connected) and is still the
  member's own text, the watcher gets that write instead.
- Watcher to service, any number, no answers:
  - `copied` (payload, `kind`, `via`): the clipboard changed; the engine decides whether it is
    an event (section 5). A watcher reports `via` `universal-clipboard` for items that came
    through Universal Clipboard.
  - `clipboard` (payload, `kind`): what the clipboard holds, without a change; used for items
    that a password manager marked (`kind` `secret`), which the engine remembers as secrets.
    The Go connector sends marked items only this way, never as `copied`.
- Service to watcher: `write` (payload, `kind`, `via`, `seq`, and for a secret `ttl_ms`).
  `seq` grows with every write the engine decides on (starting at 1 per service run); the
  service sends each write to every connected watcher, dropping the oldest queued write for
  one that falls 16 behind. A watcher MUST ignore a write whose `seq` is not greater than the
  last one it applied. `ttl_ms` is the secret's remaining lifetime (60 s minus its age, at
  least 1 ms); the Go connector uses 60 s when it is missing and gives up the clipboard when
  it expires. A watcher writes a secret with the platform's password-manager marks.
- Reports with an unknown `kind` or `via`, and other `op`s, are logged and ignored.

The `devices` and `revoke` operations are in section 10.

## 9. Planned: the phone as the root (not implemented)

This section fixes the wire changes for the phone apps ("Target architecture with the phone
apps" in [design.md](design.md)), so that the Go foundation and the apps are built to the
same plan. Nothing here is implemented yet; sections 1-8 stay valid, and groups created by
a computer keep working as they do today.

- **Group CA.** The app creates the group root CA: a P-256 key in the Secure Enclave or
  StrongBox that cannot be exported, with the certificate profile of section 2 except
  path length 1 (MaxPathLen 1), CN `clipbridge group root YYYY-MM-DD`. Below it every admin
  phone has an admin CA (section 10). Computers get member certificates only and never hold
  a CA key; only admin phones admit devices. The
  Linux side is in place: a Welcome without CA keys makes a Linux member without them
  (section 6), and such members never hold `clipbridge.local`. There is no iPhone CA in such
  a group.
- **The app is a member.** It holds a member certificate of its own group with role
  `phone` and speaks the member protocol of section 4. It always dials and never listens
  (a phone cannot accept connections in the background), so members MUST NOT dial a
  `phone` member; it publishes no mDNS records. The roles `phone` and `lite` are already
  accepted (section 4).
- **Join QR code and pairing direction.** Already implemented: `clipbridge join` listens
  and shows its addresses and certificate fingerprint, and the admitting side dials it and
  confirms first (section 6, "The joiner listens"). Today a Linux member dials, when the
  shortcut posts the QR code to `/admit`; the app will dial by itself, as the admitting
  side, and send a Welcome with a member certificate signed by the phone's CA.
- **No profile, no token.** The app trusts its own CA, so it needs no configuration
  profile, no iPhone CA and no token; it reaches members through mDNS browsing as a Mac does.
  The shortcut endpoints of section 7 stay for phones without the app.
- **Renewal and revocation.** Certificate renewal (section 2) moves to the admin phones,
  which send `cert` messages as a Linux member does today; revocation and the devices list
  are section 10, and a second admin phone is the way back when a phone is lost.

## 10. Admin CAs, device records and revocation

The wire side of "Admin phones, the devices list and revocation (planned)" in
[design.md](design.md). Implemented in Go: the records, their exchange, refusing revoked
keys, and `devices` and `revoke` in groups a computer created (`internal/group/records.go`,
`internal/node`, `internal/service/devices.go`). Planned, with the apps: admin CAs in member
chains (Go verifies records signed by one already) and `root` records.

### Admin CA and chains (planned)

| Certificate | Subject CN | Validity | Extensions |
|-------------|-----------|----------|------------|
| Group root CA (phone groups) | `clipbridge group root YYYY-MM-DD` | as the group CA | CA, path length 1; key usage certSign, cRLSign |
| Admin CA | `clipbridge admin <device ID>`, the admin phone's device ID | NotBefore = the root's NotBefore; NotAfter = the root's NotAfter | CA, path length 0; key usage certSign, cRLSign; issued by the root |

- An admin phone has two keys: its admin key (certified by the admin CA, used only to sign
  certificates and records, behind a user-presence check) and its member key (certified by
  its own admin CA, role `phone`).
- A member certificate issued by an admin CA has the profile of section 2, issuer the admin
  CA, NotBefore = the admin CA's NotBefore.
- In the member handshake (section 4) a member MUST send its certificate followed by its
  issuer when the issuer is not the group CA. Checking a peer: the chain MUST verify to the
  group CA through at most one intermediate that is a CA with path length 0, with the time
  rule of section 2; then the revocation rules below apply. A group whose CA has path length
  0 (every group a computer created) has no intermediates.

### Records

A record is a signed JSON body. On the wire and on disk it is an envelope:

| Field | Type | Meaning |
|-------|------|---------|
| `body` | bytes | the record body, JSON (below); signed as these exact bytes, never re-encoded |
| `sig` | bytes | ECDSA P-256 with SHA-256 over `body`, DER |
| `chain` | array of bytes | the signer's certificates below the group CA: empty when the group CA key signed (groups a computer created, or the root), else the admin CA certificate |

Body fields common to every record: `v` (1), `type`, `group` (the group tag), `time_ms` (the
signer's wall clock; informative only, never used for ordering), `by` (the signer's device
ID; informative). Types:

| `type` | Fields | Meaning |
|--------|--------|---------|
| `device` | `device`, `name` (1-64 bytes, as the pairing Info), `role` (`linux`, `mac`, `phone`, `lite`, `iphone` for a shortcut token), `key` (SHA-256 of the device's SubjectPublicKeyInfo; for `iphone`, of the phone ID), `admin` (SHA-256 of the admin CA's SubjectPublicKeyInfo, only for an admin phone) | a device in the group; a later `device` record for the same `device` from a valid signer updates `name` |
| `revoke` | `keys` (array of SHA-256 of SubjectPublicKeyInfos or phone IDs), `keep` (array of the same, for certificates issued by a revoked admin CA that stay valid) | removes keys from the group |
| `root` | `root` (the new group root CA certificate, DER) | hands the group from the CA it was signed under to a new root (phone groups only) |

The record ID is SHA-256 over the envelope's `body`. A member keeps every valid record it
has seen, in a file next to its identity, at most 4096 records.

Validity and evaluation, which depend only on the set of records, never on their order:

1. A record is **signed by an admin** when `group` is the member's group tag and `sig`
   verifies with the group CA key (empty `chain`) or with the key of an admin CA in
   `chain` that verifies to the group CA. Other records are dropped.
2. The **revoked set** is the union of `keys` of every `revoke` record signed by an admin,
   including records whose signer is itself revoked. So two admins that revoke each other
   are both revoked.
3. A `device` or `root` record counts only when its signer's key is not revoked; a
   `device` record also counts when every record that revoked its signer keeps the
   device's key, so the devices a removed admin admitted stay in the list.
4. A certificate is refused when its key is revoked, or when its issuer is an admin CA
   whose key is revoked and not every record that revoked that admin CA keeps the
   certificate's key.
5. A `root` record signed under the current root replaces the group CA: the member trusts
   the new root alone, keeps its records (re-signed records are not needed, since records
   are checked against the root they were signed under, which the member keeps as history),
   and expects new certificates from an admin. When two valid `root` records exist under the
   same root, the one whose new root certificate has the smaller SHA-256 wins.

The devices list is, for each device, the `device` record that counts with the largest
`time_ms` (then the largest record ID), less the revoked keys; a device is an admin when its
record names an admin CA whose key is not revoked. A Linux member that holds the CA keys is
an admin in a group a computer created. Go keeps the records in `records.json` next to the
identity (mode 0600) and refuses `root` records until the apps implement them.

### Exchange in the member protocol

- The hello object (section 4) carries `records`: SHA-256 over the sorted record IDs the
  sender holds, standard base64; absent when it holds none.
- A side that holds records and whose digest differs from the peer's sends, after the peer's
  hello, `{"t":"records","records":[envelope, ...]}` with every record it holds, split into
  messages of about 1 MiB each. A receiver adds the valid ones, saves them, and sends the
  records that were new to it to its other peers, which have sent their hello, the same way.
  Invalid records are logged and dropped; the connection stays.
- After adding a revocation a member closes every connection whose peer certificate is now
  refused (rule 4), and the TLS check refuses it from then on. A member that learns that its
  own key is revoked logs that it was removed from the group; the others refuse it.
- A Linux member that holds the group CA key records every device it admits (its name from
  the pairing Info, role `linux` or `mac`) and every iPhone it pairs (`iphone`, name
  `iPhone`, device = the phone ID), and, for groups made before the list existed, itself and
  every connected peer that has no record yet, with the name from the peer's hello (or the
  role and the first 8 characters of its ID).
- The iPhone endpoints (section 7) treat the token of a revoked iPhone as unknown.

### Control operations

| `op` | Request | Answers |
|------|---------|---------|
| `devices` | none | `{devices: [{id, name, role, admin, online, last_seen_ms, self, listed}], done}`: the listed devices, then this device and the connected peers that have no record yet (`listed` false). `last_seen_ms` is when this member last saw the device connected |
| `revoke` | `{name}`: a device ID, or a name (case-insensitive) | `{name, done}` or an error. Only on a member that holds the group CA key; a device cannot remove itself; a Linux member of a group a computer created cannot be removed yet, since it holds the CA keys (design.md, "Devices and revocation") |
