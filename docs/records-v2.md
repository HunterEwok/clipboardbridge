<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Group records, version 2

For engineers, anyone writing another implementation and security reviewers: the next format
of the group's authority records (`v:2`) and the one rule that evaluates them. It replaces
the records of [protocol.md](protocol.md), section 10, "Records" to "The old root's records",
and the rules for signed bodies in its Conventions. Until the release that switches to it,
the code implements section 10 as written there; this page is the specification the four
implementations are built from, and it moves into protocol.md with the switch
([roadmap](roadmap.md), item 42).

There is no migration. A member that holds records of version 1, or a group made before the
switch, refuses them and asks the user to set the group up again; until 1.0.0 the project
keeps no backward compatibility. Legacy groups (a group CA with path length 0, CA keys on
every computer) and `cbb upgrade` go with version 1.

## Why a new version

The rules of version 1 derive a signer's powers from other records (whether a root is a
computer, whether an admin CA is a phone's), undo what a removed admin signed and make the
remover list in `keep` what stays, freeze with lists of record IDs, keep the signer outside
the signed body and ignore unknown fields in it. Records carry no order, so a removal cannot
say what it saw. The rule for removed admin phones was bypassed four times in a row in the
security audit, each time through one of these properties. Version 2 removes them:

- **The signer is inside the body**, and a body has one signer.
- **Powers are written down**: the record that makes an admin lists what it may do.
- **Each signer numbers its records** (`seq`, and `prev`, the ID of its previous record), and
  every record that changes powers says how many records of each signer its author held
  (`seen`). A removal keeps what the remover saw and nothing after, so a removed admin's
  later records never count, whenever they arrive.
- **Conflicts are shown and stop the exchange** instead of being settled silently: two
  admins that remove or freeze each other without either having seen the other's record,
  two claims on the group, or one signer that signs two records with one number.
- **Handing the group over waits** (72 hours by default), every device is told, and the root
  cancels it at any time.
- **Bodies are closed and canonical**: an unknown field refuses the body, and a receiver
  checks that encoding what it read gives the bytes it received.

## Evaluation in one place

The rules are evaluated by a pure function from the record set to the group's **state**
(below, "The state"). It is written twice: in Go (`internal/group`) for the computers, and in
Rust (`cbb_core`, `lite/core`) for the lite member and, through bindings, for both phone
apps, which no longer evaluate records themselves. The vectors and the differential run
compare the whole state, not single answers.

## Canonical form of signed bodies

Every signed body (a record, a command of section 15, a server credential of section 18, a
release file of section 16) and the manifest of a media event (section 4) is JSON in one
canonical form. The rules of protocol.md's Conventions, "Signed bodies" (`form/object`,
`form/utf8`, `form/names`, `form/null`, `form/numbers`, `form/strings`, `form/depth`, the
sizes) hold, with these changes:

- `form/unknown`: a member the body's kind does not name refuses the body. A new field needs
  a new `v`.
- `form/empty`: an optional field whose value is empty (`""`, `[]`, `{}` or `false`) MUST be
  left out, and a body with such a field is refused. An integer is never empty: where its
  row allows 0, 0 is written.
- `form/canonical`: the body is exactly the bytes a receiver gets when it encodes what it
  read again:
  - no whitespace anywhere, outside strings;
  - the members of every object sorted by name, bytewise (names are ASCII, so this is
    the order of their bytes);
  - integers as `0` or `-?[1-9][0-9]*`;
  - in a string, `"` and `\` escaped as `\"` and `\\`, each character below U+0020 as
    `\u00` and two lower-case hex digits, and nothing else escaped: no `\/`, `\n` or `\t`,
    no `\u` for any other character; every other character as its UTF-8;
  - arrays in the order the field's row gives (a row that says "sorted" means sorted
    bytewise by each value's string, for a key hash or record ID its base64, or by the
    string field the row names, each value once);
  - bytes as standard base64 with padding in its one form, as before.

A receiver checks, in this order: the size; the strict form; the canonical form (it encodes
the value it parsed and compares bytes); each field against its row; then the group, the
signature and evaluation. A signer's own code runs the same checks before it signs. Go's
`checkStrict`, `cbb_core::strict` and the kits' readers of commands, credentials, release
files and manifests implement them; the vectors cite `form/canonical`, `form/empty` and
`form/unknown` as rules.

## The record

The envelope is unchanged: `{"body": bytes, "sig": bytes, "chain": [bytes]}`, with `sig` an
ECDSA P-256 signature with SHA-256 over the exact bytes of `body`, DER, and `chain` empty
when a root's own key signed, else the signer's admin CA certificate. The **record ID** is
SHA-256 over `body`.

### Fields every record has

| Field | JSON type | Values |
|-------|-----------|--------|
| `v` | integer | exactly `2` |
| `type` | string | one of the types below |
| `group` | string | the group tag (section 1) |
| `signer` | string | SHA-256 of the signing key's SubjectPublicKeyInfo, base64: a root's key, or the admin key that the admin CA in `chain` certifies |
| `seq` | integer | from 1 to 2^31-1: the signer's number for this record |
| `prev` | string | the record ID of the signer's record with `seq` - 1; absent when `seq` is 1 |
| `time_ms` | integer | the signer's wall clock, for display only; never used for ordering or for any rule |

A receiver MUST refuse an envelope whose `signer` is not the hash of the key that `sig`
verifies with: the key of the admin CA in `chain`, or, with an empty `chain`, the key of a
root the group may have (the group CA, or the new root of a claim). So one body has one
signer, and the same body under another signer is not a valid record.

A **key hash** is 32 bytes of SHA-256 in base64 (44 characters); a device ID 32 of `0`-`9`
and `a`-`f`.

### Types

| `type` | Fields | Meaning |
|--------|--------|---------|
| `device` | `device`, `name`, `role`, `os`, `key`, `admin`, `powers`, `commands`, `store`, `kind`, `proof`, `holds_root` | a device in the group, or a change of its name or powers |
| `revoke` | `keys`, `seen` | removes keys from the group |
| `freeze` | `keys`, `seen` | stops admins until the root or an admin with `thaw` ends it |
| `thaw` | `records` | ends the `freeze` records it names |
| `claim` | `root`, `seen` | an admin's claim to take the group over with a new root |
| `resolve` | `records` | the current root voids the records it names: a cancelled claim, one side of a conflict, one of two records with one number |
| `settings` | `takeover_delay_ms` | the root's settings for the group |

### Field rows

| Field | JSON type | Needed in | Values |
|-------|-----------|-----------|--------|
| `device` | string | `device` | a device ID |
| `name` | string | `device` | 1 to 64 bytes of UTF-8, no control character (U+0000 to U+001F, U+007F to U+009F) |
| `role` | string | `device` | `full`, `phone`, `lite`, `watch` or `shortcut` |
| `os` | string | none | `linux`, `windows`, `macos`, `ios`, `android`, `watchos`, `wearos` or `none` |
| `key` | string | `device` | a key hash: the member key (for a watch, its admin key; for `shortcut`, the phone ID) |
| `admin` | string | none | a key hash: the admin key its admin CA certifies; only in a record a root's own key signed |
| `powers` | array of strings | none | sorted; from `admit`, `renew`, `remove`, `remove-admins`, `freeze`, `thaw`, `takeover`, `hub`; only with `admin` |
| `commands` | array of strings | none | sorted; the command types (section 15) the admin may sign; only with `admin` |
| `store`, `kind`, `proof` | string | none | as in section 17 |
| `holds_root` | bool | none | `true`: this device holds the signer's root key; only in a record a root's own key signed |
| `keys` | array of strings | `revoke`, `freeze`, one at least | sorted key hashes |
| `seen` | array of objects | `revoke`, `freeze`, `claim`, one at least | sorted by `key`, each key once: `{"key": key hash of a signer, "seq": the highest seq of that signer the author held, 0 or more}`; `seq` here is never left out, 0 included |
| `records` | array of strings | `thaw`, `resolve`, one at least | sorted record IDs |
| `root` | string | `claim` | the new root CA certificate, DER, base64: self-signed, a CA with path length 1, a P-256 key |
| `takeover_delay_ms` | integer | none | from 0 to 604 800 000 (7 days); absent means 259 200 000 (72 hours) |

A field that a type does not list is refused in it (`form/unknown`), and so is a field
with an empty value (`form/empty`). An envelope's body is at most 8 KiB.

`seen` names every signer whose records the author held, its own included: the root's key,
every admin key, and a removed admin's key too. A record that removes or freezes an admin
MUST name that admin's key in `seen`, with `seq` 0 when it held none of its records (then
all of them stop). The apps and `cbb` fill `seen` from the records they hold right before
they sign; a signer MUST sync with a member first when it can, and MUST NOT write a `seq`
higher than it held for anyone.

### Who signs what

A **root key** is the key of the group CA or of the new root of a claim that took effect
(below). The **current root** is the last root on the path. An **admin key** is the `admin`
of a `device` record that the current root's own key signed (or an earlier root on the path,
for a record within that root's cut, below). An admin's **powers** and **commands** are
those of the newest such record (the highest `seq` of that root) that names it.

| Record | Signed by |
|--------|-----------|
| `device` naming `admin`, or with role `phone` or `watch` | a root's own key |
| other `device` | a root's own key, or an admin with `admit` |
| `revoke` of member keys and phone IDs | a root's own key, or an admin with `remove` |
| `revoke` of an admin key, or of the member key of a device whose newest root record names an admin key | a root's own key, or an admin with `remove-admins` |
| `revoke` of a root key, or of the root's own device | nobody: a root is replaced only by a claim |
| `freeze` | a root's own key, or an admin with `freeze`; each key it names is an admin key without `remove-admins` |
| `thaw` | a root's own key, or an admin with `thaw` and `remove-admins` |
| `claim` | an admin with `takeover`, under the current root |
| `resolve`, `settings` | the current root's own key |

A record whose signer may not sign it counts for nothing; so does a `revoke` or `freeze` that
names any key its signer may not remove or freeze. The powers the apps and `cbb`
write, which give the table of version 1:

| Admin | `powers` | `commands` |
|-------|----------|-----------|
| a phone | all eight | all |
| a computer | `admit`, `renew`, `remove`, `freeze`, `hub`, and `takeover` when the root is a computer | all |
| a watch | `remove`, `freeze` | `paste-off`, `actions-off`, `away-off`, `action` |

So whether an admin computer may take the group over is decided once, by the root, when it
makes the admin, not by each member from other records.

### Chains and numbers

A signer's records form a chain: the record with `seq` n names in `prev` the ID of the one
with `seq` n - 1. A record **counts** only when the member holds the whole chain below it.
A record whose chain is not complete waits (a member keeps at most 1024 records of one
signer, waiting ones included) and counts once the missing ones arrive.

**Two numbers.** Two different records of one signer with the same `seq`, or a record whose
`prev` is not the ID of the signer's record with `seq` - 1, prove that the signer's key
signed two histories: a stolen key, or a device brought back from a backup that signed again.
From the lowest such `seq` k, no record of that signer counts, on either branch, until the
current root voids one branch with `resolve` (naming the first record of that branch; the
records after it on that branch go with it). Meanwhile (see "Stopping the exchange") the
devices whose counting `device` records that signer alone signed get nothing, and the whole
group stops sending secrets. A root that signed two histories stops the group fully, and only
its own `resolve` ends it.

**Voiding.** A record that a counting `resolve` names counts for nothing. When it has a
sibling (another record of its signer with the same `seq`), the records whose `prev` chain
passes through it count for nothing too, so `resolve` ends two histories by naming the first
record of the branch that goes. Without a sibling only the named record goes, and the
signer's chain goes on through it.

### Removals and freezes keep what the author saw

A `revoke` record that a root's own key signed, or that counts, removes its `keys`. For each
removed admin key A, the records of A with `seq` up to the record's `seen` entry for A keep
counting, and none after: what the admin did before the remover saw it stays, the devices it
admitted among it, and nothing it signs later counts. Version 1's `keep` is gone.

A `freeze` that counts stops the admin keys it names in the same way while no counting
`thaw` names it: the records of a frozen admin up to the freeze's `seen` entry count, the
later ones do not, and they count again once the freeze ends. A member certificate of a
device whose newest root record names a frozen admin key is refused, as in version 1.

### Which admin records count

An admin's record may be cut by a removal or a freeze of that admin. Which records count is
decided the same way on every member, in any order, as follows.

A record a **attacks** a record b when b's signer is an admin key, a is a `revoke` or a
`freeze` whose `keys` name that admin key, a's signer may sign a (the table above), and a's
`seen` entry for b's signer is below b's `seq`: a cuts b off. A `thaw` attacks each `freeze`
it names. Records of a root's own key are never attacked; records of a root on the path
count up to that root's cut, and the current root's all count.

Every admin record is then **in** (it counts), **out** (it counts for nothing) or
**undecided**, the grounded labelling of these attacks:

1. a record whose attackers are all out is in, and so is one nobody attacks;
2. a record attacked by a record that is in, or by a root's record, is out;
3. repeat 1 and 2 until nothing changes; what is left is undecided.

A record r **happened before** a record s of another signer when s's `seen` names r's signer
with a `seq` of r's `seq` or more: s's author held r when it signed. So for two admins S and T
whose records r (S removes T) and q (T removes S) attack each
other only when neither author held the other's record:

- q happened before r (S held q when it signed r): r does not attack q, q attacks r; q is in,
  r is out. S was removed before it signed r.
- r happened before q: the same with the sides swapped.
- each held the other's (one of them lies): neither attacks; both are in, both are removed.
- they **cross** (neither held the other's): each attacks the other; both are undecided, and
  that is a **conflict**: the group stops (below) until the current root voids one of them, or
  both, with `resolve`, or removes S or T itself. Longer circles (S removes T, T removes U, U
  removes S) end the same way.

An undecided record counts for nothing, and neither do the records it would cut. To keep
the attacks free of circles that do not involve a thief, the powers are in two tiers: an admin
with `remove-admins` is never frozen, and `thaw` counts only from an admin that also has
`remove-admins` (or from a root's own key). So freezes and thaws never chase each other, and a
conflict always means two admins acted against each other without seeing it.

A thief with an admin key can always write a `seen` that pretends it did not see a removal,
and so stop the group; it cannot make its record win. A removal of an admin by another admin
is settled for good when the current root signs it again (a root's record is never
attacked), and the apps ask the root's user to confirm each such removal.

### Handing the group over

When the root is lost, an admin with `takeover` signs a `claim`: a new root CA certificate,
and `seen` with what it held, the current root's records among them. A claim:

- is **pending** from the moment a member first holds it (by its own clock, which counts
  sleep and does not jump: protocol.md, Conventions, "Time"; never the signer's clock) until
  the root's `takeover_delay_ms` (the newest counting `settings` record of the current root;
  72 hours without one) has passed on that member. Every device tells its user when a claim
  arrives, and `cbb status` and the apps show it with the time left. Sync and the admins'
  other powers go on; only the new root waits, and the claimant gets no secrets meanwhile
  ("Stopping the exchange");
- is **cancelled** for good when the current root's own key signs a `resolve` that names it,
  or a `revoke` of the claimant's admin key, at any time, before or after the delay: the
  root always wins. When that happens after the claim took effect, the new root and every
  record under it stop counting, and the group is the old root's again;
- **takes effect** when the delay has passed on that member, it is not cancelled, no other
  claim under the same root is held that is not cancelled, and the claimant is not removed,
  frozen or in a conflict. Its new root becomes the current root and starts its own `seq` at
  1; the old root's records up to the claim's `seen` entry for the old root keep counting,
  and its later ones count only to cancel the claim, as above.

**Two claims** under one root that are neither cancelled stop the group fully on every
member that holds both, at once and whatever their order or delay: no sync, no messages, no
admissions. Only the current root ends it, by cancelling one or both; a group whose root is
lost is set up again.

After a claim takes effect the new root signs `device` records for the admins it keeps
(their admin keys stay, so their `seq` goes on) and issues them admin CAs under itself, as
version 1 did; an admin CA from the old root still signs while the old root is on the path.

So a removed or stolen admin phone cannot take the group: its claim waits, the root cancels
it, a second claim stops the group instead of choosing one, and once a new root removes it,
nothing it signs counts.

### Certificates

A member certificate is taken when its chain verifies to a root on the path (section 2 and
protocol.md, section 10, "Admin CA and chains"), its key is the `key` of a counting `device`
record that is not revoked, its issuer is a root on the path or the admin CA of an admin
whose newest root record gives `admit` or `renew` (also when that admin was removed later,
for the devices whose records stay), and neither its key nor its issuer is frozen. An admin CA
is taken when it is under a root on the path and its key is an admin key that is not
revoked. The **root's own device** is the device of the newest `device` record with `holds_root` that
the current root's own key signed (the apps and `cbb` sign it right after making the group
or taking it over); a peer is the root only when its member key is that record's `key`.

## Stopping the exchange

When the records show a likely thief, the exchange stops until the root decides. The state
says how far:

| Cause | `stop` | Effect |
|-------|--------|--------|
| two claims under one root; a conflict between admins; a root that signed two histories | `full` | every member stops sync, events, media, commands and admissions with every peer; it keeps exchanging records and credentials only, so the root's decision reaches it |
| an admin that signed two histories | `secrets` | no member sends a secret event (`kind` `secret`) or a `secret` paste to anyone; the devices that admin alone admitted get nothing |
| a pending claim | none | the claimant's devices get no secrets |

A member applies it as soon as it holds the records, and lifts it as soon as it holds the
root's records that end it. `cbb status` and the apps show the cause, the devices involved and
what ends it. A user who has lost the root sets the group up again.

## The state

The function takes the group CA certificate, the record set, the current time on the
member's clock and, for each claim's record ID, the time the member first held it, and
returns the state as one canonical JSON object:

| Field | Type | Meaning |
|-------|------|---------|
| `roots` | array of strings | the path: the root certificates' key hashes from the group CA to the current root |
| `root_device` | string | the root's own device ID; absent when there is none |
| `devices` | array of objects | sorted by `device`: `device`, `name`, `role`, `os`, `keys` (sorted member key hashes that stand), and, for an admin, `admin`, `powers`, `commands`, `frozen` (true when frozen) |
| `revoked` | array of strings | sorted key hashes the records remove |
| `claims` | array of objects | sorted by `record`: `record`, `claimant` (admin key hash), `root` (new root key hash), `state` (`pending`, `effective`, `cancelled` or `competing`), `left_ms` while pending |
| `conflicts` | array of objects | sorted by the first record ID: `kind` (`admins`, `claims`, `two_histories`), `records` (sorted record IDs), `signers` (sorted key hashes) |
| `stop` | string | `none`, `secrets` or `full` |
| `no_secrets_to` | array of strings | sorted device IDs that get no secrets |
| `nothing_to` | array of strings | sorted device IDs that get nothing |

Empty fields are left out, as in signed bodies, so two implementations agree when their
states are the same bytes. The state does not depend on the order in which records arrived;
the vectors give each set in every order of its records (up to 8 records; in random orders
beyond) and check the same bytes.

## Vectors and tests

- `testdata/interop/v2-records.json`, written by Go: record sets with the expected state, at
  least the cases of the audit findings of version 1 (each with every order): an admin that
  removes another after a claim took effect (X1 and X2 of the second verification), two admin
  phones that remove each other crossed and in order, a chain of three claims, a claim
  cancelled before and after its delay, two claims, two histories of an admin and of the root,
  a removed admin's later `device` and `claim` records, freezes that cross, a `resolve` of each
  kind.
- `testdata/interop/strict-generated.json` and `strict-files.json` written again from the
  tables above, with the canonical-form and unknown-field vectors.
- An order-independence fuzz in Go: random sets over a few phones, computers and roots,
  evaluated in several orders, batch and one by one, checking the same state, no hang and an
  iteration limit.
- The differential run ([differential.md](differential.md)) compares the state bytes of Go
  and Rust, and the strict verdicts of all four, manifests included.

## What else changes with it

- **Commands** (section 15) get `v` 2, `signer` in the body as records have it, the canonical
  form, and `by` that MUST name the device whose records hold the signing key (or the root's
  device); an admin signs only the types in its `commands`.
- **Server credentials** (section 18) and **release files** (section 16) get `v` 2 and the
  canonical form; their fields stay.
- **The servers read no records.** A forwarder and a relay take only server credentials
  (section 18); the registrations with records and with `admin_sig`, and the phone hub's
  registration without one, go. A group has a period from the moment it is made, and a new
  root starts one when its claim takes effect. Both servers stay open to every group.
- **The phones** evaluate records with `cbb_core` through bindings (an xcframework and an
  AAR, as the tunnel's), and sign records in their kits as before (Secure Enclave, Keystore).
- **Legacy groups, `cbb upgrade`, `keep` and the records' `by`** go.
