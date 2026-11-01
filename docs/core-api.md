<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The core's entry point

For engineers and anyone binding the Rust core into another program: the one call through
which every program uses the core's rules (`cbb_core::api`, `lite/core/src/api.rs`). The
phone apps reach it through UniFFI (`lite/ffi`, the function `call`); Go reaches it through
cgo or wasm, in 0.6. The rules themselves are in
[records-v2.md](records-v2.md).

## Requests and answers

A request is a JSON object in UTF-8, at most 8 MiB:

```json
{"abi": 1, "op": "evaluate", "args": {...}}
```

| Field | Meaning |
|---|---|
| `abi` | the version of the request and answer shapes the caller speaks; the core answers only its own |
| `op` | the operation, from the table below |
| `args` | the operation's arguments; left out when it takes none |

The answer is canonical JSON, either `{"abi": 1, "ok": ...}` with the operation's result or

```json
{"abi": 1, "error": {"code": 10, "name": "body", "message": "...", "details": "..."}}
```

`message` is a short sentence for the user. `details` holds the causes under it, one per
line, each with its type where known; a program shows them under the message in debug mode
and always logs them ([errors](reference/errors.md)). The call never panics and answers any
bytes, also bytes that are not a request. A change an older caller would misread raises
`abi`.

The phones reach `call` through UniFFI (`lite/ffi`, `bind.sh`). The same library exports it
as C functions, declared in `lite/ffi/include/cbb_core.h`, for callers that link C: `cbb_call`
takes the request's bytes and returns the answer's, which the caller gives back with
`cbb_free`; `cbb_abi` gives the ABI.

Go reaches them in `internal/core`: through cgo under the build tag `cbbcore`, linking
`libcbb_ffi`, and on Windows, macOS and FreeBSD through the same core built as WebAssembly
(`lite/wasm`, `cbb_call` and its memory functions), run by wazero under the tag `cbbwasm`. `lite/wasm/build.sh` builds the module and writes the
`go build -overlay` file that lays it over `internal/core/cbb_core.wasm`, so no build output
lands in the source tree.

## Operations

| `op` | `args` | `ok` |
|---|---|---|
| `version` | none | `{"abi", "core", "source"}`: the ABI, the core's version and, when the build passed it in `CBB_SOURCE`, the commit |
| `evaluate` | `group_ca` (base64 DER), `group` (its tag), `now_ms` (the member's clock that counts sleep), `time_unknown` (optional, `true` when the member does not know how long it has held its claims), `first_seen` (`[{record, ms}]`, optional), `records` (`[{body, sig, chain}]`, base64) | the group's state ([records-v2.md](records-v2.md), "The state"); records that do not verify are left out, never an error |
| `evaluate_saved` | the arguments of `evaluate`, `secret` (base64, at least 16 bytes) and `saved` (base64, optional) | `{"saved", "state"}`: the new saved state, base64, and the group's state; see "The saved state" |
| `canonical_body` | a record body as an object, in any order, with `v` and `signer` set | `{"body"}`: the canonical bytes to sign, base64, after each field is checked against its row |
| `check_body` | `{"body"}`, base64 | `{"body"}` as it came, once its size, canonical form and fields check |
| `canonicalize` | `{"body"}`, base64 | `{"body"}`: the strict canonical form of a signed body of version 2 |
| `check_member` | `chain` (the peer's certificates as it sent them, leaf first, base64 DER), `trusted` (the roots the member trusts, the current root first), `usage` (`"server"` for a member this one dialed, `"client"` for one that dialed it), `now_ms` | `{"device", "used"}`: the device the leaf names and the certificates the records then judge, base64: the leaf and the admin CA that issued it, if one did, wherever the peer put it; see "Member chains" |
| `group_add` | the set's arguments (see "The record set"), `records` | `{"file", "fresh", "errors"}`: the new file, the records it did not hold before, and why it left others out (optional) |
| `group_view` | the set's arguments | `{"state", "devices", "path", "root_member", "hub_order", "digest", "claim_times", "records"}`: see "The record set" |
| `group_refused` | the set's arguments, `chain` (a chain `check_member` took, leaf first) | `{"verdict", "why"}`: `ok`, `not_listed` (the set does not name the device yet) or `refused`, with the reason for the log |
| `group_refused_admin_ca` | the set's arguments, `ca` (base64 DER) | `{"verdict", "why"}` for an admin CA, as for `group_refused` |
| `group_admin_peer` | the set's arguments, `device`, `chain` | `{"admin"}`: whether the device is the group's root or an admin, which alone may be a hub |
| `group_command` | the set's arguments, `command` (`{body, sig, chain}`), `me` (the member's device) | `{"command", "signer", "root", "sender", "verified"}`: the command's body as an object, the device that signed it, whether it signed as the root, and the device the limits count it for, `verified` when that device's own key signed; a command refused is code 15 |
| `group_claim_times` | the set's arguments, `claim_times` (`[{record, ms}]`, from a Welcome) | `{"file"}`: the times earlier than the set's own and not in the future taken |
| `group_next` | the set's arguments, `signer` (the key hash, base64) | `{"seq", "prev"}`: the seq and prev of the signer's next record; seq 1 and no prev when the set holds none of its records |

The arguments of `evaluate` are a case of `testdata/interop/v2-records.json` as it is.

`cbb version` of the lite member names the core it was built with in a second line,
`core 0.6.0, abi 1, source <commit>`; the release builds pass the tag's commit in `CBB_SOURCE`,
and other builds say `source unknown`. The full member and the apps show the same once they
call the core.

## Error codes

The numbers and names never change meaning; new codes are added at the end of their range.

| Code | Name | Meaning |
|---|---|---|
| 1 | `request` | the request is not a JSON object of the right shape, or an argument is missing or of the wrong type |
| 2 | `abi` | the request's `abi` is not the core's |
| 3 | `op` | the core has no such operation |
| 4 | `too_large` | the request is larger than 8 MiB |
| 10 | `body` | a record body is refused: its size, form or a field |
| 11 | `cert` | a certificate is refused |
| 12 | `strict` | a signed body is not in the strict canonical form |
| 13 | `rollback` | the record set is older than the saved one: a signer's whole chain ends below the seq saved |
| 14 | `saved` | the saved state cannot be read, is of another version or group, or its check with the secret does not match |
| 15 | `command` | a command is refused: its signer, its target, its time or its limits |

## Member chains

`check_member` is the check of a peer's certificates in member TLS, for a TLS stack's verify
callback (Go's `VerifyConnection`, the phones' trust evaluation): the leaf is no CA, lists the
usage in its extended key usage, names its device as its CN and its one DNS name
(`cb-<device>.local`), and is in its lifetime; a trusted root issued it, or an admin CA (path
length 0, a P-256 key, certificate signing) that a trusted root issued and that is in its own
lifetime. The clock is `now_ms` raised to the current root's start, so a member whose clock is
years behind still connects. A chain it refuses is code 11 (`cert`). Whether the records still
admit the device, and whether it is the device discovery found, are the caller's to check.
`testdata/interop/member-chains.json`, written by Go from crypto/tls's chain building, holds the
cases both give the same answer.

## The record set

The calls whose names start with `group_` work on the set of records a member keeps, which the
phones store as the records file the lite member writes (`cbb_core::group::Records`):
`{"v": 2, "records": [{body, sig, chain}], "first_seen": [{record, ms}]}`. The caller keeps the
file and passes it in each call, base64; a call that changes the set answers the new file,
which the caller saves in place of the old one. So the phones hold no rule of the group in
their own code, and every member gives the same answers for the same records.

The set's arguments, which every such call takes:

| Field | Meaning |
|---|---|
| `group_ca` | the group CA, base64 DER |
| `now_ms` | the member's clock that counts sleep |
| `file` | the records file, base64; left out for an empty set |
| `group` | optional: the group's tag where it is not the CA's own, for the vectors |

The set keeps a record that verifies under one of the group's roots and names the group, and a
record of a later version, which it passes on and never applies (records-v2.md); it keeps at
most the records records-v2.md allows. `group_view` answers:

| Field | Meaning |
|---|---|
| `state` | the group's state, as `evaluate` gives it for the records the set keeps |
| `devices` | `[{device, name, role, os, key, store, admin, admin_key, powers, commands, frozen, keys}]`: the devices list the apps show; `key` and `keys` base64 |
| `path` | the roots' certificates on the path, the group CA first, base64 DER |
| `root_member` | `{device, key}`: the device that holds the root key, when the set names one |
| `hub_order` | the devices that may be hubs, in the order members try them |
| `digest` | the set's digest, which a hello carries; left out for an empty set |
| `claim_times` | `[{record, ms}]`: when the set first held each claim, which a Welcome passes on |
| `records` | the number of records the set holds |

## Signatures already checked

The core keeps the signatures it has checked in memory, for every call of the process: an
entry is SHA-256 over `cbb sig cache v1`, the signer's key hash, the body's SHA-256 and the
signature, and only a signature that verified gets one. Evaluating the same records again
checks each signature once. It holds at most 8192 entries and starts again when full.

## The saved state

A member keeps a saved state between evaluations, so that a record set rolled back (an older
copy of the records put back on its disk or sent to it) is noticed, and so that the
signatures it checked are not checked again after a restart. The member makes a random
secret of 32 bytes once and keeps it next to its identity (in the keychain or Keystore on a
phone); it calls `evaluate_saved` with the secret and the saved state of its last call, and
saves the `saved` of the answer.

The saved state is canonical JSON:

| Field | Meaning |
|---|---|
| `v` | 1, the format's version |
| `group` | the group's tag |
| `seqs` | `[{key, seq}]`: for each of the group's signers, the highest seq whose prev chain is held whole down to seq 1 |
| `sigs` | the entries of the signatures already checked, base64 |
| `mac` | HMAC-SHA256 with the secret over `cbb saved state v1` and a newline, then the canonical JSON of the other fields |

The core refuses the call (`saved`) when the check does not match, when `v` is another
version or `group` another group, and (`rollback`) when a signer of `seqs` has no whole chain
up to that seq or above in the set: a record taken from the middle of a chain is a rollback
too. The group's signers are the group CA, the root of a claim one of the group's admins
signed, and the admins under those roots; a root that only a stranger's claim names is not
saved, so its records may come and go. A chain may also end at an anchor of one of the
group's roots' checkpoints, so that a set the checkpoint pruned is no rollback. Its entries of `sigs` are added to the signatures already
checked only after the check matched. The member shows the refusal with its details and does
not use the records; the state of the group is not saved, since it comes from the records
each time.
