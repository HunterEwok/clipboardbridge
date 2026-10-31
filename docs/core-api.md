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

## Operations

| `op` | `args` | `ok` |
|---|---|---|
| `version` | none | `{"abi", "core", "source"}`: the ABI, the core's version and, when the build passed it in `CBB_SOURCE`, the commit |
| `evaluate` | `group_ca` (base64 DER), `group` (its tag), `now_ms` (the member's clock that counts sleep), `first_seen` (`[{record, ms}]`, optional), `records` (`[{body, sig, chain}]`, base64) | the group's state ([records-v2.md](records-v2.md), "The state"); records that do not verify are left out, never an error |
| `canonical_body` | a record body as an object, in any order, with `v` and `signer` set | `{"body"}`: the canonical bytes to sign, base64, after each field is checked against its row |
| `check_body` | `{"body"}`, base64 | `{"body"}` as it came, once its size, canonical form and fields check |
| `canonicalize` | `{"body"}`, base64 | `{"body"}`: the strict canonical form of a signed body of version 2 |

The arguments of `evaluate` are a case of `testdata/interop/v2-records.json` as it is.

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
