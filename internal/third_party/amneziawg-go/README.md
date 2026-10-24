# amneziawg-go

The WireGuard implementation behind the tunnel (`device`, `conn`, `tun`, `ipc` and the
packages they import), copied from the module
[`github.com/amnezia-vpn/amneziawg-go`](https://github.com/amnezia-vpn/amneziawg-go)
v0.2.20-0.20260724121833-457d920a1a7d (module checksum
`h1:X/D+VZITnGJCaajBdcBTYQxcR93EcVRDjXLd/ytH/b4=`). `go.mod` at the repository root
replaces the module with this copy. Only the packages the tunnel builds on some system are
here, without their tests; `go.mod` is the module's own.

Two changes. In `device/timers.go`, a timer's function clears `timer.duration` before it
releases `modifyingLock`, not after. Upstream clears it outside the lock, so `Del`, which
writes the same field under the lock, races with a timer that fires while a peer stops; the
race detector caught it when a hub closed (`go test -race ./internal/forward`). wireguard-go
clears its flag under the lock, as this copy now does. In `conn/mark_unix.go`, `SetMark`
passes the mark's four bytes to `setsockopt` instead of converting the `uint32` to `int`,
a conversion that code scanning flags because it can wrap on 32-bit systems (clipboardbridge
sets no mark).

The code is under the MIT license in [LICENSE](LICENSE), not under the AGPL; the files keep
their original copyright notices, moved into line comments at the top, and the files that
had none got a line that points to LICENSE. clipboardbridge release archives carry this notice.

To update it, copy the same packages of a newer version over these, without `_test.go`
files, apply the change again unless upstream fixed it (then remove the copy and the
`replace`), record the version and checksum here, and run the tests.
