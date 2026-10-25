<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Running your own servers

Clipboard Bridge needs no server at home: the hub is one of your own computers. A server on
the internet helps in two cases:

- a **forwarder**, when the internet cannot reach your hub (carrier-grade NAT), or for VLESS
  in networks that block VPNs;
- a **blind relay**, when the group has no computer that can be the hub.

Neither holds any of your group's keys or can read the clipboard. What each one sees is in
[How it works](../guide/how-it-works.md#what-each-server-can-see). Any small Linux server
with a public address will do: a virtual server with 1 CPU and 512 MB of memory is plenty.

| | Forwarder | Blind relay |
|---|---|---|
| Command | `cbb forward` | `cbb relay -group TAG` |
| Serves | any hub that registers with it | only the groups you list |
| Devices connect with | the hub's `-forwarder ADDRESS -forwarder-key KEY` | `cbb global relay ADDRESS -key KEY` on each computer |
| Ports | UDP and TCP 8764; TCP 443 with VLESS | UDP and TCP 8764 |
| AmneziaWG, VLESS | yes | not yet |
| Phones | yes | not yet (in 0.5) |

## Getting `cbb` onto the server

Run it in Docker, or as a systemd service. Do not install the full service with `get.sh`
on the same server: it would take TCP 8764 for itself.

### With Docker

The image is published with each release from 0.5. The repository's
[compose.server.yaml](../../packaging/docker/compose.server.yaml) runs a forwarder:

```sh
curl -fsSLO https://raw.githubusercontent.com/HunterEwok/clipboardbridge/main/packaging/docker/compose.server.yaml
docker compose -f compose.server.yaml up -d
docker compose -f compose.server.yaml exec forward cbb forward -show-key
```

The last command prints the forwarder's key, `sha256:...`. For a relay, change `command:`
in the file to `["relay", "-group", "TAG", "-listen", ":8764"]`. More in the
[image's README](../../packaging/docker/README.md).

### As a systemd service

Download the release for the server's CPU and put `cbb` in place:

```sh
curl -fsSLO https://github.com/HunterEwok/clipboardbridge/releases/latest/download/clipboardbridge-linux-amd64.tar.gz
tar -xzf clipboardbridge-linux-amd64.tar.gz
sudo install -m 755 clipboardbridge/cbb /usr/local/bin/cbb
```

(`-arm64` for an ARM server. Check the archive against the release's `SHA256SUMS` as in
[Installing](../guide/install.md#checking-a-download).)

Then write `/etc/systemd/system/cbb-forward.service`:

```ini
[Unit]
Description=Clipboard Bridge forwarder
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/cbb forward
DynamicUser=yes
StateDirectory=cbb-forward
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
# Only for VLESS on port 443 (see below):
#AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

and start it:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now cbb-forward
journalctl -u cbb-forward | grep key          # its key, sha256:...
```

The key file is made on the first start, in the service's own state directory
(`/var/lib/private/cbb-forward/forwarder.pem`), and the forwarder prints its key in its
log each time it starts. Keep that file: a new key means giving every hub the new one.

For a relay, name the file `cbb-relay.service`, with
`ExecStart=/usr/local/bin/cbb relay -group TAG` and `StateDirectory=cbb-relay`; its log
shows its key the same way.

### The firewall

Open the ports on the server, and in the hosting provider's firewall if it has one. With ufw:

```sh
sudo ufw allow 8764/udp comment 'Clipboard Bridge'
sudo ufw allow 8764/tcp comment 'Clipboard Bridge'
sudo ufw allow 443/tcp comment 'Clipboard Bridge VLESS'    # only with VLESS
```

## A forwarder

Once it runs, give the hub its address and key:

```sh
sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key sha256:...
```

A name works in place of the address (`vpn.example.org:8764`); the hub looks it up once.
`cbb global` on the hub shows the registration. The forwarder needs no settings per group:
each hub registers by itself with its group's certificate, and every group is kept apart
from the others.

The forwarder writes nothing about the groups, not even to its log. With `CBB_DEBUG=1` in
its environment it logs counts once a minute (hubs, sessions), never who they are.

### VLESS on the forwarder

For networks that block VPNs ([Networks that block VPNs](../guide/blocked-networks.md)),
the forwarder also takes VLESS with REALITY on TCP 443, borrowing the TLS of a well-known
site:

```ini
ExecStart=/usr/local/bin/cbb forward -vless-site www.example.com
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

(In Docker, add `"-vless-site", "www.example.com"` to `command:` and publish `443:443/tcp`.)

- The site must support TLS 1.3 and must not be blocked where your devices travel. Big
  sites people use every day are the best choice.
- The REALITY key is kept in the forwarder's key file; nothing else to configure. The hub
  asks for VLESS with `-vless` and gets the rest from the forwarder.
- `-vless-listen ADDRESS:PORT` picks another port; 443 looks the most ordinary.

## A blind relay

A relay serves only the groups you list. Find your group's tag with `cbb status` on any of
its computers, then run it on the server:

```sh
cbb relay -group 0123456789abcdef        # several groups: -group TAG1,TAG2
```

On each computer of the group, after `sudo cbb global on`, in place of a hub:

```sh
sudo cbb global relay 198.51.100.9:8764 -key sha256:...
```

The computers then meet at the relay whenever they are not on one network. Both must be
online at once, since the relay stores nothing. It speaks plain WireGuard only.

Planned for 0.5 ([roadmap](../roadmap.md), item 28): the relay in the phone apps, and the
project's relay at `cbb.tools` for groups that do not want to run their own.

## Updating

Download the new release and replace `/usr/local/bin/cbb`, then
`sudo systemctl restart cbb-forward`; or `docker compose pull && docker compose up -d`. The
key stays, so the hubs and devices need no change.
