<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The website

The project's website at <https://cbb.tools>: three pages (the start page, download, and
security and privacy) in English and every language of `l10n/` (Chinese, Hindi, Spanish, Russian, Arabic, Swahili, Hebrew), built by
[`tools/site`](../tools/site/main.go) into plain HTML and CSS. It loads nothing from other
sites. Its one script is the visit counter, GoatCounter, served by the same server (the
other `<script>` elements are schema.org data for search engines). It also has error pages (`404`, `50x`) in every language, which nginx shows.

## Editing

- The pages are `templates/*.html` inside `templates/layout.html`, written in English. Every
  text a reader sees goes through `t`: `{{t "Download"}}`, or with a link or a command in it
  `{{t "Run %s on the computer." (code "sudo cbb pair")}}`.
- Each other language is `l10n/<language>.json`: every English text and its translation, and
  `@name` (the language's own name), `@lang` (its `lang` tag, when not its code) and `@dir`
  (`rtl` for Arabic and Hebrew). A new language is a new file.
- `go run ./tools/site check` fails when a language lacks a text, keeps one no page uses, or a
  translation has another number of `%s`; CI runs it. After changing an English text, change
  its key in every language, and mark the translation for review in the pull request.
- The questions of the start page are `faq` in `tools/site/build.go`, also given to search
  engines as a FAQPage; their answers are plain text, with no links.
- Write for the reader: the benefit first, short sentences, buttons that say what happens
  ("Download for Android", not "More"), and a next step at the end of every page. State only
  what is true today: no invented reviews or numbers, and what is planned says so.
- The colours are the apps' default palette from `apps/design/tokens.json`. Motion is CSS
  only, 0.2 to 0.6 s, and off under `prefers-reduced-motion`. Buttons are at least 44 px
  high.
- `static/og.png` (1200×630) is the picture links to the site show in chats and social
  networks.
- Present both kinds of group as nearly equal: with a computer at its heart (simpler, and
  said so) and phones only (fully supported).

## Previewing

```sh
go run ./tools/site build                     # writes site/out
go run ./tools/site serve -preview            # http://127.0.0.1:8780
```

`serve` picks the language as on the server, from the browser's languages; with
`-geo dbip-country-lite-YYYY-MM.csv.gz` by country too.

## How the language is chosen

`/` is the one address that is not a file. nginx passes it to `tools/site serve`, which
redirects to `/<language>/` by, in order: the language the visitor picked in the menu (the
`lang` cookie, set only then); the visitor's country, looked up in DB-IP's free
"IP to Country Lite" database on the server, with the browser's languages deciding where a
country has several of the site's; the browser's languages; English. The address is used for
this one lookup: neither nginx nor the chooser logs it. The site credits DB-IP, as its
license (CC BY 4.0) asks.

## The server

On cbb.tools, beside the forwarder and the relay, which keep their own ports. The owner
installs and changes it; nothing here does it by itself.

1. nginx from nginx.org's repository, with its ACME module, which gets and renews the
   certificates from Let's Encrypt; Ubuntu's own packages do not carry the module yet:

   ```sh
   sudo apt install curl gnupg2 ca-certificates lsb-release ubuntu-keyring
   curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
   echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list
   sudo apt update && sudo apt install nginx nginx-module-acme
   ```

   Add `load_module modules/ngx_http_acme_module.so;` at the top of
   `/etc/nginx/nginx.conf`, copy [`deploy/nginx.conf`](deploy/nginx.conf) to
   `/etc/nginx/conf.d/cbb.tools.conf`. Its `access_log off` cancels `nginx.conf`'s access
   log, since the site promises none.
2. DNS: `cbb.tools` already points at the server; add `www.cbb.tools` (a CNAME to
   `cbb.tools`), which redirects to `cbb.tools`.
3. The firewall: TCP 80 and 443, and UDP 443 for HTTP/3 (QUIC). Without UDP 443 browsers
   use HTTP/2 or HTTP/1.1 over TCP, as old clients always do.
4. The language chooser: build it with `GOOS=linux GOARCH=amd64 go build -o cbb-site
   ./tools/site`, copy it to `/usr/local/bin/cbb-site`, copy
   [`deploy/cbb-site.service`](deploy/cbb-site.service),
   [`deploy/cbb-site-geo.service`](deploy/cbb-site-geo.service) and
   [`deploy/cbb-site-geo.timer`](deploy/cbb-site-geo.timer) to `/etc/systemd/system`, then
   `sudo systemctl daemon-reload`, `sudo systemctl start cbb-site-geo.service` (the first
   database), `sudo systemctl enable --now cbb-site.service cbb-site-geo.timer`.
5. The visit counter, [GoatCounter](https://github.com/arp242/goatcounter): download the
   `linux-amd64` binary of its latest release to `/usr/local/bin/goatcounter`, then

   ```sh
   sudo useradd --system --home-dir /var/lib/goatcounter --shell /usr/sbin/nologin goatcounter
   sudo install -d -o goatcounter -g goatcounter /var/lib/goatcounter
   sudo -u goatcounter goatcounter db create site -db sqlite+/var/lib/goatcounter/db.sqlite3 \
       -createdb -vhost localhost -user.email YOU@EXAMPLE.COM   # asks for the password
   ```

   copy [`deploy/cbb-site-stats.service`](deploy/cbb-site-stats.service) to
   `/etc/systemd/system`, `sudo systemctl daemon-reload` and `sudo systemctl enable --now
   cbb-site-stats.service`. It listens only on `127.0.0.1:8781`, and its dashboard is not on
   the internet: open it through SSH with `ssh -L 8781:127.0.0.1:8781 SERVER` and
   <http://localhost:8781>. The buttons that count presses carry
   `data-goatcounter-click`.
6. The pages: `go run ./tools/site build`, then copy `site/out/` to `/srv/cbb.tools/www/`;
   `sudo nginx -t && sudo systemctl reload nginx`.
7. Search engines: in [Google Search Console](https://search.google.com/search-console)
   add the domain property `cbb.tools` and prove it with the TXT record it gives, in the
   domain's DNS; then submit `https://cbb.tools/sitemap.xml`. [Bing Webmaster
   Tools](https://www.bing.com/webmasters) can import the site from Search Console. Neither
   puts anything on the pages.

Each change of the pages is step 6 again.

## Closed until launch

Until the project opens, every visitor sees `soon.html` ("the website opens soon", in every
language), and search engines are told not to index anything, while the owner sees the whole
site. Before reloading nginx, create `/etc/nginx/cbb-preview.conf` with a secret of your own:

```sh
SECRET=$(openssl rand -hex 16)
echo "map \$cookie_cbb_preview \$cbb_closed { default 1; \"$SECRET\" 0; }" | sudo tee /etc/nginx/cbb-preview.conf
echo "https://cbb.tools/preview?key=$SECRET"
```

Open that link once in each browser that should see the site: it sets a cookie for a year.
The secret stays on the server; anyone given the link sees the site too. `/attest/`, the
counter and `/static/` stay open. To launch, make the file
`map $cookie_cbb_preview $cbb_closed { default 0; }` and `sudo nginx -t && sudo systemctl
reload nginx`.
