# VpncBar

A native macOS menu-bar front-end for the [`vpnc`](https://en.wikipedia.org/wiki/Vpnc)
Cisco IPSec VPN client. VpncBar ships with its own copy of `vpnc`, patched to use
the kernel's native **utun** interface, so it runs on Apple Silicon and modern
macOS without the long-dead `tuntaposx` kext.

It's a small AppKit app (no Xcode project, no dependencies beyond the system
frameworks) that lives in the status bar and lets you manage profiles, store
secrets in the Keychain, and bring tunnels up and down with a click.

---

## Menu-bar interface

- Runs as a status-bar item (no Dock icon); the whole UI is its menu.
- Each VPN profile is one row showing a **✓ when connected** and the profile name.
- **Left-click a row** to connect or disconnect it.
- **Right-click (or Control-click) a row** to open its editor.
- A **Disconnect All** item appears whenever one or more tunnels are up.
- Connect/disconnect/edit actions are non-blocking; the menu stays responsive.

## Multiple simultaneous connections

- You can connect to **several VPNs at once** — each profile runs its own `vpnc`
  process with its own PID file, so tunnels are independent.
- Split-include routes from every gateway are installed side by side; the system
  **default route is never touched**, so full-tunnel profiles coexist instead of
  fighting over the default gateway.
- A safeguard prevents launching the **same profile twice**.

## Live elapsed timer

- Each connected row shows how long the tunnel has been up, right-aligned in
  **monospaced digits** so it doesn't jitter.
- The timer ticks every second while the menu is open and refreshes on a short
  background interval otherwise.

## Profile editor

A two-tab editor (window kept compact) covers everything `vpnc` needs:

**Credentials tab**
- Name, Gateway, Group name, Group secret, Username, Password.
- **VPN domains** — comma-separated match domains for scoped DNS (e.g.
  `example.com, corp.local`).
- **IKE Authmode** — `psk`, `hybrid`, or `cert`.
- **CA file** and **Client cert** paths for certificate-based auth.
- Password fields show **dots when a secret is stored** and have an **eye button**
  to reveal the value.

**Options tab**
- DH Group, PFS, NAT-T Mode, Vendor, Interface MTU, DPD timeout (default 30s),
  Debug level, and the Encryption toggles (weak/3DES, single-DES, no-encryption,
  weak auth). Dropdowns are pre-filled with their real defaults.

### Authmode-reactive fields

The Credentials tab grays out fields that don't apply to the selected IKE
Authmode, so only the relevant credentials are editable:

| Field          | psk | hybrid | cert |
|----------------|:---:|:------:|:----:|
| Group name     |  ✓  |   ✓    |  ✓   |
| Group secret   |  ✓  |   ·    |  ·   |
| Username / Password (XAUTH) | ✓ | ✓ | ✓ |
| CA file        |  ·  |   ✓    |  ✓   |
| Client cert    |  ·  |   ·    |  ✓   |

Disabled rows fade to ~20% opacity. If your `vpnc` binary was built **without**
TLS/SSL support, choosing `hybrid`/`cert` shows a note: *"This VPNC build has no
certificate support. Rebuild with GnuTLS to use … mode."* (the cert fields stay
editable so you can prepare a profile ahead of a rebuild).

## Keychain-backed secrets

- Group secrets and XAUTH passwords are stored as macOS Keychain generic
  passwords — **never in the profile JSON**.
- Keychain items are keyed by a **stable per-profile UUID**, so renaming a
  profile is purely cosmetic and never loses or duplicates its secrets.

## Config import

- Import a Cisco **`.pcf`** or a **`vpnc` `.conf`** file (via *Import Config…* or
  the *Import…* button in *Manage VPNs*).
- Obfuscated secrets in `.pcf` files (`enc_GroupPwd`, `enc_UserPassword`) are
  decoded with **`cisco-decrypt`** and stored straight into the Keychain.
- After import you're told which fields, if any, still need to be filled in.

## Split DNS (scoped resolver)

- DNS is configured **per tunnel and scoped to the VPN's domains** — your normal
  DNS keeps working for everything else.
- A scoped resolver is registered at `State:/Network/Service/<utunN>/DNS` with
  `SupplementalMatchDomains` taken from the gateway (`CISCO_DEF_DOMAIN`,
  `CISCO_SPLIT_DNS`) plus the **VPN domains** you set on the profile.
- The upstream global-DNS takeover is removed, so a connecting VPN can't hijack
  your primary resolver. If no match domain is known, that VPN's DNS is skipped
  rather than applied globally.
- The gateway hostname is resolved to an IP **before** connecting, so a gateway
  living under its own scoped domain doesn't become unreachable once the tunnel's
  DNS takes effect.

## Native utun (no kext)

The bundled `vpnc` opens a `PF_SYSTEM` / `SYSPROTO_CONTROL` socket against the
`com.apple.net.utun_control` kernel control to get a `utunN` interface — the same
mechanism the OS uses for its own VPNs. No third-party kernel extension is needed.

## Notifications

- A macOS notification fires when a tunnel **connects** and when it
  **disconnects** (state changes are detected by diffing the live tunnel set).
- If notifications are disabled in System Settings, VpncBar tells you how to
  enable them instead of failing silently.

## Graceful teardown

- Disconnecting a profile signals its specific `vpnc` (by PID or PID file) via the
  patched **`vpnc-disconnect`**, which verifies the target really is `vpnc` before
  killing it.
- A **sweep** mode cleans up orphaned scoped-DNS entries and routes left behind by
  a `utun` that has gone away.
- **Quitting the app disconnects all active tunnels** first.

---

## How it's put together

| Component | What it is |
|-----------|------------|
| `src/` | The Swift/AppKit app (`main.swift`), `Info.plist`, app icon + generator. |
| `vendor/vpnc/` | A vendored, utun-patched `vpnc` (fork of `vpnc` 0.5.3 + breiter's xnu utun port). GPLv2. |
| `vendor/vpnc-script` | The network-config script (from OpenConnect), patched for scoped DNS and a hands-off default route. |
| `vendor/NOTICE` | Provenance, licensing, and a full list of local modifications. |

Runtime paths: `vpnc` and `vpnc-disconnect` live in `/opt/local/sbin`,
`vpnc-script` in `/opt/local/etc/vpnc`, and `cisco-decrypt` in `/opt/local/bin`
(MacPorts layout).

## Requirements

- macOS on Apple Silicon (or Intel), recent versions.
- Xcode Command Line Tools (`swiftc`) to build the app.
- [MacPorts](https://www.macports.org/) `libgcrypt` to build the bundled `vpnc`:
  `sudo port install libgcrypt`.
- `cisco-decrypt` (for `.pcf` import) — comes with the MacPorts `vpnc` package.

## Build & install

```sh
# 1. Build and install the utun-capable vpnc (PSK + XAUTH; no certs).
./build-vpnc.sh
sudo ./install-utun-vpnc.sh

# 2. Allow VpncBar to run vpnc/vpnc-disconnect as root without a password prompt.
./install-sudoers.sh

# 3. Build the app, then run or install it.
./build.sh
open bin/VpncBar.app
# or: cp -r bin/VpncBar.app /Applications/
```

### Certificate support (optional)

The bundled `vpnc` is built with `CRYPTO_NONE=yes` — PSK + XAUTH only, no X.509.
To use `hybrid`/`cert` authmodes, rebuild `vpnc` with a TLS backend:

```sh
# GnuTLS (LGPL, GPL-compatible) — drop CRYPTO_NONE:
make -C vendor/vpnc clean && make -C vendor/vpnc SCRIPT_PATH=/opt/local/etc/vpnc/vpnc-script
sudo ./install-utun-vpnc.sh
```

VpncBar detects (via `otool -L`) whether the installed binary has a TLS backend
and only treats cert/hybrid as usable when it does. See `vendor/NOTICE` for the
OpenSSL alternative and its licensing caveat.

## Usage

1. Click the menu-bar icon → **Manage VPNs…** to add a profile (or **Import
   Config…** to load a `.pcf`/`.conf`).
2. Click a profile row to connect; click again to disconnect.
3. Right-click a row to edit it.

## Where things are stored

- Profiles (no secrets): `~/.config/vpncbar/profiles.json`
- PID files for running tunnels: `~/.config/vpncbar/run/`
- Secrets: macOS **login Keychain**, keyed by each profile's UUID.

## Cleaning up

```sh
./clean.sh         # remove all build artifacts (sources kept)
./clean.sh app     # just the VpncBar.app build (bin/)
./clean.sh vpnc    # just the vendored vpnc objects/binaries
./clean.sh deps    # just the static crypto libs (vendor/deps)
./clean.sh pkg     # just the installer artifacts (build/ + dist/)
```

## Licensing

The app is in this repository's `LICENSE`. The vendored components
(`vendor/vpnc`, `vendor/vpnc-script`) are **GPLv2 / GPLv2-or-later**; their full
source and a detailed list of local modifications are in `vendor/NOTICE`.
