import AppKit
import Foundation
import UniformTypeIdentifiers
import UserNotifications

// MARK: - Paths

let kVpnc = "/opt/vpncbar/vpnc"
let kVpncDisconnect = "/opt/vpncbar/vpnc-disconnect"
let kCiscoDecrypt = "/opt/vpncbar/cisco-decrypt"
let kSecurity = "/usr/bin/security"
let kSudo = "/usr/bin/sudo"
let kPs = "/bin/ps"
let kOtool = "/usr/bin/otool"
let kNetstat = "/usr/sbin/netstat"
let kVpncScript = "/opt/vpncbar/vpnc-script"   // matches the binary's built-in SCRIPT_PATH

// openconnect (AnyConnect/SSL backend) is NOT bundled — we use a system install.
// Look in the usual Homebrew/MacPorts/local locations; cached. nil if not found.
private var _openconnect: String?? = nil
func openconnectPath() -> String? {
    if let cached = _openconnect { return cached }
    let found = ["/opt/homebrew/bin/openconnect", "/opt/local/bin/openconnect",
                 "/opt/local/sbin/openconnect",
                 "/usr/local/bin/openconnect"].first { FileManager.default.isExecutableFile(atPath: $0) }
    _openconnect = found
    return found
}

// Whether the installed vpnc was built with a TLS backend (GnuTLS/OpenSSL), i.e.
// supports IKE Authmode cert/hybrid. Detected from its linked libraries; cached.
private var _vpncCerts: Bool? = nil
func vpncSupportsCerts() -> Bool {
    if let c = _vpncCerts { return c }
    let out = run(kOtool, ["-L", kVpnc]).out.lowercased()
    let c = out.contains("gnutls") || out.contains("libcrypto") || out.contains("libssl")
    _vpncCerts = c
    return c
}

let configDir = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent(".config/vpncbar")
let profilesPath = configDir.appendingPathComponent("profiles.json").path

// Pidfiles live in a user-creatable, persistent dir (NOT /var/run, which is
// volatile and root-only). vpnc runs as root but can still write here.
let pidDir = configDir.appendingPathComponent("run").path
// Pidfile is "<uuid>-<name>.pid": the uuid makes it collision-proof (two profiles
// can't clash) and ties it to the stable identity; the name is for readability.
func pidFile(_ p: Profile) -> String {
    let id = p.uuid ?? p.name
    let n = p.name.filter { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
    return "\(pidDir)/\(id)-\(n).pid"
}

// Per-tunnel runtime info written by vpnc-script on connect (Stats tab) and the
// captured vpnc connection output (Debug tab). The .info file lives in a fixed
// root-writable dir derived from VPNPID *inside the script* — we must NOT pass its
// path on the vpnc "Script" line: that line has a 200-byte limit (GETLINE_MAX_BUFLEN)
// and a long path truncates the script path itself, breaking the whole connect.
// It's transient (removed on disconnect), so /var/run is fine. The .log is ours.
let infoDir = "/var/run/vpncbar"
func infoFile(_ p: Profile) -> String { "\(infoDir)/\(p.uuid ?? p.name).info" }
// "<uuid>_<name>.log" — vpnc itself writes the whole session here via --log-file
// (truncated per connect), so the Debug tab just tails it.
func logFile(_ p: Profile) -> String {
    let id = p.uuid ?? p.name
    let n = p.name.filter { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
    return "\(pidDir)/\(id)_\(n).log"
}

// The exact argv VpncBar launches (Info tab). Secrets are piped on stdin (vpnc's
// trailing "-" / openconnect's --passwd-on-stdin), so they're not in the argv.
func vpncCommandLine(_ p: Profile) -> String {
    if isOpenconnect(p) {
        let oc = openconnectPath() ?? "openconnect"
        return "\(kSudo) " + openconnectArgs(p, binary: oc).joined(separator: " ")
    }
    return "\(kSudo) -n \(kVpnc) --non-inter --pid-file \(pidFile(p)) --log-file \(logFile(p)) -"
}

// MARK: - Model

struct Profile: Codable {
    var uuid: String? = nil   // stable identity; Keychain keys off this, so renames are cosmetic
    var name: String          // display label
    var gateway: String       // IPSec gateway
    var id: String            // IPSec ID (group name)
    var username: String      // Xauth username
    // Optional vpnc options. nil/"" => directive omitted (vpnc default).
    // Defaults keep the synthesized memberwise init compatible with old call sites.
    var authmode: String? = nil      // IKE Authmode: psk/cert/hybrid
    var dhGroup: String? = nil       // IKE DH Group: dh1/dh2/dh5/dh14…dh18
    var pfs: String? = nil           // Perfect Forward Secrecy
    var natMode: String? = nil       // NAT Traversal Mode
    var vendor: String? = nil        // Vendor: cisco/netscreen/fortigate
    var ifmode: String? = nil        // Interface mode: tun/tap
    var domain: String? = nil        // Domain (auth/NT domain)
    var dnsMatchDomains: String? = nil  // scoped-DNS match domains (space/comma separated)
    var caFile: String? = nil        // CA cert path for cert/hybrid auth (CA-File)
    var clientCert: String? = nil    // client cert path (cert mode; vpnc has no directive yet)
    var appVersion: String? = nil    // Application version
    var localAddr: String? = nil     // Local Addr
    var localPort: String? = nil     // Local Port
    var udpPort: String? = nil       // Cisco UDP Encapsulation Port
    var mtu: String? = nil           // Interface MTU
    var dpdTimeout: String? = nil    // DPD idle timeout (our side)
    var debug: String? = nil         // Debug: 0/1/2/3/99
    var enableWeak: Bool? = nil      // Enable weak encryption (3DES) — defaults on
    var singleDES: Bool? = nil       // Enable Single DES
    var noEncryption: Bool? = nil    // Enable no encryption
    var weakAuth: Bool? = nil        // Enable weak authentication
    var extra: [String]? = nil       // verbatim vpnc.conf directives
    // Backend: nil/"vpnc" => Cisco IPSec via bundled vpnc; "openconnect" => AnyConnect
    // SSL via system openconnect. For openconnect we reuse gateway(=server),
    // username, password, dnsMatchDomains, clientCert.
    var kind: String? = nil          // "vpnc" (default) | "openconnect"
    var ocAuthgroup: String? = nil   // openconnect --authgroup
    var ocServerCert: String? = nil  // openconnect --servercert pin (e.g. "pin-sha256:…")
    var ocOtp: Bool? = nil           // openconnect: prompt for a one-time 2FA code on connect
    // openconnect Options tab:
    var ocProtocol: String? = nil    // --protocol (anyconnect default; gp/pulse/f5/fortinet/nc/array)
    var ocNoDTLS: Bool? = nil        // --no-dtls (force TLS transport when UDP/DTLS is blocked)
    var ocDPD: String? = nil         // --dpd seconds (blank = gateway-negotiated)
    var ocMTU: String? = nil         // --mtu (blank = automatic)
    var ocReconnect: String? = nil   // --reconnect-timeout seconds (openconnect default 300)
    var ocDebug: String? = nil       // verbosity 0/1/2/3/99 → -v… / --dump-http-traffic
}

// Backend of a profile: defaults to vpnc when unset (back-compat with old profiles).
func isOpenconnect(_ p: Profile) -> Bool { (p.kind ?? "vpnc") == "openconnect" }

// Trimmed non-empty value, or nil.
func ne(_ s: String?) -> String? {
    guard let t = s?.trimmingCharacters(in: .whitespaces), !t.isEmpty else { return nil }
    return t
}

// Split "DOMAIN\user" into (domain, user); a plain "user" yields (nil, "user").
func splitDomainUser(_ s: String) -> (domain: String?, user: String) {
    guard let r = s.range(of: "\\") else { return (nil, s) }
    let d = s[..<r.lowerBound].trimmingCharacters(in: .whitespaces)
    let u = s[r.upperBound...].trimmingCharacters(in: .whitespaces)
    return (d.isEmpty ? nil : d, u)
}

func loadProfiles() -> [Profile] {
    guard let data = FileManager.default.contents(atPath: profilesPath),
          let list = try? JSONDecoder().decode([Profile].self, from: data) else { return [] }
    return list
}

func saveProfiles(_ list: [Profile]) {
    try? FileManager.default.createDirectory(at: configDir, withIntermediateDirectories: true)
    let enc = JSONEncoder()
    enc.outputFormatting = [.prettyPrinted, .sortedKeys]
    if let data = try? enc.encode(list) {
        try? data.write(to: URL(fileURLWithPath: profilesPath))
    }
}

// MARK: - Shell

@discardableResult
func run(_ launchPath: String, _ args: [String], stdin: String? = nil)
    -> (status: Int32, out: String, err: String) {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: launchPath)
    proc.arguments = args
    let outPipe = Pipe(), errPipe = Pipe()
    proc.standardOutput = outPipe
    proc.standardError = errPipe
    var inPipe: Pipe?
    if stdin != nil { inPipe = Pipe(); proc.standardInput = inPipe }
    do { try proc.run() } catch {
        return (-1, "", "failed to launch \(launchPath): \(error)")
    }
    if let inPipe, let stdin {
        inPipe.fileHandleForWriting.write(Data(stdin.utf8))
        inPipe.fileHandleForWriting.closeFile()
    }
    let out = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    proc.waitUntilExit()
    return (proc.terminationStatus, out, err)
}

// MARK: - Keychain

func keychainSecret(_ service: String) -> String? {
    let r = run(kSecurity, ["find-generic-password", "-s", service, "-w"])
    guard r.status == 0 else { return nil }
    let v = r.out.trimmingCharacters(in: .whitespacesAndNewlines)
    return v.isEmpty ? nil : v
}

@discardableResult
func storeKeychain(service: String, account: String, value: String) -> Bool {
    run(kSecurity, ["add-generic-password", "-U", "-s", service, "-a", account, "-w", value]).status == 0
}

func deleteKeychain(service: String) {
    run(kSecurity, ["delete-generic-password", "-s", service])
}

// MARK: - Config import (.pcf / vpnc .conf)

struct ParsedConfig { var profile: Profile; var secret: String?; var password: String? }

func parseConfigFile(_ path: String) -> ParsedConfig? {
    guard let raw = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
    let lines = raw.replacingOccurrences(of: "\r", with: "")
        .split(separator: "\n", omittingEmptySubsequences: false).map(String.init)

    func pcf(_ key: String) -> String? {
        let p = key.lowercased() + "="
        return lines.first { $0.lowercased().hasPrefix(p) }.map { String($0.dropFirst(p.count)) }
    }
    func conf(_ key: String) -> String? {
        let p = key.lowercased() + " "
        return lines.first { $0.lowercased().hasPrefix(p) }
            .map { String($0.dropFirst(key.count)).trimmingCharacters(in: .whitespaces) }
    }
    func decrypt(_ s: String) -> String? {
        let r = run(kCiscoDecrypt, [s])
        return r.status == 0 ? r.out.trimmingCharacters(in: .whitespacesAndNewlines) : nil
    }
    func blank(_ s: String?) -> Bool { s == nil || s!.isEmpty }

    var gateway = "", id = "", username = ""
    var secret: String?, password: String?

    if lines.contains(where: { $0.lowercased().hasPrefix("ipsec gateway ") }) {
        gateway = conf("IPSec gateway") ?? ""
        id = conf("IPSec ID") ?? ""
        username = conf("Xauth username") ?? ""
        password = conf("Xauth password")
        secret = conf("IPSec secret")
        if blank(secret), let obf = conf("IPSec obfuscated secret") { secret = decrypt(obf) }
    } else if lines.contains(where: { $0.lowercased().hasPrefix("host=") }) {
        gateway = pcf("Host") ?? ""
        id = pcf("GroupName") ?? ""
        username = pcf("Username") ?? ""
        secret = pcf("GroupPwd")
        if blank(secret), let enc = pcf("enc_GroupPwd") { secret = decrypt(enc) }
        password = pcf("UserPassword")
        if blank(password), let enc = pcf("enc_UserPassword") { password = decrypt(enc) }
    } else {
        return nil
    }

    let base = ((path as NSString).lastPathComponent as NSString).deletingPathExtension
    let safe = base.lowercased().replacingOccurrences(of: " ", with: "-")
    return ParsedConfig(
        profile: Profile(name: safe, gateway: gateway, id: id, username: username, extra: nil),
        secret: blank(secret) ? nil : secret,
        password: blank(password) ? nil : password)
}

// Keychain service for a profile's secret/password. Keyed off the stable uuid
// (falling back to name only for not-yet-migrated entries), so renaming a profile
// never changes the key — no migration, no duplicate, no lost secret.
func kcService(_ p: Profile, _ kind: String) -> String { "vpnc-\(p.uuid ?? p.name)-\(kind)" }

// Persist a profile + (optional) secrets, keyed by uuid. A new profile gets a
// uuid here; an edited one keeps its uuid, so this replaces it in place even if
// the name changed.
@discardableResult
func upsert(_ profile: Profile, secret: String?, password: String?) -> Profile {
    var p = profile
    if p.uuid == nil { p.uuid = UUID().uuidString }
    var list = loadProfiles().filter { $0.uuid != p.uuid }
    list.append(p)
    list.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    saveProfiles(list)
    if let secret, !secret.isEmpty { storeKeychain(service: kcService(p, "secret"), account: p.id, value: secret) }
    if let password, !password.isEmpty { storeKeychain(service: kcService(p, "password"), account: p.username, value: password) }
    return p
}

func removeProfile(_ p: Profile) {
    saveProfiles(loadProfiles().filter { $0.uuid != p.uuid })
    deleteKeychain(service: kcService(p, "secret"))
    deleteKeychain(service: kcService(p, "password"))
}

// One-time migration: give every profile a uuid and move its name-based Keychain
// items (vpnc-<name>-…) to uuid-based ones (vpnc-<uuid>-…).
func migrateProfilesToUUID() {
    var list = loadProfiles()
    var changed = false
    for i in list.indices where list[i].uuid == nil {
        let id = UUID().uuidString
        let name = list[i].name
        if let s = keychainSecret("vpnc-\(name)-secret") {
            storeKeychain(service: "vpnc-\(id)-secret", account: list[i].id, value: s)
            deleteKeychain(service: "vpnc-\(name)-secret")
        }
        if let pw = keychainSecret("vpnc-\(name)-password") {
            storeKeychain(service: "vpnc-\(id)-password", account: list[i].username, value: pw)
            deleteKeychain(service: "vpnc-\(name)-password")
        }
        list[i].uuid = id
        changed = true
    }
    if changed { saveProfiles(list) }
}

// MARK: - Connection state (multi-tunnel: one vpnc per profile, keyed by pidfile)

func parseEtime(_ s: String) -> Int? {
    var days = 0
    var rest = Substring(s)
    if let dash = s.firstIndex(of: "-") {
        days = Int(s[..<dash]) ?? 0
        rest = s[s.index(after: dash)...]
    }
    let parts = rest.split(separator: ":").map { Int($0) ?? 0 }
    switch parts.count {
    case 3: return days * 86400 + parts[0] * 3600 + parts[1] * 60 + parts[2]
    case 2: return days * 86400 + parts[0] * 60 + parts[1]
    default: return nil
    }
}

func formatElapsed(_ secs: Int) -> String {
    let d = secs / 86400, h = (secs % 86400) / 3600, m = (secs % 3600) / 60, s = secs % 60
    if d > 0 { return "\(d)d \(h)h" }
    if h > 0 { return String(format: "%d:%02d:%02d", h, m, s) }
    return String(format: "%d:%02d", m, s)
}

// Elapsed seconds for a live tunnel daemon (vpnc or openconnect) with this pid.
func vpncElapsed(pid: Int) -> Int? {
    let r = run(kPs, ["-p", "\(pid)", "-o", "comm=,etime="])
    guard r.status == 0 else { return nil }
    let line = r.out.trimmingCharacters(in: .whitespacesAndNewlines)
    guard line.contains("vpnc") || line.contains("openconnect"),
          let etok = line.split(separator: " ").last else { return nil }
    return parseEtime(String(etok))
}

// Connected profiles -> (live pid, elapsed seconds), keyed by current profile name.
// Detected from running vpnc command lines via `ps` (no root file access needed):
// the "--pid-file …/<uuid>-<name>.pid" argument maps each daemon to a profile by
// its stable uuid (falling back to a legacy "<name>.pid" match). Falls back to
// reading the pidfile for any profile not seen in the process list.
func connectedTunnels(_ profiles: [Profile]) -> [String: (pid: Int, secs: Int)] {
    func match(_ stem: String) -> Profile? {
        for p in profiles { if let u = p.uuid, stem.hasPrefix(u + "-") { return p } }
        return profiles.first { $0.name == stem }   // legacy "<name>.pid"
    }
    var result: [String: (pid: Int, secs: Int)] = [:]
    let r = run(kPs, ["-axo", "pid=,etime=,command="])
    if r.status == 0 {
        for raw in r.out.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            // Both backends carry "--pid-file …/<uuid>-<name>.pid"; match either binary.
            guard line.contains("/vpnc") || line.contains("/openconnect"),
                  let pf = line.range(of: "--pid-file ") else { continue }
            guard let pathTok = line[pf.upperBound...].split(separator: " ").first else { continue }
            let base = (String(pathTok) as NSString).lastPathComponent
            guard base.hasSuffix(".pid") else { continue }
            let toks = line.split(separator: " ")
            guard let p = match(String(base.dropLast(4))), toks.count >= 2,
                  let pid = Int(toks[0]), let secs = parseEtime(String(toks[1])) else { continue }
            result[p.name] = (pid, secs)
        }
    }
    for p in profiles where result[p.name] == nil {
        if let s = try? String(contentsOfFile: pidFile(p), encoding: .utf8),
           let pid = Int(s.trimmingCharacters(in: .whitespacesAndNewlines)),
           let secs = vpncElapsed(pid: pid) {
            result[p.name] = (pid, secs)
        }
    }
    return result
}

enum ActionResult { case ok, message(String) }

// Last good gateway-hostname → IP lookup, so a reconnect still works even if a
// stale scoped resolver is lingering and would route the gateway to the VPN DNS.
var gatewayIPCache: [String: String] = [:]

// Resolve the gateway to an IPv4 literal via the system resolver. We hand vpnc an
// IP (not the hostname) so the gateway never depends on DNS — immune to having its
// own domain scoped to the VPN's internal DNS (which doesn't know the public host).
func resolveGatewayIP(_ host: String) -> String {
    var a4 = in_addr()
    if host.withCString({ inet_pton(AF_INET, $0, &a4) }) == 1 { return host }  // already an IP
    var hints = addrinfo()
    hints.ai_family = AF_INET
    hints.ai_socktype = SOCK_DGRAM
    var res: UnsafeMutablePointer<addrinfo>?
    if getaddrinfo(host, nil, &hints, &res) == 0, let info = res {
        defer { freeaddrinfo(res) }
        if let sa = info.pointee.ai_addr {
            var addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN))
            let ip = String(cString: buf)
            gatewayIPCache[host] = ip
            return ip
        }
    }
    return gatewayIPCache[host] ?? host   // fall back to last good IP, else the hostname
}

// "VPNPID='…' [VPNC_MATCH_DOMAINS='…']" — env prefix for our vpnc-script. VPNPID
// pins the per-tunnel stats file (/var/run/vpncbar/<uuid>.info) so the Info tab
// works; VPNC_MATCH_DOMAINS drives scoped DNS. Shared by vpnc's "Script" directive
// and openconnect's "--script" (both run the value via /bin/sh, so the env sticks).
func scriptEnvPrefix(_ p: Profile) -> String {
    var s = "VPNPID='\(p.uuid ?? p.name)'"
    if let raw = ne(p.dnsMatchDomains) {
        let domains = String(raw.map { ", ".contains($0) ? " " : $0 })
            .filter { $0.isLetter || $0.isNumber || ". -_".contains($0) }
            .split(separator: " ").joined(separator: " ")
        if !domains.isEmpty { s += " VPNC_MATCH_DOMAINS='\(domains)'" }
    }
    return s
}

func connect(_ p: Profile, otp: String? = nil) -> ActionResult {
    // Safeguard: never launch a second daemon for a profile that's already up
    // (a duplicate would fight over the same pidfile and re-resolve the gateway).
    if !connectedTunnels([p]).isEmpty { return .ok }

    if isOpenconnect(p) { return connectOpenconnect(p, otp: otp) }

    let authmode = ne(p.authmode) ?? "psk"
    let usesCert = (authmode == "cert" || authmode == "hybrid")

    // The Username field may hold "DOMAIN\user"; send the domain via vpnc's
    // Domain directive and the bare user via Xauth username.
    let (xauthDomain, xauthUser) = splitDomainUser(p.username)
    var lines = [
        "IPSec gateway \(resolveGatewayIP(p.gateway))",
        "IPSec ID \(p.id)",
        "IKE Authmode \(authmode)",
        "Xauth username \(xauthUser)",
    ]
    // psk authenticates the group with a pre-shared key; cert/hybrid authenticate
    // the gateway with an X.509 cert (verified against a CA file) instead.
    if usesCert {
        guard let ca = ne(p.caFile) else {
            return .message("\(authmode) auth needs a CA file.\nOpen Manage VPNs and set it.")
        }
        lines.append("CA-File \(ca)")
    } else {
        guard let secret = keychainSecret(kcService(p, "secret")) else {
            return .message("Group secret not found in Keychain for “\(p.name)”.\nOpen Manage VPNs and set it.")
        }
        lines.append("IPSec secret \(secret)")
    }
    let password = keychainSecret(kcService(p, "password"))
    if let xauthDomain { lines.append("Domain \(xauthDomain)") }
    if let password { lines.append("Xauth password \(password)") }

    func add(_ key: String, _ value: String?) {
        if let v = ne(value) { lines.append("\(key) \(v)") }
    }
    add("IKE DH Group", p.dhGroup)
    add("Perfect Forward Secrecy", p.pfs)
    add("NAT Traversal Mode", p.natMode)
    add("Vendor", p.vendor)
    add("Interface MTU", p.mtu)
    add("DPD idle timeout (our side)", p.dpdTimeout)
    add("Debug", p.debug)
    // Interface mode is intentionally not set — vpnc defaults to tun, which our
    // build opens as a native utun. App version / Local Addr / Local Port / UDP
    // Encap Port are left to vpnc's automatic defaults.
    // Boolean directives (each takes no value). Weak encryption defaults ON.
    if p.enableWeak ?? true { lines.append("Enable weak encryption") }
    if p.singleDES ?? false { lines.append("Enable Single DES") }
    if p.noEncryption ?? false { lines.append("Enable no encryption") }
    if p.weakAuth ?? false { lines.append("Enable weak authentication") }

    // Run our script with env vars prefixed on the "Script" command (vpnc runs it
    // via /bin/sh, so the assignments stick — for connect AND disconnect, since vpnc
    // reuses this command). VPNPID is pinned to the profile uuid so the script's temp
    // files (resolv.conf-backup, defaultroute) are keyed consistently across connect
    // and disconnect — vpnc's daemonizing fork otherwise changes the derived pid and
    // orphans the backups. VPNC_MATCH_DOMAINS carries the scoped-DNS domains.
    lines.append("Script \(scriptEnvPrefix(p)) \(kVpncScript)")
    lines.append(contentsOf: p.extra ?? [])
    let config = lines.joined(separator: "\n") + "\n"

    // Pre-create the log as OUR user (dropping any prior root-owned one), so vpnc's
    // fopen("w") truncates it in place and the file stays user-owned — that lets the
    // Debug tab's Clear truncate it without deleting it out from under a live daemon.
    try? FileManager.default.removeItem(atPath: logFile(p))
    FileManager.default.createFile(atPath: logFile(p), contents: nil)

    // Each profile gets its own pidfile so multiple tunnels can run at once.
    // --log-file makes vpnc write the whole session (handshake, debug, start/stop)
    // to our per-profile log itself, so the Debug tab just tails that file.
    let r = run(kSudo, ["-n", kVpnc, "--non-inter",
                        "--pid-file", pidFile(p), "--log-file", logFile(p), "-"], stdin: config)
    if r.status == 0 { return .ok }
    if r.err.lowercased().contains("password") && r.err.lowercased().contains("sudo") {
        return .message("sudo needs a password.\nRun install-sudoers.sh once to allow passwordless vpnc.")
    }
    // vpnc's own output went to the log file (not our pipes), so surface its tail.
    let tail = (try? String(contentsOfFile: logFile(p), encoding: .utf8))?
        .trimmingCharacters(in: .whitespacesAndNewlines).suffix(600)
    let detail = (tail.map(String.init) ?? "").isEmpty ? (r.err.isEmpty ? r.out : r.err) : String(tail!)
    return .message("vpnc failed (status \(r.status)):\n\(detail)")
}

// Build openconnect's argv (without the password, which goes on stdin). Shared by
// connect and the Info tab's command display. Server is the gateway field.
func openconnectArgs(_ p: Profile, binary: String) -> [String] {
    var args = ["-n", binary, "--background",
                "--pid-file", pidFile(p),
                "--script", "\(scriptEnvPrefix(p)) \(kVpncScript)",  // VPNPID → Info tab + scoped DNS
                "--protocol=\(ne(p.ocProtocol) ?? "anyconnect")",
                "--passwd-on-stdin",
                "--user=\(splitDomainUser(p.username).user)"]
    // Verbosity: 0 none · 1 -v · 2 -vv · 3 -vvv · 99 -vvv + full HTTP dump.
    switch ne(p.ocDebug) ?? "1" {
    case "1": args.append("-v")
    case "2": args.append("-vv")
    case "3": args.append("-vvv")
    case "99": args += ["-vvv", "--dump-http-traffic"]
    default: break   // "0": no extra verbosity
    }
    if p.ocNoDTLS ?? false { args.append("--no-dtls") }
    if let dpd = ne(p.ocDPD) { args += ["--dpd", dpd] }
    if let mtu = ne(p.ocMTU) { args += ["--mtu", mtu] }
    if let rc = ne(p.ocReconnect) { args += ["--reconnect-timeout", rc] }
    if let g = ne(p.ocAuthgroup) { args.append("--authgroup=\(g)") }
    if let pin = ne(p.ocServerCert) { args.append("--servercert=\(pin)") }
    if let cert = ne(p.clientCert) { args.append("--certificate=\(cert)") }
    args.append(p.gateway)   // server (URL or host)
    return args
}

// Fetch the gateway's group list AND each group's 2FA flag in ONE probe. The 2FA
// requirement is encoded as second-auth="1" on the group's <option>; openconnect's
// --authgroup matches the option's LABEL (its text), so that's what we store/use.
// No credentials needed — the group list is in the initial auth form.
// On a self-signed / untrusted gateway cert openconnect refuses to fetch the form
// and prints its pin-sha256 fingerprint instead. Surface that pin (only when no
// pin was already passed) so the caller can offer TOFU-style trust + pin.
func openconnectGroupList(server: String, serverCert: String?)
    -> (groups: [(group: String, otp: Bool)], certPin: String?) {
    guard let oc = openconnectPath(), !server.isEmpty else { return ([], nil) }
    var args = ["--protocol=anyconnect", "--cookieonly", "--dump-http-traffic",
                "--user=probe", "--passwd-on-stdin"]
    let havePin = ne(serverCert)
    if let pin = havePin { args.append("--servercert=\(pin)") }
    args.append(server)
    // A couple of dummy lines so openconnect reads past its password prompts and the
    // form (with the group list) gets dumped before auth harmlessly fails.
    let r = run(oc, args, stdin: "x\ny\n")
    let out = r.out + "\n" + r.err
    var result: [(String, Bool)] = []
    var seen = Set<String>()
    if let re = try? NSRegularExpression(pattern: "<option([^>]*)>([^<]+)</option>", options: [.caseInsensitive]) {
        let ns = out as NSString
        for m in re.matches(in: out, range: NSRange(location: 0, length: ns.length)) {
            let attrs = ns.substring(with: m.range(at: 1)).lowercased()
            let label = ns.substring(with: m.range(at: 2)).trimmingCharacters(in: .whitespacesAndNewlines)
            if !label.isEmpty, seen.insert(label).inserted {
                result.append((label, attrs.contains("second-auth=\"1\"")))
            }
        }
    }
    // No groups + no pin in play → scan for openconnect's "pin-sha256:…=" line.
    if result.isEmpty, havePin == nil,
       let re = try? NSRegularExpression(pattern: "pin-sha256:[A-Za-z0-9+/]+=*"),
       let m = re.firstMatch(in: out, range: NSRange(out.startIndex..., in: out)),
       let range = Range(m.range, in: out) {
        return ([], String(out[range]))
    }
    return (result, nil)
}

// Connect an openconnect (AnyConnect SSL) profile via a system openconnect, reusing
// our vpnc-script for routes/scoped-DNS. openconnect reads one value per form prompt
// from stdin: the account password, then (for 2FA groups) the one-time code.
func connectOpenconnect(_ p: Profile, otp: String? = nil) -> ActionResult {
    guard let oc = openconnectPath() else {
        return .message("openconnect isn't installed.\nInstall it:  brew install openconnect")
    }
    let password = keychainSecret(kcService(p, "password")) ?? ""
    var input = password + "\n"
    if let otp = ne(otp) { input += otp + "\n" }

    // Fresh, user-owned log; openconnect's stdout/stderr go here and the --background
    // daemon inherits the fd, so the Debug tab can tail the whole session.
    try? FileManager.default.removeItem(atPath: logFile(p))
    FileManager.default.createFile(atPath: logFile(p), contents: nil)
    let logFH = FileHandle(forWritingAtPath: logFile(p))

    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: kSudo)
    proc.arguments = openconnectArgs(p, binary: oc)
    let inPipe = Pipe()
    proc.standardInput = inPipe
    if let logFH { proc.standardOutput = logFH; proc.standardError = logFH }
    do { try proc.run() } catch {
        return .message("Couldn't launch openconnect: \(error.localizedDescription)")
    }
    inPipe.fileHandleForWriting.write(Data(input.utf8))
    inPipe.fileHandleForWriting.closeFile()
    proc.waitUntilExit()
    logFH?.closeFile()   // our handle; the backgrounded daemon keeps its own copy

    if proc.terminationStatus == 0 { return .ok }
    // Output went to the log file, so read its tail for the error detail.
    let tail = (try? String(contentsOfFile: logFile(p), encoding: .utf8))?
        .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    if tail.lowercased().contains("sudo") && tail.lowercased().contains("password") {
        return .message("sudo needs a password.\nRe-run the installer so openconnect is allowed passwordless.")
    }
    return .message("openconnect failed (status \(proc.terminationStatus)):\n\(String(tail.suffix(600)))")
}

// Prompt (on the main thread) for a one-time 2FA code before connecting an
// openconnect profile that needs one. Returns the code, or nil if cancelled.
func promptOTP(_ p: Profile) -> String? {
    let a = NSAlert()
    a.messageText = "One-time code for “\(p.name)”"
    a.addButton(withTitle: "Connect")
    a.addButton(withTitle: "Cancel")
    let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 220, height: 24))
    a.accessoryView = field
    NSApp.activate(ignoringOtherApps: true)
    a.window.initialFirstResponder = field
    // The insertion-point caret only draws when the window is actually key. In an
    // LSUIElement app NSApp.activate is async, so focusing early leaves the caret in
    // the "off" state. Hook the window's didBecomeKey (delivered synchronously during
    // runModal) and selectText *then* — at that point the window is key and the caret
    // is drawn immediately.
    let token = NotificationCenter.default.addObserver(
        forName: NSWindow.didBecomeKeyNotification, object: a.window, queue: nil) { _ in
        a.window.makeFirstResponder(field)
        field.selectText(nil)
    }
    defer { NotificationCenter.default.removeObserver(token) }
    return a.runModal() == .alertFirstButtonReturn ? field.stringValue : nil
}

// Disconnect one profile. Prefer the live PID discovered from `ps` (works even
// if no pidfile was written); fall back to the pidfile path.
func disconnect(_ p: Profile) -> ActionResult {
    let target = connectedTunnels([p])[p.name].map { "\($0.pid)" } ?? pidFile(p)
    let r = run(kSudo, ["-n", kVpncDisconnect, target])
    // The daemon logs its own teardown to the --log-file, so nothing to append here.
    if r.status == 0 || r.out.contains("no vpnc") { return .ok }
    if r.err.lowercased().contains("password") && r.err.lowercased().contains("sudo") {
        return .message("sudo needs a password.\nRun install-sudoers.sh once.")
    }
    return .message("disconnect failed:\n\(r.err.isEmpty ? r.out : r.err)")
}

// MARK: - Live tunnel stats + vpnc log (Stats / Debug tabs)

// Runtime values vpnc-script records to infoFile(p) on connect (removed on
// disconnect). Only the kernel/gateway know these at connect time, so the script
// is our source of truth rather than guessing the interface from the process.
struct TunnelInfo {
    var iface: String?
    var internalIP: String?
    var dns: String?
    var gateway: String?
    var defDomain: String?
    var splitDNS: String?
    var matchDomains: String?
    var routes: [String] = []
}

func readTunnelInfo(_ p: Profile) -> TunnelInfo {
    var t = TunnelInfo()
    guard let raw = try? String(contentsOfFile: infoFile(p), encoding: .utf8) else { return t }
    for line in raw.split(separator: "\n") {
        guard let eq = line.firstIndex(of: "=") else { continue }
        let k = String(line[..<eq]); let v = String(line[line.index(after: eq)...])
        switch k {
        case "TUNDEV":               t.iface = ne(v)
        case "INTERNAL_IP4_ADDRESS": t.internalIP = ne(v)
        case "INTERNAL_IP4_DNS":     t.dns = ne(v)
        case "VPNGATEWAY":           t.gateway = ne(v)
        case "CISCO_DEF_DOMAIN":     t.defDomain = ne(v)
        case "CISCO_SPLIT_DNS":      t.splitDNS = ne(v)
        case "VPNC_MATCH_DOMAINS":   t.matchDomains = ne(v)
        case "ROUTE":                if let r = ne(v) { t.routes.append(r) }
        default: break
        }
    }
    return t
}

// rx/tx byte+packet counters for an interface, via `netstat -ib`. The columns
// vary (the utun rows omit Address), so we count from the END, where the seven
// numeric columns are fixed: …Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll.
func interfaceCounters(_ iface: String) -> (rxBytes: Int, txBytes: Int, rxPkts: Int, txPkts: Int)? {
    let r = run(kNetstat, ["-i", "-b", "-n", "-I", iface])
    guard r.status == 0 else { return nil }
    for line in r.out.split(separator: "\n").dropFirst() {
        let c = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard c.count >= 8, c[0] == iface, Int(c[c.count - 1]) != nil else { continue }
        let n = c.count
        guard let rxp = Int(c[n - 7]), let rxb = Int(c[n - 5]),
              let txp = Int(c[n - 4]), let txb = Int(c[n - 2]) else { continue }
        return (rxb, txb, rxp, txp)
    }
    return nil
}

func humanBytes(_ n: Int) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"]
    var v = Double(n), i = 0
    while v >= 1024 && i < units.count - 1 { v /= 1024; i += 1 }
    return i == 0 ? "\(n) B" : String(format: "%.1f %@", v, units[i])
}

func grouped(_ n: Int) -> String {
    let f = NumberFormatter(); f.numberStyle = .decimal
    return f.string(from: NSNumber(value: n)) ?? "\(n)"
}

// MARK: - Profile menu row (left-click connect, right-click edit)

final class ProfileMenuItemView: NSView {
    private let name: String
    private let connectedSince: Date?     // nil = not connected; else the moment it connected
    private let onConnect: () -> Void
    private let onEdit: () -> Void
    private var hovered = false

    init(name: String, connectedSince: Date?, width: CGFloat,
         onConnect: @escaping () -> Void, onEdit: @escaping () -> Void) {
        self.name = name
        self.connectedSince = connectedSince
        self.onConnect = onConnect
        self.onEdit = onEdit
        super.init(frame: NSRect(x: 0, y: 0, width: width, height: 22))
    }
    required init?(coder: NSCoder) { fatalError() }

    // Give AppKit a fixed size so it doesn't re-guess the menu's geometry during
    // hover/dismiss (which could leave extra padding at the menu's bottom).
    override var intrinsicContentSize: NSSize { NSSize(width: frame.width, height: 22) }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        trackingAreas.forEach(removeTrackingArea)
        addTrackingArea(NSTrackingArea(rect: bounds,
                                       options: [.mouseEnteredAndExited, .activeAlways],
                                       owner: self))
    }
    override func mouseEntered(with event: NSEvent) { hovered = true; needsDisplay = true }
    override func mouseExited(with event: NSEvent) { hovered = false; needsDisplay = true }

    override func draw(_ dirtyRect: NSRect) {
        if hovered {
            NSColor.selectedContentBackgroundColor.setFill()
            bounds.fill()
        }
        let font = NSFont.menuFont(ofSize: 0)
        let color: NSColor = hovered ? .alternateSelectedControlTextColor : .labelColor
        let attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: color]
        if let since = connectedSince {
            ("✓" as NSString).draw(at: NSPoint(x: 8, y: 3), withAttributes: attrs)
            // Recompute elapsed at draw time so a 1s tick (while the menu is open)
            // makes it count up live, to the second.
            let elapsed = formatElapsed(max(0, Int(Date().timeIntervalSince(since))))
            let dim: NSColor = hovered ? .alternateSelectedControlTextColor : .secondaryLabelColor
            // Monospaced-digit font so ticking numerals don't change width (no jitter).
            let monoFont = NSFont.monospacedDigitSystemFont(ofSize: font.pointSize, weight: .regular)
            let elAttrs: [NSAttributedString.Key: Any] = [.font: monoFont, .foregroundColor: dim]
            let w = (elapsed as NSString).size(withAttributes: elAttrs).width
            (elapsed as NSString).draw(at: NSPoint(x: bounds.width - w - 12, y: 3), withAttributes: elAttrs)
        }
        (name as NSString).draw(at: NSPoint(x: 24, y: 3), withAttributes: attrs)
    }

    // Close the menu, then run the action on the next runloop tick — after the
    // menu has fully torn down (this view may be deallocated by then, so we
    // capture the closure by value rather than touching self).
    private func fire(_ action: @escaping () -> Void) {
        enclosingMenuItem?.menu?.cancelTracking()
        DispatchQueue.main.async(execute: action)
    }

    // When the menu's window isn't key, AppKit treats the first click as a mere
    // activation click and swallows it — so connecting took two clicks (the
    // first activated, the second acted). Standard NSMenuItems are immune; our
    // custom view isn't unless it opts into receiving that first click.
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

    // AppKit only delivers mouseUp to the view that claimed the preceding
    // mouseDown, so claim it here to guarantee our mouseUp below fires.
    override func mouseDown(with event: NSEvent) { }

    // Exactly one action per click: control-click edits, plain click connects.
    override func mouseUp(with event: NSEvent) {
        if event.modifierFlags.contains(.control) { fire(onEdit) } else { fire(onConnect) }
    }

    // Right-click edits the profile directly.
    override func rightMouseUp(with event: NSEvent) { fire(onEdit) }
}

// MARK: - Menu-bar controller

final class AppController: NSObject, UNUserNotificationCenterDelegate, NSMenuDelegate, NSApplicationDelegate {
    let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    var timer: Timer?
    var tickTimer: Timer?     // 1s redraw of elapsed times, only while the menu is open
    var manageWindow: ManageWindow?
    var aboutWindow: AboutWindow?
    var signalSources: [DispatchSourceSignal] = []   // SIGTERM/SIGINT → disconnect all, then exit
    private var lastConnected: Set<String>?   // nil until first poll (no notification at launch)

    func start() {
        // Single instance: every copy (bin/, /Applications, …) shares this bundle id,
        // so launching another copy would run a second menu-bar icon. If one is
        // already running, quit this one immediately — exit() (not NSApp.terminate)
        // so we DON'T run the disconnect-all teardown and tear down the other's tunnels.
        let bid = Bundle.main.bundleIdentifier ?? "local.vpncbar"
        if NSRunningApplication.runningApplications(withBundleIdentifier: bid)
            .contains(where: { $0 != .current }) {
            exit(0)
        }

        try? FileManager.default.createDirectory(atPath: pidDir, withIntermediateDirectories: true)
        migrateProfilesToUUID()   // give existing profiles a stable uuid + move their Keychain items
        statusItem.menu = NSMenu()
        statusItem.menu?.delegate = self
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            if !granted {
                DispatchQueue.main.async { [weak self] in self?.warnNotificationsDisabled() }
            }
        }
        refreshState()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.refreshState()
        }
        installTerminationHandlers()
    }

    // A plain `kill`/`pkill VpncBar` (and our uninstaller) send SIGTERM, which would
    // otherwise kill us WITHOUT running applicationWillTerminate — orphaning tunnels.
    // Catch SIGTERM/SIGINT and tear everything down first. (SIGKILL is uncatchable.)
    func installTerminationHandlers() {
        for sig in [SIGTERM, SIGINT] {
            signal(sig, SIG_IGN)   // disable default action; the DispatchSource handles it
            let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            src.setEventHandler { [weak self] in
                self?.disconnectAllSync()
                exit(0)
            }
            src.resume()
            signalSources.append(src)
        }
    }

    // Disconnect every live tunnel synchronously (each sends SIGTERM to its vpnc,
    // which runs the teardown script). Shared by quit and the signal handlers.
    func disconnectAllSync() {
        let profiles = loadProfiles()
        let connected = Set(connectedTunnels(profiles).keys)
        for p in profiles where connected.contains(p.name) {
            _ = disconnect(p)
        }
    }

    func refreshState() {
        let profiles = loadProfiles()
        let tunnels = connectedTunnels(profiles)
        let elapsed = tunnels.mapValues { $0.secs }
        let connected = Set(tunnels.keys)

        let img = NSImage(systemSymbolName: connected.isEmpty ? "lock.open" : "lock.fill",
                          accessibilityDescription: "VPN")
        img?.isTemplate = true
        statusItem.button?.image = img
        rebuildMenu(profiles: profiles, elapsed: elapsed)

        // Notify per profile on change (covers manual connects + unexpected drops).
        if let prev = lastConnected {
            for name in connected.subtracting(prev) { notify("VPN connected", "Connected to \(name).") }
            let closed = prev.subtracting(connected)
            for name in closed { notify("VPN disconnected", "Disconnected from \(name).") }
            // When any tunnel closes, sweep config a crashed vpnc may have left
            // behind (orphaned scoped DNS + routes on a now-gone utun).
            if !closed.isEmpty {
                DispatchQueue.global(qos: .utility).async {
                    _ = run(kSudo, ["-n", kVpncDisconnect, "sweep"])
                }
            }
        }
        lastConnected = connected
    }

    // Shown when notification permission is off, with a shortcut to Settings.
    func warnNotificationsDisabled() {
        let a = NSAlert()
        a.messageText = "Enable notifications for VpncBar"
        a.informativeText = "VpncBar needs notification permission to alert you when the VPN connects or disconnects.\n\nEnable it in System Settings → Notifications → VpncBar."
        a.addButton(withTitle: "Open Settings")
        a.addButton(withTitle: "Not Now")
        NSApp.activate(ignoringOtherApps: true)
        if a.runModal() == .alertFirstButtonReturn,
           let url = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension") {
            NSWorkspace.shared.open(url)
        }
    }

    func notify(_ title: String, _ body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        if !body.isEmpty { content.body = body }
        content.sound = .default
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req)
    }

    // Show banners even when VpncBar is the active app.
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }

    // While the menu is open, tick the elapsed times every second. The normal
    // poll timer is suspended during menu tracking and a default-mode timer
    // won't fire — so this one is added in the event-tracking run-loop mode.
    func menuWillOpen(_ menu: NSMenu) {
        refreshState()   // fresh times the instant it opens
        let t = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            for item in self?.statusItem.menu?.items ?? [] {
                (item.view as? ProfileMenuItemView)?.needsDisplay = true
            }
        }
        RunLoop.main.add(t, forMode: .eventTracking)
        tickTimer = t
    }

    func menuDidClose(_ menu: NSMenu) {
        tickTimer?.invalidate()
        tickTimer = nil
    }

    func rebuildMenu(profiles: [Profile], elapsed: [String: Int]) {
        guard let menu = statusItem.menu else { return }
        menu.removeAllItems()

        if profiles.isEmpty {
            let none = NSMenuItem(title: "No VPNs — use Manage VPNs…", action: nil, keyEquivalent: "")
            none.isEnabled = false
            menu.addItem(none)
        } else {
            // Uniform row width so the elapsed times line up on the right edge.
            // Reserve room for an hour-format string so width doesn't jump when
            // a tunnel crosses the 1-hour mark while the menu is open.
            let font = NSFont.menuFont(ofSize: 0)
            let monoFont = NSFont.monospacedDigitSystemFont(ofSize: font.pointSize, weight: .regular)
            var width: CGFloat = 200
            for p in profiles {
                let nameW = (p.name as NSString).size(withAttributes: [.font: font]).width
                let sample = elapsed[p.name] != nil ? "0:00:00" : ""
                let elW = (sample as NSString).size(withAttributes: [.font: monoFont]).width
                width = max(width, 24 + ceil(nameW) + 24 + ceil(elW) + 14)
            }
            let now = Date()
            for p in profiles {
                let item = NSMenuItem()
                item.view = ProfileMenuItemView(
                    name: p.name,
                    connectedSince: elapsed[p.name].map { now.addingTimeInterval(-Double($0)) },
                    width: width,
                    onConnect: { [weak self] in self?.toggleProfile(p.name) },
                    onEdit: { [weak self] in self?.editProfile(p.name) })
                menu.addItem(item)
            }
        }

        menu.addItem(.separator())
        if !elapsed.isEmpty {
            let d = NSMenuItem(title: "Disconnect All", action: #selector(doDisconnectAll), keyEquivalent: "")
            d.target = self
            menu.addItem(d)
        }
        let m = NSMenuItem(title: "Manage VPNs…", action: #selector(openManage), keyEquivalent: "")
        m.target = self
        menu.addItem(m)
        let about = NSMenuItem(title: "About VpncBar", action: #selector(openAbout), keyEquivalent: "")
        about.target = self
        menu.addItem(about)
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Quit VpncBar",
                                action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
    }

    // Left-click a profile: toggle just that tunnel — leaves other tunnels alone.
    func toggleProfile(_ name: String) {
        guard let p = loadProfiles().first(where: { $0.name == name }) else { return }
        if !connectedTunnels([p]).isEmpty {
            perform { disconnect(p) }
        } else if isOpenconnect(p) && (p.ocOtp ?? false) {
            guard let code = promptOTP(p) else { return }   // cancelled
            perform { connect(p, otp: code) }
        } else {
            perform { connect(p) }
        }
    }

    // Right-click a profile: jump straight to its edit dialog.
    // At most one editor window per profile (keyed by uuid; new profiles share the
    // "__new__" slot). Both the menu and the Manage window open editors through here.
    var editors: [String: ProfileEditor] = [:]

    func editProfile(_ name: String) {
        guard let p = loadProfiles().first(where: { $0.name == name }) else { return }
        openEditor(p)
    }

    func openEditor(_ p: Profile?) {
        let key = p?.uuid ?? p?.name ?? "__new__"
        // Already open for this profile → just bring it forward, don't duplicate.
        if let existing = editors[key] {
            NSApp.activate(ignoringOtherApps: true)
            existing.window.makeKeyAndOrderFront(nil)
            return
        }
        let editor = ProfileEditor(profile: p) { [weak self] prof, secret, password in
            upsert(prof, secret: secret, password: password)
            self?.refreshState()
            self?.manageWindow?.reload()
        }
        editor.onClose = { [weak self] in self?.editors[key] = nil }
        editors[key] = editor
        NSApp.activate(ignoringOtherApps: true)
        editor.window.center()
        editor.window.makeKeyAndOrderFront(nil)
    }

    @objc func doDisconnectAll() {
        let profiles = loadProfiles()
        let connected = Set(connectedTunnels(profiles).keys)
        let toDrop = profiles.filter { connected.contains($0.name) }
        perform {
            var lastError: ActionResult = .ok
            for p in toDrop {
                let r = disconnect(p)
                if case .message = r { lastError = r }
            }
            return lastError
        }
    }

    // Quit without orphaning tunnels: disconnect every one synchronously before
    // we exit. Each disconnect sends SIGTERM to vpnc, which runs the script's
    // teardown (restoring its routes/DNS) — graceful even though vpnc outlives us.
    func applicationWillTerminate(_ notification: Notification) {
        tickTimer?.invalidate()
        disconnectAllSync()
    }

    func perform(_ action: @escaping () -> ActionResult) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = action()
            DispatchQueue.main.async { [weak self] in
                self?.refreshState()
                if case let .message(msg) = result { alert(msg) }
            }
        }
    }

    @objc func openManage() {
        if manageWindow == nil {
            manageWindow = ManageWindow(onChange: { [weak self] in self?.refreshState() },
                                        onEdit: { [weak self] p in self?.openEditor(p) })
        }
        NSApp.activate(ignoringOtherApps: true)
        manageWindow?.show()
    }

    @objc func openAbout() {
        if aboutWindow == nil { aboutWindow = AboutWindow() }
        NSApp.activate(ignoringOtherApps: true)
        aboutWindow?.show()
    }
}

func alert(_ message: String) {
    let a = NSAlert()
    a.messageText = "VpncBar"
    a.informativeText = message
    a.runModal()
}

// MARK: - Manage window (list + add/edit/remove/import)

final class ManageWindow: NSObject, NSTableViewDataSource, NSTableViewDelegate {
    let window: NSWindow
    let table = NSTableView()
    var profiles: [Profile] = []
    let onChange: () -> Void
    let onEdit: (Profile?) -> Void   // open/focus the shared per-profile editor

    init(onChange: @escaping () -> Void, onEdit: @escaping (Profile?) -> Void) {
        self.onChange = onChange
        self.onEdit = onEdit
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 420, height: 320),
                          styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "Manage VPNs"
        window.isReleasedWhenClosed = false
        super.init()

        let col = NSTableColumn(identifier: .init("name"))
        col.title = "VPN profiles"
        table.addTableColumn(col)
        table.dataSource = self
        table.delegate = self
        table.headerView = nil
        table.doubleAction = #selector(editSelected)
        table.target = self

        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false

        func button(_ title: String, _ sel: Selector) -> NSButton {
            let b = NSButton(title: title, target: self, action: sel)
            b.bezelStyle = .rounded
            b.translatesAutoresizingMaskIntoConstraints = false
            return b
        }
        let add = button("Add", #selector(addNew))
        let edit = button("Edit", #selector(editSelected))
        let remove = button("Remove", #selector(removeSelected))
        let importBtn = button("Import…", #selector(importFile))
        let stack = NSStackView(views: [add, edit, remove, importBtn])
        stack.orientation = .horizontal
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false

        let content = NSView()
        content.addSubview(scroll)
        content.addSubview(stack)
        window.contentView = content
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: content.topAnchor, constant: 12),
            scroll.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 12),
            scroll.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -12),
            stack.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 10),
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 12),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -12),
        ])
        window.center()
        reload()
    }

    func show() { window.makeKeyAndOrderFront(nil) }

    func reload() {
        profiles = loadProfiles()
        table.reloadData()
        onChange()
    }

    // Data source
    func numberOfRows(in tableView: NSTableView) -> Int { profiles.count }
    func tableView(_ t: NSTableView, viewFor col: NSTableColumn?, row: Int) -> NSView? {
        let id = NSUserInterfaceItemIdentifier("cell")
        let cell = (t.makeView(withIdentifier: id, owner: self) as? NSTableCellView) ?? {
            let c = NSTableCellView()
            let tf = NSTextField(labelWithString: "")
            tf.translatesAutoresizingMaskIntoConstraints = false
            c.addSubview(tf); c.textField = tf
            NSLayoutConstraint.activate([
                tf.leadingAnchor.constraint(equalTo: c.leadingAnchor, constant: 4),
                tf.centerYAnchor.constraint(equalTo: c.centerYAnchor),
            ])
            c.identifier = id
            return c
        }()
        let p = profiles[row]
        cell.textField?.stringValue = "\(p.name)   —   \(p.gateway)"
        return cell
    }

    // Buttons
    @objc func addNew() { onEdit(nil) }
    @objc func editSelected() {
        guard table.selectedRow >= 0 else { return }
        onEdit(profiles[table.selectedRow])
    }
    @objc func removeSelected() {
        guard table.selectedRow >= 0 else { return }
        let p = profiles[table.selectedRow]
        let a = NSAlert()
        a.messageText = "Remove “\(p.name)”?"
        a.informativeText = "This deletes the profile and its Keychain secrets."
        a.addButton(withTitle: "Remove")
        a.addButton(withTitle: "Cancel")
        if a.runModal() == .alertFirstButtonReturn {
            removeProfile(p)
            reload()
        }
    }
    @objc func importFile() {
        let panel = NSOpenPanel()
        panel.allowsOtherFileTypes = true
        panel.allowedContentTypes = ["pcf", "conf", "txt"].compactMap { UTType(filenameExtension: $0) }
        guard panel.runModal() == .OK, let url = panel.url,
              let parsed = parseConfigFile(url.path) else { return }
        upsert(parsed.profile, secret: parsed.secret, password: parsed.password)
        reload()
    }

}

// MARK: - About window (app info + Uninstall)

final class AboutWindow: NSObject {
    let window: NSWindow

    override init() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 420, height: 360),
                          styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "About VpncBar"
        window.isReleasedWhenClosed = false
        super.init()

        func label(_ s: String, _ size: CGFloat, bold: Bool = false,
                   color: NSColor = .labelColor, width: CGFloat? = nil) -> NSTextField {
            let f = NSTextField(labelWithString: s)
            f.font = bold ? .boldSystemFont(ofSize: size) : .systemFont(ofSize: size)
            f.textColor = color
            f.alignment = .center
            f.maximumNumberOfLines = 0
            f.lineBreakMode = .byWordWrapping
            if let w = width {
                f.preferredMaxLayoutWidth = w
                f.widthAnchor.constraint(equalToConstant: w).isActive = true
            }
            return f
        }
        let version = (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "1.0"
        let vpncVer = run(kVpnc, ["--version"]).out.split(separator: "\n").first.map(String.init)
            ?? "vpnc (version unknown)"
        let ocVer = openconnectPath().map {
            run($0, ["--version"]).out.split(separator: "\n").first.map(String.init) ?? "openconnect"
        } ?? "openconnect: not installed (brew install openconnect)"

        let icon = NSImageView()
        icon.image = NSApp.applicationIconImage
        icon.translatesAutoresizingMaskIntoConstraints = false

        let link = NSButton(title: "github.com/bouncyball-git/vpncbar", target: self, action: #selector(openRepo))
        link.isBordered = false
        link.contentTintColor = .linkColor
        link.font = .systemFont(ofSize: 12)

        let uninstall = NSButton(title: "Uninstall VpncBar…", target: self, action: #selector(uninstallTapped))
        uninstall.bezelStyle = .rounded

        let vpncLine = label("Bundled \(vpncVer)  ·  GPLv2", 11, color: .secondaryLabelColor, width: 300)
        let ocLine = label("\(ocVer)  ·  LGPLv2.1", 11, color: .secondaryLabelColor, width: 300)
        let stack = NSStackView(views: [
            icon,
            label("VpncBar", 22, bold: true),
            label("Version \(version)", 12, color: .secondaryLabelColor),
            label("A native macOS menu-bar front-end for vpnc (Cisco IPSec) and openconnect (Cisco AnyConnect SSL).", 12, width: 300),
            vpncLine,
            ocLine,
            link,
            uninstall,
        ])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.setCustomSpacing(1, after: vpncLine)   // keep the two backend rows together

        let content = NSView()
        content.addSubview(stack)
        window.contentView = content
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 24),
            stack.centerXAnchor.constraint(equalTo: content.centerXAnchor),
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: content.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -16),
            icon.widthAnchor.constraint(equalToConstant: 64),
            icon.heightAnchor.constraint(equalToConstant: 64),
        ])
        window.center()
    }

    func show() { window.makeKeyAndOrderFront(nil) }

    @objc private func openRepo() {
        if let u = URL(string: "https://github.com/bouncyball-git/vpncbar") { NSWorkspace.shared.open(u) }
    }

    @objc private func uninstallTapped() {
        let uninstaller = "/opt/vpncbar/uninstall.sh"
        guard FileManager.default.isExecutableFile(atPath: uninstaller) else {
            alert("VpncBar doesn't look installed — \(uninstaller) is missing.\nRun ./uninstall.sh from the source tree instead.")
            return
        }
        let a = NSAlert()
        a.alertStyle = .warning
        a.messageText = "Uninstall VpncBar?"
        a.informativeText = "This disconnects all tunnels and removes VpncBar.app (from /Applications), /opt/vpncbar, and the sudoers rule. Your saved profiles and Keychain secrets are kept."
        a.addButton(withTitle: "Uninstall")
        a.addButton(withTitle: "Cancel")
        NSApp.activate(ignoringOtherApps: true)
        guard a.runModal() == .alertFirstButtonReturn else { return }

        // Spawn a DETACHED root helper (macOS auth prompt) that first waits for this
        // app to fully quit, THEN runs the uninstaller — so the .app isn't running
        // when it's removed. We then quit the app, which lets the helper proceed.
        let helper = "(while /usr/bin/pgrep -x VpncBar >/dev/null 2>&1; do sleep 0.3; done; "
                   + "\(uninstaller)) </dev/null >/tmp/vpncbar-uninstall.log 2>&1 &"
        let cmd = "do shell script \"\(helper)\" with administrator privileges"
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", cmd]
        p.terminationHandler = { proc in
            if proc.terminationStatus == 0 {   // only quit if the user authenticated
                DispatchQueue.main.async { NSApp.terminate(nil) }
            }
        }
        do { try p.run() } catch { alert("Couldn't start the uninstaller: \(error.localizedDescription)") }
    }
}

// MARK: - Profile editor sheet

/// A button that shows the standard arrow cursor instead of inheriting the I-beam
/// cursor rect of the text field it's overlaid on.
final class ArrowButton: NSButton {
    override func resetCursorRects() { addCursorRect(bounds, cursor: .arrow) }
}

/// A password field with an eye toggle to reveal/hide the value. Internally swaps
/// a masked NSSecureTextField with a plain NSTextField, keeping their value in sync.
final class RevealableSecureField: NSView {
    private let secure = NSSecureTextField()
    private let plain = NSTextField()
    private let eye = ArrowButton()
    private var revealed = false

    var stringValue: String {
        get { revealed ? plain.stringValue : secure.stringValue }
        set { secure.stringValue = newValue; plain.stringValue = newValue }
    }
    var placeholderString: String? {
        get { secure.placeholderString }
        set { secure.placeholderString = newValue; plain.placeholderString = newValue }
    }
    var isEnabled: Bool = true {
        didSet { secure.isEnabled = isEnabled; plain.isEnabled = isEnabled; eye.isEnabled = isEnabled }
    }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        for f in [secure, plain] { f.translatesAutoresizingMaskIntoConstraints = false }
        plain.isHidden = true
        eye.translatesAutoresizingMaskIntoConstraints = false
        eye.isBordered = false
        eye.bezelStyle = .regularSquare
        eye.setButtonType(.momentaryChange)
        eye.imagePosition = .imageOnly
        eye.image = NSImage(systemSymbolName: "eye", accessibilityDescription: "Show")
        eye.contentTintColor = .secondaryLabelColor
        eye.refusesFirstResponder = true
        eye.target = self
        eye.action = #selector(toggle)
        // Fields fill the width; the eye is overlaid INSIDE the field's right edge
        // (added last so it sits on top and receives the click).
        addSubview(secure); addSubview(plain); addSubview(eye)
        NSLayoutConstraint.activate([
            secure.leadingAnchor.constraint(equalTo: leadingAnchor),
            secure.trailingAnchor.constraint(equalTo: trailingAnchor),
            secure.centerYAnchor.constraint(equalTo: centerYAnchor),
            plain.leadingAnchor.constraint(equalTo: leadingAnchor),
            plain.trailingAnchor.constraint(equalTo: trailingAnchor),
            plain.centerYAnchor.constraint(equalTo: centerYAnchor),
            eye.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -5),
            eye.centerYAnchor.constraint(equalTo: centerYAnchor),
            eye.widthAnchor.constraint(equalToConstant: 18),
            eye.heightAnchor.constraint(equalToConstant: 16),
            heightAnchor.constraint(equalToConstant: 22),
        ])
    }
    required init?(coder: NSCoder) { fatalError() }

    @objc private func toggle() {
        if revealed { secure.stringValue = plain.stringValue } else { plain.stringValue = secure.stringValue }
        revealed.toggle()
        secure.isHidden = revealed
        plain.isHidden = !revealed
        eye.image = NSImage(systemSymbolName: revealed ? "eye.slash" : "eye", accessibilityDescription: nil)
    }
}

final class ProfileEditor: NSObject, NSWindowDelegate, NSTabViewDelegate {
    let window: NSWindow
    let statsTextView = NSTextView()
    let debugTextView = NSTextView()
    private var refreshTimer: Timer?
    private var debugTimer: Timer?   // fast (~0.25s) tail, runs only while Debug tab is visible
    private let tabs = NSTabView()
    private var optionsTabItem: NSTabViewItem?     // vpnc Options
    private var ocOptionsTabItem: NSTabViewItem?   // openconnect Options
    private var infoTabItem: NSTabViewItem?
    private var debugTabItem: NSTabViewItem?
    private var credsGrid: NSGridView?   // for showing/hiding rows by backend type
    private var groupOTP: [String: Bool] = [:]   // fetched group → needs one-time code
    let typePopup = NSPopUpButton()      // vpnc | openconnect
    let nameField = NSTextField()
    let gatewayField = NSTextField()
    let idField = NSTextField()
    let authgroupField = NSComboBox()    // openconnect --authgroup (dropdown if fetched, else manual)
    let fetchGroupsButton = NSButton(title: "Fetch groups", target: nil, action: nil)
    let serverCertField = NSTextField()  // openconnect --servercert pin
    let advancedCheck = NSButton(checkboxWithTitle: "Advanced", target: nil, action: nil)  // openconnect: reveal cert fields
    let userField = NSTextField()
    let secretField = RevealableSecureField()
    let passwordField = RevealableSecureField()
    let authmodePopup = NSPopUpButton()
    let dhPopup = NSPopUpButton()
    let pfsPopup = NSPopUpButton()
    let nattPopup = NSPopUpButton()
    let vendorPopup = NSPopUpButton()
    let debugPopup = NSPopUpButton()
    let dnsField = NSTextField()
    let caFileField = NSTextField()
    let clientCertField = NSTextField()
    let secretLabel = NSTextField(labelWithString: "Group secret")
    let caFileLabel = NSTextField(labelWithString: "CA file")
    let clientCertLabel = NSTextField(labelWithString: "Client cert")
    let authNote = NSTextField(labelWithString: "")
    let mtuField = NSTextField()
    let dpdField = NSTextField()
    // openconnect Options tab
    let ocProtocolPopup = NSPopUpButton()
    let ocNoDTLSCheck = NSButton(checkboxWithTitle: "Disable DTLS", target: nil, action: nil)
    let ocDPDField = NSTextField()
    let ocMTUField = NSTextField()
    let ocReconnectField = NSTextField()
    let ocDebugPopup = NSPopUpButton()
    let weakCheck = NSButton(checkboxWithTitle: "Enable weak encryption (3DES)", target: nil, action: nil)
    let singleDESCheck = NSButton(checkboxWithTitle: "Enable single DES", target: nil, action: nil)
    let noEncCheck = NSButton(checkboxWithTitle: "Enable no encryption", target: nil, action: nil)
    let weakAuthCheck = NSButton(checkboxWithTitle: "Enable weak authentication", target: nil, action: nil)
    let onSave: (Profile, String?, String?) -> Void
    let existing: Profile?
    var onClose: (() -> Void)?   // registry uses this to drop its entry on close
    private let toggleButton = NSButton(title: "Connect", target: nil, action: nil)
    private var toggling = false   // suppress live title updates during a connect/disconnect
    private var transition: String?   // "Connecting…"/"Disconnecting…" shown in the Status row while in flight
    private var transitionDeadline = Date.distantPast   // safety timeout for a stuck transition
    private var cachedBody: String?   // last-known info rows, kept visible through teardown

    init(profile: Profile?, onSave: @escaping (Profile, String?, String?) -> Void) {
        self.onSave = onSave
        self.existing = profile
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 410, height: 510),
                          styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = profile == nil ? "Add VPN" : "Edit VPN"
        window.isReleasedWhenClosed = false   // we retain it; let ARC free it
        super.init()
        window.delegate = self

        nameField.stringValue = profile?.name ?? ""
        gatewayField.stringValue = profile?.gateway ?? ""
        idField.stringValue = profile?.id ?? ""
        // Username may carry a domain as "DOMAIN\user". Fold any legacy separate
        // domain back into the field so old profiles display correctly.
        if let d = ne(profile?.domain) {
            userField.stringValue = "\(d)\\\(profile?.username ?? "")"
        } else {
            userField.stringValue = profile?.username ?? ""
        }
        // Prefill stored secrets so a configured field shows dots ("••••"); the eye reveals them.
        secretField.stringValue = profile.flatMap { keychainSecret(kcService($0, "secret")) } ?? ""
        passwordField.stringValue = profile.flatMap { keychainSecret(kcService($0, "password")) } ?? ""
        secretField.placeholderString = "shared group secret"
        passwordField.placeholderString = "Xauth password"
        nameField.placeholderString = "work"
        gatewayField.placeholderString = "vpn.example.com"
        idField.placeholderString = "group name"
        userField.placeholderString = "user  or  DOMAIN\\user"
        dnsField.stringValue = profile?.dnsMatchDomains ?? ""
        dnsField.placeholderString = "example.com, ..."
        caFileField.stringValue = profile?.caFile ?? ""
        caFileField.placeholderString = "/path/to/ca.pem"
        clientCertField.stringValue = profile?.clientCert ?? ""
        clientCertField.placeholderString = "/path/to/client.pem"
        authgroupField.stringValue = profile?.ocAuthgroup ?? ""
        authgroupField.placeholderString = "auth group (type, or Fetch)"
        authgroupField.completes = true
        fetchGroupsButton.bezelStyle = .rounded
        fetchGroupsButton.target = self
        fetchGroupsButton.action = #selector(fetchGroups)
        serverCertField.stringValue = profile?.ocServerCert ?? ""
        serverCertField.placeholderString = "(optional) pin-sha256:…"
        // Seed groupOTP from the saved profile so a re-opened editor (no Fetch yet)
        // still knows whether the persisted Auth group needs a one-time code.
        if let g = ne(profile?.ocAuthgroup), let otp = profile?.ocOtp { groupOTP[g] = otp }
        // openconnect: hide the rarely-used cert fields behind "Advanced", but expand
        // it automatically if this profile already has a server-cert pin or client cert.
        advancedCheck.state = (ne(profile?.ocServerCert) != nil || ne(profile?.clientCert) != nil) ? .on : .off
        advancedCheck.target = self
        advancedCheck.action = #selector(advancedChanged)
        authNote.font = .systemFont(ofSize: 11)
        authNote.textColor = .systemOrange
        authNote.maximumNumberOfLines = 2
        authNote.lineBreakMode = .byWordWrapping
        mtuField.stringValue = profile?.mtu ?? ""
        mtuField.placeholderString = "automatic"
        dpdField.stringValue = profile?.dpdTimeout ?? "30"   // seconds

        // Show real values (no "(default)" sentinel); pre-select vpnc's actual default.
        func fill(_ p: NSPopUpButton, _ items: [String], _ value: String?, _ def: String) {
            p.removeAllItems()
            p.addItems(withTitles: items)
            p.selectItem(withTitle: (value.flatMap { items.contains($0) ? $0 : nil }) ?? def)
        }
        fill(typePopup, ["vpnc", "openconnect"], profile?.kind, "vpnc")
        typePopup.target = self
        typePopup.action = #selector(typeChanged)
        typePopup.isEnabled = (profile == nil)   // backend is fixed once the profile exists

        // openconnect Options — pre-filled with openconnect's real defaults.
        fill(ocProtocolPopup, ["anyconnect", "nc", "gp", "pulse", "f5", "fortinet", "array"],
             profile?.ocProtocol, "anyconnect")
        fill(ocDebugPopup, ["0", "1", "2", "3", "99"], profile?.ocDebug, "1")
        ocNoDTLSCheck.state = (profile?.ocNoDTLS ?? false) ? .on : .off
        ocDPDField.stringValue = profile?.ocDPD ?? ""
        ocDPDField.placeholderString = "automatic"
        ocMTUField.stringValue = profile?.ocMTU ?? ""
        ocMTUField.placeholderString = "automatic"
        ocReconnectField.stringValue = profile?.ocReconnect ?? "300"   // openconnect default (seconds)
        fill(authmodePopup, ["psk", "cert", "hybrid"], profile?.authmode, "psk")
        fill(dhPopup, ["dh1", "dh2", "dh5", "dh14", "dh15", "dh16", "dh17", "dh18"], profile?.dhGroup, "dh2")
        fill(pfsPopup, ["nopfs", "dh1", "dh2", "dh5", "dh14", "dh15", "dh16", "dh17", "dh18", "server"], profile?.pfs, "server")
        fill(nattPopup, ["natt", "none", "force-natt", "cisco-udp"], profile?.natMode, "natt")
        fill(vendorPopup, ["cisco", "netscreen", "fortigate"], profile?.vendor, "cisco")
        fill(debugPopup, ["0", "1", "2", "3", "99"], profile?.debug, "0")
        authmodePopup.target = self
        authmodePopup.action = #selector(authModeChanged)

        weakCheck.state = (profile?.enableWeak ?? true) ? .on : .off    // 3DES on by default
        singleDESCheck.state = (profile?.singleDES ?? false) ? .on : .off
        noEncCheck.state = (profile?.noEncryption ?? false) ? .on : .off
        weakAuthCheck.state = (profile?.weakAuth ?? false) ? .on : .off

        let encStack = NSStackView(views: [weakCheck, singleDESCheck, noEncCheck, weakAuthCheck])
        encStack.orientation = .vertical
        encStack.alignment = .leading
        encStack.spacing = 4

        func label(_ s: String) -> NSTextField { NSTextField(labelWithString: s) }
        func grid(_ rows: [[NSView]]) -> NSGridView {
            let g = NSGridView(views: rows)
            g.column(at: 0).xPlacement = .trailing
            g.rowSpacing = 8
            g.columnSpacing = 10
            // Center each label with its control (default is first-baseline, which
            // floats labels above taller controls like pop-ups).
            for r in 0..<g.numberOfRows { g.row(at: r).yPlacement = .center }
            g.translatesAutoresizingMaskIntoConstraints = false
            return g
        }
        let credsGrid = grid([
            [label("Type"), typePopup],
            [label("Name"), nameField],
            [label("Gateway"), gatewayField],
            [label("Group name"), idField],          // vpnc only
            [secretLabel, secretField],              // vpnc only
            [label("Auth group"), authgroupField],   // openconnect only
            [label(""), fetchGroupsButton],          // openconnect only
            [label("Username"), userField],
            [label("Password"), passwordField],
            [label("VPN domains"), dnsField],
            [label("IKE Authmode"), authmodePopup],  // vpnc only
            [label(""), advancedCheck],              // openconnect only — last everyday option
            [caFileLabel, caFileField],              // vpnc only
            [label("Server cert"), serverCertField], // openconnect only — Advanced
            [clientCertLabel, clientCertField],      // vpnc (cert mode) / openconnect (Advanced)
            [label(""), authNote],                   // vpnc only
        ])
        self.credsGrid = credsGrid
        // Pin the label column to the widest label across ALL rows, so hiding/showing
        // rows per backend doesn't change its width (which would slide the fields).
        let labelFont = NSFont.systemFont(ofSize: NSFont.systemFontSize)
        let widest = ["Type", "Name", "Gateway", "Group name", "Group secret", "Auth group",
                      "Server cert", "Username", "Password", "VPN domains", "IKE Authmode",
                      "CA file", "Client cert"]
            .map { ($0 as NSString).size(withAttributes: [.font: labelFont]).width }.max() ?? 90
        credsGrid.column(at: 0).width = ceil(widest) + 2

        let optionsGrid = grid([
            [label("DH Group"), dhPopup],
            [label("PFS"), pfsPopup],
            [label("NAT-T Mode"), nattPopup],
            [label("Vendor"), vendorPopup],
            [label("Interface MTU"), mtuField],
            [label("DPD timeout"), dpdField],
            [label("Debug level"), debugPopup],
            [label("Encryption"), encStack],
        ])

        let ocOptionsGrid = grid([
            [label("Protocol"), ocProtocolPopup],
            [label("Transport"), ocNoDTLSCheck],
            [label("DPD"), ocDPDField],
            [label("Interface MTU"), ocMTUField],
            [label("Reconnect"), ocReconnectField],
            [label("Debug level"), ocDebugPopup],
        ])

        let fixedWidth: [NSView] = [nameField, gatewayField, idField, userField, secretField,
            passwordField, dnsField, caFileField, clientCertField, authNote, mtuField, dpdField,
            authmodePopup, dhPopup, pfsPopup, nattPopup, vendorPopup, debugPopup,
            typePopup, authgroupField, serverCertField,
            ocProtocolPopup, ocDPDField, ocMTUField, ocReconnectField, ocDebugPopup]
        for v in fixedWidth {
            v.translatesAutoresizingMaskIntoConstraints = false
            v.widthAnchor.constraint(equalToConstant: 240).isActive = true
        }

        // Each grid sits top-left inside a tab's view.
        func tab(_ g: NSGridView, _ title: String) -> NSTabViewItem {
            let v = NSView()
            v.addSubview(g)
            NSLayoutConstraint.activate([
                g.topAnchor.constraint(equalTo: v.topAnchor, constant: 16),
                g.leadingAnchor.constraint(equalTo: v.leadingAnchor, constant: 16),
            ])
            let item = NSTabViewItem()
            item.label = title
            item.view = v
            return item
        }
        tabs.translatesAutoresizingMaskIntoConstraints = false
        tabs.delegate = self
        tabs.addTabViewItem(tab(credsGrid, "Credentials"))
        optionsTabItem = tab(optionsGrid, "Options")        // vpnc
        ocOptionsTabItem = tab(ocOptionsGrid, "Options")    // openconnect
        tabs.addTabViewItem(optionsTabItem!)                // typeChanged() swaps the right one in
        let info = statsTab(); infoTabItem = info
        tabs.addTabViewItem(info)
        let dbg = debugTab(); debugTabItem = dbg
        tabs.addTabViewItem(dbg)

        let save = NSButton(title: "Save", target: self, action: #selector(saveTapped))
        save.bezelStyle = .rounded
        save.keyEquivalent = "\r"
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancelTapped))
        cancel.bezelStyle = .rounded
        cancel.keyEquivalent = "\u{1b}"
        toggleButton.bezelStyle = .rounded
        toggleButton.target = self
        toggleButton.action = #selector(toggleTapped)
        updateToggleTitle()   // initial Connect/Disconnect label (disabled for unsaved new profile)
        let buttons = NSStackView(views: [toggleButton, cancel, save])
        buttons.spacing = 8
        buttons.translatesAutoresizingMaskIntoConstraints = false

        let content = NSView()
        content.addSubview(tabs)
        content.addSubview(buttons)
        window.contentView = content
        NSLayoutConstraint.activate([
            tabs.topAnchor.constraint(equalTo: content.topAnchor, constant: 12),
            tabs.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 12),
            tabs.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -12),
            buttons.topAnchor.constraint(equalTo: tabs.bottomAnchor, constant: 12),
            buttons.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -12),
            buttons.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -12),
        ])
        typeChanged()       // show/hide rows for the backend, then set auth-field state

        // Info tab refreshes live (cheap). Debug only refreshes while its tab is
        // visible (the system-log query is slow) — loaded on selection + throttled.
        refreshTick()
        let t = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in self?.refreshTick() }
        RunLoop.main.add(t, forMode: .common)
        refreshTimer = t
    }

    func windowWillClose(_ notification: Notification) {
        refreshTimer?.invalidate()
        refreshTimer = nil
        stopDebugPolling()
        onClose?()
    }

    // A read-only, scrolled NSTextView used by both the Stats and Debug tabs.
    private func makeTextScroll(_ tv: NSTextView, monospaced: Bool) -> NSScrollView {
        tv.isEditable = false
        tv.isRichText = false
        tv.drawsBackground = true
        tv.font = monospaced ? .monospacedSystemFont(ofSize: 11, weight: .regular)
                             : .monospacedSystemFont(ofSize: 12, weight: .regular)
        tv.textContainerInset = NSSize(width: 6, height: 6)
        tv.minSize = NSSize(width: 0, height: 0)
        tv.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        tv.isVerticallyResizable = true
        tv.isHorizontallyResizable = false
        tv.autoresizingMask = [.width]
        tv.textContainer?.widthTracksTextView = true
        tv.textContainer?.containerSize = NSSize(width: 0, height: CGFloat.greatestFiniteMagnitude)
        let sv = NSScrollView()
        sv.documentView = tv
        sv.hasVerticalScroller = true
        sv.borderType = .bezelBorder
        sv.translatesAutoresizingMaskIntoConstraints = false
        return sv
    }

    private func statsTab() -> NSTabViewItem {
        let sv = makeTextScroll(statsTextView, monospaced: true)
        let v = NSView()
        v.addSubview(sv)
        NSLayoutConstraint.activate([
            sv.topAnchor.constraint(equalTo: v.topAnchor, constant: 12),
            sv.leadingAnchor.constraint(equalTo: v.leadingAnchor, constant: 12),
            sv.trailingAnchor.constraint(equalTo: v.trailingAnchor, constant: -12),
            sv.bottomAnchor.constraint(equalTo: v.bottomAnchor, constant: -12),
        ])
        let item = NSTabViewItem(); item.label = "Info"; item.view = v
        return item
    }

    private func debugTab() -> NSTabViewItem {
        let sv = makeTextScroll(debugTextView, monospaced: true)
        let clear = NSButton(title: "Clear log", target: self, action: #selector(clearLog))
        let reveal = NSButton(title: "Reveal log", target: self, action: #selector(revealLog))
        for b in [clear, reveal] { b.bezelStyle = .rounded }
        let bar = NSStackView(views: [clear, reveal])
        bar.spacing = 8
        bar.translatesAutoresizingMaskIntoConstraints = false
        let v = NSView()
        v.addSubview(sv); v.addSubview(bar)
        NSLayoutConstraint.activate([
            sv.topAnchor.constraint(equalTo: v.topAnchor, constant: 12),
            sv.leadingAnchor.constraint(equalTo: v.leadingAnchor, constant: 12),
            sv.trailingAnchor.constraint(equalTo: v.trailingAnchor, constant: -12),
            bar.topAnchor.constraint(equalTo: sv.bottomAnchor, constant: 8),
            bar.leadingAnchor.constraint(equalTo: v.leadingAnchor, constant: 12),
            bar.bottomAnchor.constraint(equalTo: v.bottomAnchor, constant: -12),
        ])
        let item = NSTabViewItem(); item.label = "Debug"; item.view = v
        return item
    }

    // Runs on the 1s timer, but only refreshes a tab while it's actually visible
    // (both reads are cheap now: a `ps` for Info, a file read for Debug).
    @objc func refreshTick() {
        advanceTransition()                     // end Connecting…/Disconnecting… when state flips
        if !toggling { updateToggleTitle() }    // keep the button label in sync with live state
        if tabs.selectedTabViewItem === infoTabItem { refreshStats() }
        // Debug has its own fast timer (started when its tab is shown), so it's not here.
    }

    // Clear the in-flight transition only once the live state reaches the target
    // (or a safety timeout) — so Status/button never flicker back through the stale
    // state while vpnc is still actually coming up or tearing down.
    private func advanceTransition() {
        guard let p = existing, let tr = transition else { return }
        let up = !connectedTunnels([p]).isEmpty
        let reached = (tr == "Connecting…" && up) || (tr == "Disconnecting…" && !up)
        if reached || Date() >= transitionDeadline {
            transition = nil
            toggling = false
        }
    }

    // Connect/Disconnect label reflects live state; disabled for an unsaved new profile.
    private func updateToggleTitle() {
        guard let p = existing else {
            toggleButton.isEnabled = false
            toggleButton.title = "Connect"
            return
        }
        toggleButton.isEnabled = true
        toggleButton.title = connectedTunnels([p]).isEmpty ? "Connect" : "Disconnect"
    }

    @objc private func toggleTapped() {
        guard let p = existing else { return }
        let connected = !connectedTunnels([p]).isEmpty
        // 2FA openconnect: gather the one-time code (main thread) before connecting.
        var otp: String? = nil
        if !connected && isOpenconnect(p) && needsOtp() {
            guard let code = promptOTP(p) else { return }   // cancelled
            otp = code
        }
        toggling = true
        transition = connected ? "Disconnecting…" : "Connecting…"   // shown in Status row
        transitionDeadline = Date().addingTimeInterval(20)
        toggleButton.isEnabled = false   // keep its Connect/Disconnect label, just block re-clicks
        refreshStats()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = connected ? disconnect(p) : connect(p, otp: otp)
            DispatchQueue.main.async {
                guard let self = self else { return }
                // On failure, end the transition now and report. On success, leave it:
                // advanceTransition() ends it once the OS state actually flips, so the
                // Status/button never snap back through the old state first.
                if case let .message(msg) = result {
                    self.transition = nil
                    self.toggling = false
                    self.updateToggleTitle()
                    self.refreshStats()
                    alert(msg)
                }
            }
        }
    }

    private func refreshStats() {
        let stats = buildStatsText()
        if statsTextView.string != stats { statsTextView.string = stats }
    }

    // Refresh the just-shown tab immediately, so you don't wait for the next tick.
    func tabView(_ tabView: NSTabView, didSelect tabViewItem: NSTabViewItem?) {
        if tabViewItem === debugTabItem {
            startDebugPolling()
        } else {
            stopDebugPolling()
            if tabViewItem === infoTabItem { refreshStats() }
        }
    }

    // Near-real-time tail while the Debug tab is visible; cheap (local file read).
    private func startDebugPolling() {
        stopDebugPolling()
        reloadDebug()
        let t = Timer(timeInterval: 0.25, repeats: true) { [weak self] _ in self?.reloadDebug() }
        RunLoop.main.add(t, forMode: .common)
        debugTimer = t
    }

    private func stopDebugPolling() {
        debugTimer?.invalidate()
        debugTimer = nil
    }

    // Tail the per-profile vpnc log file. Cheap (a file read), so it can run every
    // tick; only updates the view when the text changed, keeping the scroll position
    // unless already at the bottom (then auto-scrolls like tail -f).
    @objc func reloadDebug() {
        let text = ProfileEditor.buildDebugText(existing)
        guard debugTextView.string != text else { return }
        let atBottom = debugAtBottom()
        debugTextView.string = text
        if atBottom { debugTextView.scrollToEndOfDocument(nil) }
    }

    private func debugAtBottom() -> Bool {
        guard let sv = debugTextView.enclosingScrollView else { return true }
        return sv.contentView.bounds.maxY >= debugTextView.frame.height - 12
    }

    // Truncate the log in place (non-atomic = same inode), so a live vpnc daemon
    // keeps writing to it. Falls back to unlink for any legacy root-owned file we
    // can't truncate (the next connect recreates it user-owned).
    @objc private func clearLog() {
        guard let p = existing else { return }
        let url = URL(fileURLWithPath: logFile(p))
        do { try Data().write(to: url) }
        catch { try? FileManager.default.removeItem(atPath: logFile(p)) }
        reloadDebug()
    }

    @objc private func revealLog() {
        guard let p = existing else { return }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: logFile(p))])
    }


    private func buildStatsText() -> String {
        guard let p = existing else {
            return "Save this profile first, then connect to see live tunnel stats."
        }
        func row(_ k: String, _ value: String) -> String {
            k.padding(toLength: 15, withPad: " ", startingAt: 0) + value + "\n"
        }
        // Connecting: there's no tunnel data yet, so just the status.
        if transition == "Connecting…" { return row("Status:", "Connecting…") }

        // Live tunnel: build the info rows and cache them so they survive teardown.
        if let c = connectedTunnels([p])[p.name] {
            let t = readTunnelInfo(p)
            var body = row("Uptime:", formatElapsed(c.secs))
            if let v = t.iface { body += row("Interface:", v) }
            if let iface = t.iface, let cnt = interfaceCounters(iface) {
                body += row("Traffic in:", "\(humanBytes(cnt.rxBytes))  (\(grouped(cnt.rxPkts)) pkts)")
                body += row("Traffic out:", "\(humanBytes(cnt.txBytes))  (\(grouped(cnt.txPkts)) pkts)")
            }
            body += "\n"   // blank line after Traffic out
            if let v = t.internalIP { body += row("Internal IP:", v) }
            if let v = t.gateway { body += row("Gateway:", v) }
            if let v = t.dns, !v.isEmpty {
                body += row("DNS:", v.split(separator: " ").joined(separator: ", "))
            }
            // Match domains: gateway-supplied + the profile's, de-duplicated, in order.
            let allDomains = [t.defDomain, t.splitDNS, t.matchDomains]
                .compactMap { $0 }.joined(separator: " ")
                .split(separator: " ").map(String.init)
            var seen = Set<String>(); var domains: [String] = []
            for d in allDomains where seen.insert(d).inserted { domains.append(d) }
            if !domains.isEmpty { body += row("Match domains:", domains.joined(separator: ", ")) }
            if let first = t.routes.first {
                body += row("Routes:", first)
                for r in t.routes.dropFirst() { body += row("", r) }
            }
            body += "\nCommand (PID \(c.pid)):\n\(vpncCommandLine(p))\n"
            cachedBody = body
            return row("Status:", transition ?? "Connected") + body
        }
        // Process already gone but disconnect still in flight: keep last-known info.
        if transition == "Disconnecting…", let body = cachedBody {
            return row("Status:", "Disconnecting…") + body
        }
        // Fully disconnected: clear everything.
        cachedBody = nil
        return row("Status:", "Not connected")
    }

    // vpnc writes the whole session (handshake, debug, start/stop) to logFile(p) via
    // --log-file, truncated per connect — so the Debug tab just tails that file.
    static func buildDebugText(_ p: Profile?) -> String {
        guard let p = p else { return "Save this profile first, then connect to see logs." }
        guard let raw = try? String(contentsOfFile: logFile(p), encoding: .utf8),
              !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return "No connection logged for “\(p.name)” yet."
        }
        // Cap very large (level-99) logs to the most recent ~256 KB.
        let maxBytes = 262_144
        if raw.utf8.count > maxBytes {
            return "…(earlier output truncated)…\n" + String(raw.suffix(maxBytes))
        }
        return raw
    }

    // Show only the rows relevant to the chosen backend. vpnc: Group name/secret,
    // IKE Authmode, CA file. openconnect: Auth group, Server cert. Shared: Name,
    // Gateway, Username, Password, VPN domains, Client cert.
    @objc func typeChanged() {
        let oc = typePopup.titleOfSelectedItem == "openconnect"
        let adv = oc && (advancedCheck.state == .on)   // openconnect cert fields revealed
        func setRowHidden(_ v: NSView, _ hidden: Bool) { credsGrid?.cell(for: v)?.row?.isHidden = hidden }
        for v in [idField, secretField, authmodePopup, caFileField, authNote] { setRowHidden(v, oc) }
        for v in [authgroupField, fetchGroupsButton, advancedCheck] { setRowHidden(v, !oc) }
        // openconnect cert fields live under "Advanced". Client cert is shared: vpnc
        // always shows it (authmode-reactive); openconnect shows it only when Advanced.
        setRowHidden(serverCertField, !adv)
        setRowHidden(clientCertField, oc && !adv)
        // Each backend has its own Options tab — show the matching one (at index 1).
        if let vpncOpts = optionsTabItem, let ocOpts = ocOptionsTabItem {
            let want = oc ? ocOpts : vpncOpts
            let drop = oc ? vpncOpts : ocOpts
            if tabs.tabViewItems.contains(drop) { tabs.removeTabViewItem(drop) }
            if !tabs.tabViewItems.contains(want) { tabs.insertTabViewItem(want, at: 1) }
        }
        if !oc { authModeChanged() }   // restore vpnc cert-field graying
    }

    @objc func advancedChanged() { typeChanged() }   // re-evaluate which rows show

    // Wizard: one fetch gets the gateway's group list AND each group's 2FA flag.
    // Fills the dropdown and remembers which groups need a one-time code. Manual
    // entry still works if nothing comes back.
    @objc func fetchGroups() {
        let server = gatewayField.stringValue.trimmingCharacters(in: .whitespaces)
        guard !server.isEmpty else { alert("Enter the Gateway (server) first."); return }
        let pin = ne(serverCertField.stringValue)
        fetchGroupsButton.isEnabled = false
        fetchGroupsButton.title = "Fetching…"
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let probe = openconnectGroupList(server: server, serverCert: pin)
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.fetchGroupsButton.isEnabled = true
                self.fetchGroupsButton.title = "Fetch groups"
                // Trust-on-first-use: the gateway's cert isn't trusted by the system
                // (self-signed / private CA). Show the fingerprint and, on consent,
                // pin it into Server cert and retry — the pin is enforced thereafter.
                if let certPin = probe.certPin {
                    let a = NSAlert()
                    a.alertStyle = .warning
                    a.messageText = "Untrusted server certificate"
                    a.informativeText =
                        "The gateway “\(server)” presented a certificate the system doesn't trust "
                      + "(self-signed, or from a private CA).\n\nFingerprint:\n\(certPin)\n\n"
                      + "Trust and pin this certificate? It's saved to the profile and required on "
                      + "every future connection — you'll be warned if it ever changes."
                    a.addButton(withTitle: "Trust and pin")
                    a.addButton(withTitle: "Cancel")
                    if a.runModal() == .alertFirstButtonReturn {
                        self.serverCertField.stringValue = certPin
                        self.fetchGroups()   // retry — the pin now lets the probe through
                    }
                    return
                }
                guard !probe.groups.isEmpty else {
                    alert("Couldn't get a group list from \(server).\nType the Auth group manually."); return
                }
                self.groupOTP = Dictionary(probe.groups.map { ($0.group, $0.otp) }, uniquingKeysWith: { a, _ in a })
                let current = self.authgroupField.stringValue
                self.authgroupField.removeAllItems()
                self.authgroupField.addItems(withObjectValues: probe.groups.map { $0.group })
                if current.isEmpty, let first = probe.groups.first {
                    self.authgroupField.stringValue = first.group
                }
            }
        }
    }

    // Does the currently-selected openconnect group need a one-time code? Looks the
    // group up in the last Fetch groups result; for a group not fetched this session
    // (typed by hand, or the editor opened without fetching) falls back to the saved
    // ocOtp flag — which we also seed into groupOTP at load time.
    private func needsOtp() -> Bool {
        let g = authgroupField.stringValue.trimmingCharacters(in: .whitespaces)
        return groupOTP[g] ?? (existing?.ocOtp ?? false)
    }

    // React to the IKE Authmode selection: psk uses the Group secret; cert/hybrid
    // use the CA file. Whichever isn't relevant is grayed out. If this vpnc has no
    // TLS backend, cert/hybrid stay selectable but their fields are grayed and a
    // note explains why.
    @objc func authModeChanged() {
        let mode = authmodePopup.titleOfSelectedItem ?? "psk"
        let usesCert = (mode == "cert" || mode == "hybrid")
        let certOK = vpncSupportsCerts()
        // Field-enable matrix by auth mode:
        //   Group secret -> psk only          (PSK is not used by hybrid/cert)
        //   CA file      -> hybrid + cert      (verify the gateway's certificate)
        //   Client cert  -> cert only          (mutual cert auth)
        //   Username/Password (XAUTH) and Group name stay enabled in all modes.
        // A disabled NSTextField only dims its text faintly, which is easy to
        // miss — so also fade the field and its row label to ~35% opacity.
        func setRow(_ field: NSView, _ rowLabel: NSTextField, _ on: Bool) {
            let alpha: CGFloat = on ? 1.0 : 0.2
            field.alphaValue = alpha
            rowLabel.alphaValue = alpha
        }
        secretField.isEnabled = !usesCert
        caFileField.isEnabled = usesCert
        clientCertField.isEnabled = (mode == "cert")
        setRow(secretField, secretLabel, !usesCert)
        setRow(caFileField, caFileLabel, usesCert)
        setRow(clientCertField, clientCertLabel, mode == "cert")
        if usesCert && !certOK {
            authNote.stringValue = "This VPNC build has no certificate support.\nRebuild with GnuTLS to use \(mode) mode."
            authNote.isHidden = false
        } else {
            authNote.stringValue = ""
            authNote.isHidden = true
        }
    }

    @objc func saveTapped() {
        let oc = typePopup.titleOfSelectedItem == "openconnect"
        let name = nameField.stringValue.trimmingCharacters(in: .whitespaces)
        let gw = gatewayField.stringValue.trimmingCharacters(in: .whitespaces)
        let id = idField.stringValue.trimmingCharacters(in: .whitespaces)
        let user = userField.stringValue.trimmingCharacters(in: .whitespaces)
        // Group name is vpnc-only; openconnect needs only Name, Server, Username.
        if oc {
            guard !name.isEmpty, !gw.isEmpty, !user.isEmpty else {
                alert("Name, Server and Username are required.")
                return
            }
        } else {
            guard !name.isEmpty, !gw.isEmpty, !id.isEmpty, !user.isEmpty else {
                alert("Name, Gateway, Group name and Username are all required.")
                return
            }
        }
        func pv(_ p: NSPopUpButton) -> String? { p.titleOfSelectedItem }
        func tv(_ f: NSTextField) -> String? { ne(f.stringValue) }

        // ifmode stays nil (we always use native utun). The auto/rarely-needed
        // fields and any imported "extra" lines are preserved verbatim, just not
        // exposed in the editor.
        let p = Profile(
            uuid: existing?.uuid,   // keep identity on edit; upsert assigns one for a new profile
            name: name, gateway: gw, id: id, username: user,
            authmode: pv(authmodePopup), dhGroup: pv(dhPopup), pfs: pv(pfsPopup),
            natMode: pv(nattPopup), vendor: pv(vendorPopup), ifmode: nil,
            domain: nil, dnsMatchDomains: tv(dnsField), caFile: tv(caFileField),
            clientCert: tv(clientCertField),
            appVersion: existing?.appVersion, localAddr: existing?.localAddr,
            localPort: existing?.localPort, udpPort: existing?.udpPort, mtu: tv(mtuField),
            dpdTimeout: tv(dpdField), debug: pv(debugPopup),
            enableWeak: weakCheck.state == .on, singleDES: singleDESCheck.state == .on,
            noEncryption: noEncCheck.state == .on, weakAuth: weakAuthCheck.state == .on,
            extra: existing?.extra,
            kind: oc ? "openconnect" : "vpnc",
            ocAuthgroup: tv(authgroupField), ocServerCert: tv(serverCertField),
            ocOtp: (oc && needsOtp()) ? true : nil,
            ocProtocol: pv(ocProtocolPopup), ocNoDTLS: oc ? (ocNoDTLSCheck.state == .on) : nil,
            ocDPD: tv(ocDPDField), ocMTU: tv(ocMTUField),
            ocReconnect: tv(ocReconnectField), ocDebug: pv(ocDebugPopup))
        let secret = secretField.stringValue.isEmpty ? nil : secretField.stringValue
        let password = passwordField.stringValue.isEmpty ? nil : passwordField.stringValue
        onSave(p, secret, password)
        finish()
    }

    @objc func cancelTapped() { finish() }

    func finish() {
        if let sheetParent = window.sheetParent { sheetParent.endSheet(window) }
        else { window.close() }
    }
}

// MARK: - Launch

let app = NSApplication.shared
app.setActivationPolicy(.accessory)   // menu-bar only, no dock icon
let controller = AppController()
app.delegate = controller             // so applicationWillTerminate disconnects tunnels
controller.start()
app.run()
