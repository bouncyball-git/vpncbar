import AppKit
import Foundation
import UniformTypeIdentifiers
import UserNotifications

// MARK: - Paths

let kVpnc = "/opt/local/sbin/vpnc"
let kVpncDisconnect = "/opt/local/sbin/vpnc-disconnect"
let kCiscoDecrypt = "/opt/local/bin/cisco-decrypt"
let kSecurity = "/usr/bin/security"
let kSudo = "/usr/bin/sudo"
let kPgrep = "/usr/bin/pgrep"
let kPs = "/bin/ps"
let kVpncScript = "/opt/local/etc/vpnc/vpnc-script"   // matches the binary's built-in SCRIPT_PATH

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
}

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

// Elapsed seconds for a live vpnc with this pid, or nil if it isn't a running vpnc.
func vpncElapsed(pid: Int) -> Int? {
    let r = run(kPs, ["-p", "\(pid)", "-o", "comm=,etime="])
    guard r.status == 0 else { return nil }
    let line = r.out.trimmingCharacters(in: .whitespacesAndNewlines)
    guard line.contains("vpnc"), let etok = line.split(separator: " ").last else { return nil }
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
            guard line.contains("/vpnc"), let pf = line.range(of: "--pid-file ") else { continue }
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

func connect(_ p: Profile) -> ActionResult {
    // Safeguard: never launch a second vpnc for a profile that's already up
    // (a duplicate would fight over the same pidfile and re-resolve the gateway).
    if !connectedTunnels([p]).isEmpty { return .ok }

    guard let secret = keychainSecret(kcService(p, "secret")) else {
        return .message("Group secret not found in Keychain for “\(p.name)”.\nOpen Manage VPNs and set it.")
    }
    let password = keychainSecret(kcService(p, "password"))
    // The Username field may hold "DOMAIN\user"; send the domain via vpnc's
    // Domain directive and the bare user via Xauth username.
    let (xauthDomain, xauthUser) = splitDomainUser(p.username)
    var lines = [
        "IPSec gateway \(resolveGatewayIP(p.gateway))",
        "IPSec ID \(p.id)",
        "IPSec secret \(secret)",
        "IKE Authmode \(ne(p.authmode) ?? "psk")",
        "Xauth username \(xauthUser)",
    ]
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

    // Manual DNS match domains: pass them to the script via an env var prefix on
    // the "Script" command (vpnc runs it through /bin/sh, so the assignment sticks).
    // Sanitized to domain-safe chars; commas become spaces. Empty => not added.
    if let raw = ne(p.dnsMatchDomains) {
        let domains = String(raw.map { ", ".contains($0) ? " " : $0 })
            .filter { $0.isLetter || $0.isNumber || ". -_".contains($0) }
            .split(separator: " ").joined(separator: " ")
        if !domains.isEmpty {
            lines.append("Script VPNC_MATCH_DOMAINS='\(domains)' \(kVpncScript)")
        }
    }
    lines.append(contentsOf: p.extra ?? [])
    let config = lines.joined(separator: "\n") + "\n"

    // Each profile gets its own pidfile so multiple tunnels can run at once.
    let r = run(kSudo, ["-n", kVpnc, "--non-inter", "--pid-file", pidFile(p), "-"], stdin: config)
    if r.status == 0 { return .ok }
    if r.err.lowercased().contains("password") && r.err.lowercased().contains("sudo") {
        return .message("sudo needs a password.\nRun install-sudoers.sh once to allow passwordless vpnc.")
    }
    return .message("vpnc failed (status \(r.status)):\n\(r.err.isEmpty ? r.out : r.err)")
}

// Disconnect one profile. Prefer the live PID discovered from `ps` (works even
// if no pidfile was written); fall back to the pidfile path.
func disconnect(_ p: Profile) -> ActionResult {
    let target = connectedTunnels([p])[p.name].map { "\($0.pid)" } ?? pidFile(p)
    let r = run(kSudo, ["-n", kVpncDisconnect, target])
    if r.status == 0 || r.out.contains("no vpnc") { return .ok }
    if r.err.lowercased().contains("password") && r.err.lowercased().contains("sudo") {
        return .message("sudo needs a password.\nRun install-sudoers.sh once.")
    }
    return .message("disconnect failed:\n\(r.err.isEmpty ? r.out : r.err)")
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
    private var lastConnected: Set<String>?   // nil until first poll (no notification at launch)

    func start() {
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
        let imp = NSMenuItem(title: "Import Config…", action: #selector(importConfig), keyEquivalent: "")
        imp.target = self
        menu.addItem(imp)
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Quit VpncBar",
                                action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
    }

    // Left-click a profile: toggle just that tunnel — leaves other tunnels alone.
    func toggleProfile(_ name: String) {
        guard let p = loadProfiles().first(where: { $0.name == name }) else { return }
        if !connectedTunnels([p]).isEmpty {
            perform { disconnect(p) }
        } else {
            perform { connect(p) }
        }
    }

    // Right-click a profile: jump straight to its edit dialog.
    var profileEditor: ProfileEditor?
    func editProfile(_ name: String) {
        guard let p = loadProfiles().first(where: { $0.name == name }) else { return }
        profileEditor = ProfileEditor(profile: p) { [weak self] prof, secret, password in
            upsert(prof, secret: secret, password: password)
            self?.refreshState()
        }
        NSApp.activate(ignoringOtherApps: true)
        profileEditor?.window.center()
        profileEditor?.window.makeKeyAndOrderFront(nil)
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
        let profiles = loadProfiles()
        let connected = Set(connectedTunnels(profiles).keys)
        for p in profiles where connected.contains(p.name) {
            _ = disconnect(p)
        }
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
            manageWindow = ManageWindow { [weak self] in self?.refreshState() }
        }
        NSApp.activate(ignoringOtherApps: true)
        manageWindow?.show()
    }

    @objc func importConfig() {
        let panel = NSOpenPanel()
        panel.title = "Import VPN config"
        panel.allowsOtherFileTypes = true
        panel.allowedContentTypes = ["pcf", "conf", "txt"].compactMap { UTType(filenameExtension: $0) }
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK, let url = panel.url else { return }
        guard let parsed = parseConfigFile(url.path) else {
            alert("Couldn't parse that file as a Cisco .pcf or vpnc .conf.")
            return
        }
        upsert(parsed.profile, secret: parsed.secret, password: parsed.password)
        var notes: [String] = []
        if parsed.secret == nil { notes.append("group secret") }
        if parsed.password == nil { notes.append("password") }
        let missing = notes.isEmpty ? "" : "\n\nMissing (set them in Manage VPNs): \(notes.joined(separator: ", "))."
        alert("Imported “\(parsed.profile.name)”.\(missing)")
        refreshState()
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
    var editor: ProfileEditor?
    let onChange: () -> Void

    init(onChange: @escaping () -> Void) {
        self.onChange = onChange
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
    @objc func addNew() { presentEditor(nil) }
    @objc func editSelected() {
        guard table.selectedRow >= 0 else { return }
        presentEditor(profiles[table.selectedRow])
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

    func presentEditor(_ p: Profile?) {
        editor = ProfileEditor(profile: p) { [weak self] prof, secret, password in
            upsert(prof, secret: secret, password: password)
            self?.reload()
        }
        window.beginSheet(editor!.window)
    }
}

// MARK: - Profile editor sheet

/// Top-origin view so the scrolled form starts at the top, not the bottom.
final class FlippedView: NSView { override var isFlipped: Bool { true } }

/// A password field with an eye toggle to reveal/hide the value. Internally swaps
/// a masked NSSecureTextField with a plain NSTextField, keeping their value in sync.
final class RevealableSecureField: NSView {
    private let secure = NSSecureTextField()
    private let plain = NSTextField()
    private let eye = NSButton()
    private var revealed = false

    var stringValue: String {
        get { revealed ? plain.stringValue : secure.stringValue }
        set { secure.stringValue = newValue; plain.stringValue = newValue }
    }
    var placeholderString: String? {
        get { secure.placeholderString }
        set { secure.placeholderString = newValue; plain.placeholderString = newValue }
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

final class ProfileEditor: NSObject {
    let window: NSWindow
    let nameField = NSTextField()
    let gatewayField = NSTextField()
    let idField = NSTextField()
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
    let mtuField = NSTextField()
    let dpdField = NSTextField()
    let weakCheck = NSButton(checkboxWithTitle: "Enable weak encryption (3DES)", target: nil, action: nil)
    let singleDESCheck = NSButton(checkboxWithTitle: "Enable single DES", target: nil, action: nil)
    let noEncCheck = NSButton(checkboxWithTitle: "Enable no encryption", target: nil, action: nil)
    let weakAuthCheck = NSButton(checkboxWithTitle: "Enable weak authentication", target: nil, action: nil)
    let onSave: (Profile, String?, String?) -> Void
    let existing: Profile?

    init(profile: Profile?, onSave: @escaping (Profile, String?, String?) -> Void) {
        self.onSave = onSave
        self.existing = profile
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 440, height: 710),
                          styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = profile == nil ? "Add VPN" : "Edit VPN"
        window.isReleasedWhenClosed = false   // we retain it; let ARC free it
        super.init()

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
        mtuField.stringValue = profile?.mtu ?? ""
        mtuField.placeholderString = "automatic"
        dpdField.stringValue = profile?.dpdTimeout ?? "30"   // seconds

        // Show real values (no "(default)" sentinel); pre-select vpnc's actual default.
        func fill(_ p: NSPopUpButton, _ items: [String], _ value: String?, _ def: String) {
            p.removeAllItems()
            p.addItems(withTitles: items)
            p.selectItem(withTitle: (value.flatMap { items.contains($0) ? $0 : nil }) ?? def)
        }
        fill(authmodePopup, ["psk", "cert", "hybrid"], profile?.authmode, "psk")
        fill(dhPopup, ["dh1", "dh2", "dh5", "dh14", "dh15", "dh16", "dh17", "dh18"], profile?.dhGroup, "dh2")
        fill(pfsPopup, ["nopfs", "dh1", "dh2", "dh5", "dh14", "dh15", "dh16", "dh17", "dh18", "server"], profile?.pfs, "server")
        fill(nattPopup, ["natt", "none", "force-natt", "cisco-udp"], profile?.natMode, "natt")
        fill(vendorPopup, ["cisco", "netscreen", "fortigate"], profile?.vendor, "cisco")
        fill(debugPopup, ["0", "1", "2", "3", "99"], profile?.debug, "0")

        weakCheck.state = (profile?.enableWeak ?? true) ? .on : .off    // 3DES on by default
        singleDESCheck.state = (profile?.singleDES ?? false) ? .on : .off
        noEncCheck.state = (profile?.noEncryption ?? false) ? .on : .off
        weakAuthCheck.state = (profile?.weakAuth ?? false) ? .on : .off

        let encStack = NSStackView(views: [weakCheck, singleDESCheck, noEncCheck, weakAuthCheck])
        encStack.orientation = .vertical
        encStack.alignment = .leading
        encStack.spacing = 4

        func label(_ s: String) -> NSTextField { NSTextField(labelWithString: s) }
        let grid = NSGridView(views: [
            [label("Name"), nameField],
            [label("Gateway"), gatewayField],
            [label("Group name"), idField],
            [label("Group secret"), secretField],
            [label("Username"), userField],
            [label("Password"), passwordField],
            [label("VPN domains"), dnsField],
            [label("IKE Authmode"), authmodePopup],
            [label("DH Group"), dhPopup],
            [label("PFS"), pfsPopup],
            [label("NAT-T Mode"), nattPopup],
            [label("Vendor"), vendorPopup],
            [label("Interface MTU"), mtuField],
            [label("DPD timeout"), dpdField],
            [label("Debug level"), debugPopup],
            [label("Encryption"), encStack],
        ])
        grid.column(at: 0).xPlacement = .trailing
        grid.rowSpacing = 8
        grid.columnSpacing = 10
        grid.translatesAutoresizingMaskIntoConstraints = false

        let fixedWidth: [NSView] = [nameField, gatewayField, idField, userField, secretField,
            passwordField, dnsField, mtuField, dpdField,
            authmodePopup, dhPopup, pfsPopup, nattPopup, vendorPopup, debugPopup]
        for v in fixedWidth {
            v.translatesAutoresizingMaskIntoConstraints = false
            v.widthAnchor.constraint(equalToConstant: 240).isActive = true
        }

        // Scrollable form (many fields), fixed Save/Cancel below.
        let doc = FlippedView()
        doc.translatesAutoresizingMaskIntoConstraints = false
        doc.addSubview(grid)
        let scroll = NSScrollView()
        scroll.documentView = doc
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        scroll.translatesAutoresizingMaskIntoConstraints = false

        let save = NSButton(title: "Save", target: self, action: #selector(saveTapped))
        save.bezelStyle = .rounded
        save.keyEquivalent = "\r"
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancelTapped))
        cancel.bezelStyle = .rounded
        cancel.keyEquivalent = "\u{1b}"
        let buttons = NSStackView(views: [cancel, save])
        buttons.spacing = 8
        buttons.translatesAutoresizingMaskIntoConstraints = false

        let content = NSView()
        content.addSubview(scroll)
        content.addSubview(buttons)
        window.contentView = content
        NSLayoutConstraint.activate([
            grid.topAnchor.constraint(equalTo: doc.topAnchor, constant: 16),
            grid.leadingAnchor.constraint(equalTo: doc.leadingAnchor, constant: 16),
            grid.trailingAnchor.constraint(equalTo: doc.trailingAnchor, constant: -16),
            grid.bottomAnchor.constraint(equalTo: doc.bottomAnchor, constant: -16),
            doc.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),

            scroll.topAnchor.constraint(equalTo: content.topAnchor),
            scroll.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            buttons.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 12),
            buttons.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            buttons.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -12),
        ])
    }

    @objc func saveTapped() {
        let name = nameField.stringValue.trimmingCharacters(in: .whitespaces)
        let gw = gatewayField.stringValue.trimmingCharacters(in: .whitespaces)
        let id = idField.stringValue.trimmingCharacters(in: .whitespaces)
        let user = userField.stringValue.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty, !gw.isEmpty, !id.isEmpty, !user.isEmpty else {
            alert("Name, Gateway, Group name and Username are all required.")
            return
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
            domain: nil, dnsMatchDomains: tv(dnsField),
            appVersion: existing?.appVersion, localAddr: existing?.localAddr,
            localPort: existing?.localPort, udpPort: existing?.udpPort, mtu: tv(mtuField),
            dpdTimeout: tv(dpdField), debug: pv(debugPopup),
            enableWeak: weakCheck.state == .on, singleDES: singleDESCheck.state == .on,
            noEncryption: noEncCheck.state == .on, weakAuth: weakAuthCheck.state == .on,
            extra: existing?.extra)
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
