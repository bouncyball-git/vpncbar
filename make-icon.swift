// Generates VpncBar.icns: a gradient squircle with a white lock glyph.
// Usage: swift make-icon.swift   (then build.sh bundles the .icns)
import AppKit

func tinted(_ symbol: String, color: NSColor, box: CGFloat) -> NSImage? {
    let cfg = NSImage.SymbolConfiguration(pointSize: box, weight: .semibold)
    guard let sym = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)?
        .withSymbolConfiguration(cfg) else { return nil }
    let out = NSImage(size: sym.size)
    out.lockFocus()
    color.set()
    NSRect(origin: .zero, size: sym.size).fill()
    sym.draw(in: NSRect(origin: .zero, size: sym.size), from: .zero,
             operation: .destinationIn, fraction: 1)
    out.unlockFocus()
    return out
}

func iconPNG(_ px: CGFloat) -> Data {
    let img = NSImage(size: NSSize(width: px, height: px))
    img.lockFocus()
    let rect = NSRect(x: 0, y: 0, width: px, height: px)

    // Squircle background with vertical gradient (indigo → blue).
    let radius = px * 0.2237
    let path = NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius)
    let grad = NSGradient(colors: [
        NSColor(srgbRed: 0.35, green: 0.34, blue: 0.84, alpha: 1),  // top
        NSColor(srgbRed: 0.16, green: 0.40, blue: 0.78, alpha: 1),  // bottom
    ])!
    grad.draw(in: path, angle: -90)

    // White lock, centered, ~52% of the canvas.
    if let lock = tinted("lock.fill", color: .white, box: px * 0.46) {
        let s = lock.size
        let scale = min(px * 0.52 / s.width, px * 0.56 / s.height)
        let w = s.width * scale, h = s.height * scale
        lock.draw(in: NSRect(x: (px - w) / 2, y: (px - h) / 2, width: w, height: h),
                  from: .zero, operation: .sourceOver, fraction: 1)
    }
    img.unlockFocus()

    let rep = NSBitmapImageRep(data: img.tiffRepresentation!)!
    return rep.representation(using: .png, properties: [:])!
}

let fm = FileManager.default
let dir = "VpncBar.iconset"
try? fm.removeItem(atPath: dir)
try! fm.createDirectory(atPath: dir, withIntermediateDirectories: true)

// (filename, pixel size) for a complete iconset.
let entries: [(String, CGFloat)] = [
    ("icon_16x16.png", 16), ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32), ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128), ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256), ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512), ("icon_512x512@2x.png", 1024),
]
for (name, px) in entries {
    try! iconPNG(px).write(to: URL(fileURLWithPath: "\(dir)/\(name)"))
}
print("Wrote \(dir) (\(entries.count) sizes). Now: iconutil -c icns \(dir) -o VpncBar.icns")
