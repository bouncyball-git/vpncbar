#!/bin/sh
# Build VpncBar.  Usage:  ./build.sh [all|deps|vpnc|app|pkg]   (default: all)
#
#   deps   static crypto libs (libgpg-error + libgcrypt) from source -> vendor/deps
#   vpnc   the utun-capable, statically-linked vpnc -> vendor/vpnc/bin
#   app    VpncBar.app (swiftc, ad-hoc signed) -> bin/
#   pkg    distributable installer -> dist/VpncBar-<version>.pkg
#   all    deps, then vpnc, then app, then pkg   (default; this exact order)
#
# vpnc ends up self-contained (only /usr/lib/libSystem) — no MacPorts needed.
set -e
cd "$(dirname "$0")"
ROOT="$(pwd)"

VPNC_DIR="vendor/vpnc"
DEPS="$ROOT/vendor/deps"
APP="bin/VpncBar.app"
SCRIPT_PATH="${SCRIPT_PATH:-/opt/vpncbar/vpnc-script}"

# Pinned crypto source versions.
GPGERR_VER=1.61
GCRYPT_VER=1.12.2
GCRYPT_BASE="https://www.gnupg.org/ftp/gcrypt"

# --- deps: static libgpg-error + libgcrypt from source -----------------------
build_deps() {
    if [ -f "$DEPS/lib/libgcrypt.a" ] && [ -f "$DEPS/lib/libgpg-error.a" ]; then
        echo "[deps] already built (vendor/deps) — skipping."
        return 0
    fi
    echo "[deps] building static libgpg-error + libgcrypt from source…"
    mkdir -p "$DEPS/build"
    cd "$DEPS/build"

    if [ ! -d "libgpg-error-$GPGERR_VER" ]; then
        curl -fsSLO "$GCRYPT_BASE/libgpg-error/libgpg-error-$GPGERR_VER.tar.bz2"
        tar xjf "libgpg-error-$GPGERR_VER.tar.bz2"
    fi
    ( cd "libgpg-error-$GPGERR_VER" &&
      ./configure --prefix="$DEPS" --enable-static --disable-shared \
                  --disable-doc --disable-tests CFLAGS="-O2" &&
      make -j"$(sysctl -n hw.ncpu)" && make install )

    if [ ! -d "libgcrypt-$GCRYPT_VER" ]; then
        curl -fsSLO "$GCRYPT_BASE/libgcrypt/libgcrypt-$GCRYPT_VER.tar.bz2"
        tar xjf "libgcrypt-$GCRYPT_VER.tar.bz2"
    fi
    ( cd "libgcrypt-$GCRYPT_VER" &&
      ./configure --prefix="$DEPS" --enable-static --disable-shared \
                  --disable-doc --with-libgpg-error-prefix="$DEPS" CFLAGS="-O2" &&
      make -j"$(sysctl -n hw.ncpu)" && make install )

    cd "$ROOT"
    echo "[deps] built $DEPS/lib/libgcrypt.a + libgpg-error.a"
}

# --- vpnc: statically-linked, utun-capable vpnc ------------------------------
build_vpnc() {
    [ -f "$VPNC_DIR/Makefile" ] || { echo "error: $VPNC_DIR/Makefile not found" >&2; exit 1; }
    build_deps   # ensure the static archives exist
    echo "[vpnc] building (static, CRYPTO_NONE=yes, SCRIPT_PATH=$SCRIPT_PATH)…"
    # Our static libgcrypt-config wins on PATH; its lib dir is .a-only, so the link
    # resolves to the static archives (no MacPorts).
    ( export PATH="$DEPS/bin:$PATH"
      make -C "$VPNC_DIR" clean >/dev/null 2>&1 || true
      make -C "$VPNC_DIR" CRYPTO_NONE=yes SCRIPT_PATH="$SCRIPT_PATH" )
    echo "[vpnc] built $VPNC_DIR/bin/vpnc — $("$VPNC_DIR/bin/vpnc" --version | head -1)"
    echo "[vpnc] runtime deps (expect ONLY libSystem):"
    /usr/bin/otool -L "$VPNC_DIR/bin/vpnc" | sed -n '2,$p'
}

# --- app: VpncBar.app via swiftc (no Xcode) ----------------------------------
build_app() {
    SRCDIR="src"
    SOURCES=$(find "$SRCDIR" -name '*.swift' -not -name 'make-icon.swift' | sort)
    [ -n "$SOURCES" ] || { echo "error: no .swift sources" >&2; exit 1; }
    echo "[app] compiling Swift sources…"
    mkdir -p bin
    # shellcheck disable=SC2086
    swiftc -O -o bin/vpncbar $SOURCES -framework AppKit
    rm -rf "$APP"
    mkdir -p "$APP/Contents/MacOS"
    mv bin/vpncbar "$APP/Contents/MacOS/VpncBar"
    cp "$SRCDIR/Info.plist" "$APP/Contents/Info.plist"
    if [ -f "$SRCDIR/VpncBar.icns" ]; then
        mkdir -p "$APP/Contents/Resources"
        cp "$SRCDIR/VpncBar.icns" "$APP/Contents/Resources/VpncBar.icns"
    fi
    codesign --force --sign - "$APP" 2>/dev/null || echo "[app] (codesign skipped)"
    echo "[app] built $ROOT/$APP"
}

# --- pkg: distributable installer -------------------------------------------
build_pkg() {
    [ -f "$VPNC_DIR/bin/vpnc" ] && [ -f "$VPNC_DIR/bin/cisco-decrypt" ] || build_vpnc
    [ -d "$APP" ] || build_app

    ID="local.vpncbar"
    STAGE="build/pkgroot"
    SCRIPTS="build/pkg-scripts"
    COMP="build/VpncBar-component.pkg"
    DISTXML="build/distribution.xml"
    OUT="dist"
    VER=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")

    echo "[pkg] staging payload…"
    rm -rf build "$OUT/VpncBar-$VER.pkg"
    mkdir -p "$STAGE/Applications" "$STAGE/opt/vpncbar" "$SCRIPTS" "$OUT"
    cp -R "$APP" "$STAGE/Applications/"
    install -m 755 "$VPNC_DIR/bin/vpnc"            "$STAGE/opt/vpncbar/vpnc"
    install -m 755 "$VPNC_DIR/bin/cisco-decrypt"   "$STAGE/opt/vpncbar/cisco-decrypt"
    install -m 755 "$VPNC_DIR/src/vpnc-disconnect" "$STAGE/opt/vpncbar/vpnc-disconnect"
    install -m 755 vendor/vpnc-script              "$STAGE/opt/vpncbar/vpnc-script"
    install -m 755 uninstall.sh                    "$STAGE/opt/vpncbar/uninstall.sh"
    xattr -cr "$STAGE" 2>/dev/null || true   # no ._ noise in the payload

    cat > "$SCRIPTS/postinstall" <<'EOF'
#!/bin/sh
USER_NAME=$(stat -f "%Su" /dev/console)
DEST=/etc/sudoers.d/vpncbar
printf '%s ALL=(root) NOPASSWD: /opt/vpncbar/vpnc, /opt/vpncbar/vpnc-disconnect\n' "$USER_NAME" > "$DEST"
chmod 440 "$DEST"
visudo -cf "$DEST" >/dev/null 2>&1 || rm -f "$DEST"
exit 0
EOF
    chmod 755 "$SCRIPTS/postinstall"

    echo "[pkg] building component + product…"
    pkgbuild --root "$STAGE" --identifier "$ID" --version "$VER" \
             --scripts "$SCRIPTS" --ownership recommended --install-location / "$COMP"

    cat > "$DISTXML" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>VpncBar $VER</title>
    <options customize="never" require-scripts="true" hostArchitectures="arm64"/>
    <volume-check>
        <allowed-os-versions><os-version min="13.0"/></allowed-os-versions>
    </volume-check>
    <license file="LICENSE"/>
    <choices-outline><line choice="default"><line choice="$ID"/></line></choices-outline>
    <choice id="default"/>
    <choice id="$ID" visible="false"><pkg-ref id="$ID"/></choice>
    <pkg-ref id="$ID" version="$VER" onConclusion="none">VpncBar-component.pkg</pkg-ref>
</installer-gui-script>
EOF

    if [ -n "$PKG_SIGN_ID" ]; then
        productbuild --distribution "$DISTXML" --package-path build --resources "$ROOT" \
                     --sign "$PKG_SIGN_ID" "$OUT/VpncBar-$VER.pkg"
    else
        productbuild --distribution "$DISTXML" --package-path build --resources "$ROOT" \
                     "$OUT/VpncBar-$VER.pkg"
        echo "[pkg] (unsigned — for distribution set PKG_SIGN_ID and notarize)"
    fi
    echo "[pkg] built $OUT/VpncBar-$VER.pkg"
}

TARGET="${1:-all}"
case "$TARGET" in
    deps) build_deps ;;
    vpnc) build_vpnc ;;
    app)  build_app ;;
    pkg)  build_pkg ;;
    all)  build_deps; build_vpnc; build_app; build_pkg ;;
    *)    echo "usage: $0 [all|deps|vpnc|app|pkg]   (default: all)" >&2; exit 1 ;;
esac

echo "Done ($TARGET)."
