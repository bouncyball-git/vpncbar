#!/bin/sh
# Build VpncBar.app from the project's Swift sources using swiftc (no Xcode needed).
set -e
cd "$(dirname "$0")"

BUILDDIR="build/bin"
APP="$BUILDDIR/VpncBar.app"
SRCDIR="src"

# Compile every .swift file under src/, excluding the standalone icon generator
# (which has its own main). Works whether the code is one file or split across many.
SOURCES=$(find "$SRCDIR" -name '*.swift' -not -name 'make-icon.swift' | sort)
if [ -z "$SOURCES" ]; then
    echo "error: no .swift files found" >&2
    exit 1
fi
echo "Compiling:"
echo "$SOURCES" | sed 's/^/  /'
mkdir -p "$BUILDDIR"
# shellcheck disable=SC2086
swiftc -O -o "$BUILDDIR/vpncbar" $SOURCES -framework AppKit

echo "Assembling $APP…"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
mv "$BUILDDIR/vpncbar" "$APP/Contents/MacOS/VpncBar"
cp "$SRCDIR/Info.plist" "$APP/Contents/Info.plist"

# App icon (generate once with: swift src/make-icon.swift && iconutil -c icns ...).
if [ -f "$SRCDIR/VpncBar.icns" ]; then
    mkdir -p "$APP/Contents/Resources"
    cp "$SRCDIR/VpncBar.icns" "$APP/Contents/Resources/VpncBar.icns"
else
    echo "(no VpncBar.icns — app will use the default icon)"
fi

# Ad-hoc sign so macOS lets it run locally.
codesign --force --sign - "$APP" 2>/dev/null || echo "(codesign skipped)"

echo "Built $(pwd)/$APP"
echo "Run it:    open $APP"
echo "Install:   cp -r $APP /Applications/"
