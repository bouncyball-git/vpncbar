#!/bin/sh
# Build the static crypto libraries vpnc links against — libgpg-error + libgcrypt —
# FROM SOURCE into vendor/deps (.a archives only, no dylibs). build-vpnc.sh links
# against these to produce a self-contained, MacPorts-free vpnc.
#
# Idempotent: does nothing if the archives already exist. Needs a network
# connection the first time (downloads the source tarballs from gnupg.org).
set -e
cd "$(dirname "$0")"
ROOT="$(pwd)"
DEPS="$ROOT/vendor/deps"

# Pinned source versions (match the libs VpncBar was tested against).
GPGERR_VER=1.61
GCRYPT_VER=1.12.2
BASE="https://www.gnupg.org/ftp/gcrypt"

if [ -f "$DEPS/lib/libgcrypt.a" ] && [ -f "$DEPS/lib/libgpg-error.a" ]; then
    echo "Static crypto deps already built (vendor/deps) — nothing to do."
    exit 0
fi

echo "Building static crypto deps from source into vendor/deps…"
mkdir -p "$DEPS/build"
cd "$DEPS/build"

if [ ! -d "libgpg-error-$GPGERR_VER" ]; then
    curl -fsSLO "$BASE/libgpg-error/libgpg-error-$GPGERR_VER.tar.bz2"
    tar xjf "libgpg-error-$GPGERR_VER.tar.bz2"
fi
( cd "libgpg-error-$GPGERR_VER" &&
  ./configure --prefix="$DEPS" --enable-static --disable-shared \
              --disable-doc --disable-tests CFLAGS="-O2" &&
  make -j"$(sysctl -n hw.ncpu)" && make install )

if [ ! -d "libgcrypt-$GCRYPT_VER" ]; then
    curl -fsSLO "$BASE/libgcrypt/libgcrypt-$GCRYPT_VER.tar.bz2"
    tar xjf "libgcrypt-$GCRYPT_VER.tar.bz2"
fi
( cd "libgcrypt-$GCRYPT_VER" &&
  ./configure --prefix="$DEPS" --enable-static --disable-shared \
              --disable-doc --with-libgpg-error-prefix="$DEPS" CFLAGS="-O2" &&
  make -j"$(sysctl -n hw.ncpu)" && make install )

cd "$ROOT"
echo "Built: $DEPS/lib/libgcrypt.a + libgpg-error.a"
