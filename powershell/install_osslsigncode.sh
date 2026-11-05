#!/usr/bin/env bash
#
# install_osslsigncode.sh - Download, build and install osslsigncode on Ubuntu.
#
# osslsigncode signs Windows files (PowerShell scripts, .exe, .msi) with
# Authenticode from Linux. PowerShell script signing needs osslsigncode 2.8 or
# newer, and Ubuntu's own package is older than that, so this script builds it
# from the upstream source: https://github.com/mtrojnar/osslsigncode
#
# Usage:
#   ./install_osslsigncode.sh [-v version] [-p prefix] [-f] [-t]
#
#   -v  osslsigncode release tag to build, e.g. 2.14   (default: latest release)
#   -p  install prefix; the binary goes to <prefix>/bin
#       (default: /usr/local when run as root, otherwise ~/.local)
#   -f  rebuild even if the same version is already installed at the prefix
#   -t  run the upstream test suite before installing
#
# What it does:
#   1. Installs missing build packages with apt-get (uses sudo when not root):
#      build-essential pkg-config libssl-dev libcurl4-openssl-dev zlib1g-dev
#      curl ca-certificates python3
#   2. Uses the system cmake if it is 3.17 or newer. Otherwise (Ubuntu 20.04
#      has 3.16) it installs a current cmake with pip into the temporary build
#      directory only; the system cmake is not touched.
#   3. Downloads the release tarball, builds it in a temporary directory,
#      installs it to the prefix and deletes the temporary directory.
#
# Requirements: Ubuntu 20.04 or newer (or Debian-based equivalent), network
# access to github.com (and pypi.org on Ubuntu 20.04), sudo rights if build
# packages are missing or the prefix is not writable.
# GITHUB_TOKEN, if set, is used for the GitHub API call (avoids rate limits).

set -euo pipefail

REPO="mtrojnar/osslsigncode"
VERSION="latest"
PREFIX=""
FORCE=0
RUN_TESTS=0
MIN_CMAKE="3.17"
APT_PACKAGES=(build-essential pkg-config libssl-dev libcurl4-openssl-dev zlib1g-dev curl ca-certificates python3)

usage() { awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "$0"; exit "${1:-0}"; }
log() { echo "==> $*"; }
die() { echo "Error: $*" >&2; exit 1; }

while getopts ":v:p:fth" opt; do
    case "$opt" in
        v) VERSION="$OPTARG" ;;
        p) PREFIX="$OPTARG" ;;
        f) FORCE=1 ;;
        t) RUN_TESTS=1 ;;
        h) usage 0 ;;
        :) echo "Option -$OPTARG needs a value" >&2; usage 1 ;;
        *) echo "Unknown option -$OPTARG" >&2; usage 1 ;;
    esac
done
shift $((OPTIND - 1))
[ $# -eq 0 ] || { echo "Unexpected argument: $1" >&2; usage 1; }

command -v apt-get >/dev/null || die "apt-get not found; this script is for Ubuntu/Debian"

if [ "$(id -u)" -eq 0 ]; then
    SUDO=()
    PREFIX="${PREFIX:-/usr/local}"
else
    SUDO=(sudo)
    PREFIX="${PREFIX:-$HOME/.local}"
fi

# version_ge A B: true if version A >= version B
version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# --- 1. build packages -------------------------------------------------------
missing=()
for pkg in "${APT_PACKAGES[@]}"; do
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" || missing+=("$pkg")
done
if [ ${#missing[@]} -gt 0 ]; then
    log "Installing build packages: ${missing[*]}"
    "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get update -q
    "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "${missing[@]}"
else
    log "Build packages already installed"
fi

# --- 2. resolve the version ----------------------------------------------------
if [ "$VERSION" = "latest" ]; then
    auth=()
    [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
    VERSION="$(curl -fsSL "${auth[@]}" "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
        | sed -n 's/^ *"tag_name": *"\([^"]*\)".*/\1/p' | head -n1 || true)"
    if [ -z "$VERSION" ] && command -v git >/dev/null; then
        # API unavailable (rate limit, proxy): fall back to the highest release tag
        VERSION="$(git ls-remote --tags --refs "https://github.com/$REPO.git" 2>/dev/null \
            | sed -n 's#.*refs/tags/\([0-9][0-9.]*\)$#\1#p' | sort -V | tail -n1 || true)"
    fi
    [ -n "$VERSION" ] || die "could not determine the latest osslsigncode release; pass -v"
fi
log "osslsigncode version: $VERSION"

BIN="$PREFIX/bin/osslsigncode"
if [ "$FORCE" -eq 0 ] && [ -x "$BIN" ]; then
    installed="$("$BIN" --version 2>/dev/null | sed -n 's/^osslsigncode \([0-9][0-9.]*\).*/\1/p' | head -n1 || true)"
    if [ "$installed" = "${VERSION#v}" ]; then
        log "$BIN is already version $installed (use -f to rebuild)"
        exit 0
    fi
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/osslsigncode-build.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT

# --- 3. cmake -----------------------------------------------------------------
CMAKE=cmake
sys_cmake="$(cmake --version 2>/dev/null | sed -n 's/^cmake version \([0-9][0-9.]*\).*/\1/p' || true)"
if [ -n "$sys_cmake" ] && version_ge "$sys_cmake" "$MIN_CMAKE"; then
    log "Using system cmake $sys_cmake"
else
    log "System cmake ${sys_cmake:-not found} is older than $MIN_CMAKE; installing a private copy with pip"
    if ! python3 -m pip --version >/dev/null 2>&1; then
        "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends python3-pip
    fi
    python3 -m pip install -q --disable-pip-version-check --target "$WORK/cmake-py" cmake
    export PYTHONPATH="$WORK/cmake-py${PYTHONPATH:+:$PYTHONPATH}"
    CMAKE="$WORK/cmake-py/bin/cmake"
    log "Using $("$CMAKE" --version | head -n1)"
fi

# --- 4. download, build, install ------------------------------------------------
log "Downloading $REPO $VERSION"
mkdir -p "$WORK/src"
curl -fsSL "https://github.com/$REPO/archive/refs/tags/$VERSION.tar.gz" \
    | tar -xz -C "$WORK/src" --strip-components=1 \
    || die "download of $VERSION failed (does the tag exist?)"

log "Building"
# BASH_COMPLETION_USER_DIR keeps the bash completion file under the prefix
# (<prefix>/share/bash-completion/completions); otherwise upstream installs it
# to the system /usr/share directory whatever the prefix is.
"$CMAKE" -S "$WORK/src" -B "$WORK/build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DBASH_COMPLETION_USER_DIR="$PREFIX/share" >"$WORK/configure.log" 2>&1 \
    || { cat "$WORK/configure.log" >&2; die "cmake configure failed"; }
"$CMAKE" --build "$WORK/build" -j"$(nproc)" >"$WORK/build.log" 2>&1 \
    || { tail -n 50 "$WORK/build.log" >&2; die "build failed"; }

if [ "$RUN_TESTS" -eq 1 ]; then
    log "Running tests"
    CTEST="$(dirname "$CMAKE")/ctest"
    [ "$CMAKE" = cmake ] && CTEST=ctest
    (cd "$WORK/build" && "$CTEST" --output-on-failure) || die "tests failed"
fi

log "Installing to $PREFIX"
mkdir -p "$PREFIX" 2>/dev/null || true
if [ -w "$PREFIX" ]; then
    "$CMAKE" --install "$WORK/build" >/dev/null
else
    "${SUDO[@]}" env PYTHONPATH="${PYTHONPATH:-}" "$CMAKE" --install "$WORK/build" >/dev/null
fi

"$BIN" --version | head -n1
case ":$PATH:" in
    *":$PREFIX/bin:"*) ;;
    *) echo "Note: $PREFIX/bin is not on PATH. Add it, or call $BIN directly." ;;
esac
