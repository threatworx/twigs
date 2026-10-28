#!/usr/bin/env bash
#
# build.sh - Build the twigs PowerShell release artifacts on Linux.
#
# Produces, in the output directory:
#   twigs-powershell-<version>.zip   twigs.ps1 and everything it needs on disk
#   twigs-exe-<version>.zip          twigs.exe (built by ps2exe.sh) and its runtime files
#   (each zip also has run_twigs.bat: all discovery options on, placeholders for
#   the ThreatWorx instance, handle and token)
#   SHA256SUMS
#
# HardeningKitty is not kept in the repo. It is downloaded from GitHub at build
# time: the latest release by default, or the tag / branch / commit given with
# -k. Each zip gets a BUILD-INFO.txt recording the HardeningKitty commit and
# file checksums that went into it. For a reproducible build, pass -k <commit>.
#
# Usage:
#   ./build.sh [-v version] [-k hk_version] [-o output_dir] [-a]
#
#   -v  version for the zip names and twigs.exe   (default: twigs/__init__.py __version__)
#   -k  HardeningKitty tag, branch or commit      (default: latest release)
#       e.g. v.0.9.4, master, da0976073caa...
#   -o  output directory                          (default: powershell/dist)
#   -a  build twigs.exe to require administrator (UAC prompt on start)
#
# Requirements: bash, curl, tar, sha256sum, zip (or python3), dotnet SDK 6+ (for ps2exe.sh).
# GITHUB_TOKEN, if set, is used for GitHub API calls (avoids anonymous rate limits).

set -euo pipefail

PS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$PS_DIR")"

HK_REPO="scipag/HardeningKitty"
HK_REF="latest"

# twigs files shipped in both zips, besides HardeningKitty
COMMON_FILES=(
    "$PS_DIR/hk_metadata.json"
    "$PS_DIR/sqlite3.exe"
    "$REPO_DIR/twigs/shadow_ai_signatures.json"
)

VERSION=""
OUT_DIR="$PS_DIR/dist"
ADMIN_FLAG=()

usage() { awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "$0"; exit "${1:-0}"; }

while getopts ":v:k:o:ah" opt; do
    case "$opt" in
        v) VERSION="$OPTARG" ;;
        k) HK_REF="$OPTARG" ;;
        o) OUT_DIR="$OPTARG" ;;
        a) ADMIN_FLAG=(-a) ;;
        h) usage 0 ;;
        :) echo "Option -$OPTARG needs a value" >&2; usage 1 ;;
        *) echo "Unknown option -$OPTARG" >&2; usage 1 ;;
    esac
done

die() { echo "ERROR: $*" >&2; exit 1; }

for tool in curl tar sha256sum; do
    command -v "$tool" >/dev/null || die "$tool not found"
done
if command -v zip >/dev/null; then
    make_zip() { (cd "$1" && zip -qrX "$2" "$3"); }
elif command -v python3 >/dev/null; then
    make_zip() { (cd "$1" && python3 -m zipfile -c "$2" "$3"); }
else
    die "zip or python3 is needed to create the zip files"
fi

if [[ -z "$VERSION" ]]; then
    VERSION="$(sed -n "s/^__version__ = ['\"]\([^'\"]*\)['\"].*/\1/p" "$REPO_DIR/twigs/__init__.py")"
    [[ -n "$VERSION" ]] || die "could not read __version__ from twigs/__init__.py; pass -v"
fi

for f in "$PS_DIR/twigs.ps1" "$PS_DIR/ShadowAI.psm1" "$PS_DIR/ps2exe.sh" "${COMMON_FILES[@]}"; do
    [[ -f "$f" ]] || die "missing required file: $f"
done
ICON_FLAG=()
[[ -f "$PS_DIR/favicon.ico" ]] && ICON_FLAG=(-c "$PS_DIR/favicon.ico")

mkdir -p "$OUT_DIR"
OUT_DIR="$(realpath "$OUT_DIR")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> twigs PowerShell build $VERSION"

# ---------------------------------------------------------------- HardeningKitty
gh_api() {
    local auth=()
    [[ -n "${GITHUB_TOKEN:-}" ]] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
    curl -fsSL --retry 3 "${auth[@]}" -H "Accept: $1" "https://api.github.com/repos/$HK_REPO/$2"
}

if [[ "$HK_REF" == "latest" ]]; then
    HK_REF="$(gh_api application/vnd.github+json releases/latest 2>/dev/null \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)" || true
    if [[ -z "$HK_REF" ]] && command -v git >/dev/null; then
        # API unavailable (e.g. rate limited): fall back to the highest version tag
        HK_REF="$(git ls-remote --tags --refs "https://github.com/$HK_REPO.git" \
            | sed 's|.*refs/tags/||' | sort -V | tail -1)"
    fi
    [[ -n "$HK_REF" ]] || die "could not find the latest HardeningKitty release; pass -k <version>"
fi
HK_COMMIT="$(gh_api application/vnd.github.sha "commits/$HK_REF" 2>/dev/null)" || HK_COMMIT="unknown"

echo "==> Downloading HardeningKitty $HK_REF (commit $HK_COMMIT)"
curl -fsSL --retry 3 -o "$WORK/hk.tar.gz" "https://codeload.github.com/$HK_REPO/tar.gz/$HK_REF" \
    || die "could not download HardeningKitty '$HK_REF' - check that the tag, branch or commit exists"
mkdir "$WORK/hk"
tar -xzf "$WORK/hk.tar.gz" -C "$WORK/hk" --strip-components=1

# The finding list and manifest names are read from the module itself, so a
# release that renames them still builds correctly.
HK_PSM1="$WORK/hk/HardeningKitty.psm1"
[[ -f "$HK_PSM1" ]] || die "HardeningKitty.psm1 not found in HardeningKitty $HK_REF"
HK_LIST="$(sed -n 's/^[[:space:]]*\$DefaultList = .*\\lists\\\([^"\\]*\.csv\)".*/\1/p' "$HK_PSM1" | head -1)"
HK_MANIFEST="$(sed -n 's/^[[:space:]]*\$HardeningKittyListManifestName = "\([^"]*\)".*/\1/p' "$HK_PSM1" | head -1)"
[[ -n "$HK_LIST" ]] || die "could not find the default finding list name in HardeningKitty.psm1 ($HK_REF)"

HK_FILES=(HardeningKitty.psm1 HardeningKitty.psd1 LICENSE "lists/$HK_LIST")
if [[ -n "$HK_MANIFEST" ]]; then
    HK_FILES+=("lists/$HK_MANIFEST")
    [[ -f "$WORK/hk/lists/$HK_MANIFEST.p7s" ]] && HK_FILES+=("lists/$HK_MANIFEST.p7s")
fi
for path in "${HK_FILES[@]}"; do
    [[ -f "$WORK/hk/$path" ]] || die "HardeningKitty $HK_REF is missing $path"
done

# Records exactly what went into a release folder
write_build_info() {
    {
        echo "twigs version:          $VERSION"
        echo "built:                  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "HardeningKitty version: $HK_REF"
        echo "HardeningKitty commit:  $HK_COMMIT"
        echo "HardeningKitty source:  https://github.com/$HK_REPO"
        echo
        echo "HardeningKitty files (SHA-256):"
        (cd "$WORK/hk" && sha256sum "${HK_FILES[@]}")
    } > "$1/BUILD-INFO.txt"
}

# Copies the HardeningKitty files into a release folder
stage_hk() {
    local dest="$1" with_module="$2"
    mkdir -p "$dest/lists"
    write_build_info "$dest"
    for path in "${HK_FILES[@]}"; do
        case "$path" in
            LICENSE) cp "$WORK/hk/LICENSE" "$dest/LICENSE-HardeningKitty.txt" ;;
            lists/*) cp "$WORK/hk/$path" "$dest/$path" ;;
            *) [[ "$with_module" == true ]] && cp "$WORK/hk/$path" "$dest/$path" ;;
        esac
    done
}

# ---------------------------------------------------------------- versioned twigs.ps1
# Both zips ship this copy, with $twigs_version set to the release version.
mkdir "$WORK/src"
# (twigs.ps1 has CRLF line endings, so the line end may be preceded by \r)
sed "s/^\$twigs_version = 'dev'\(\r\?\)\$/\$twigs_version = '$VERSION'\1/" "$PS_DIR/twigs.ps1" > "$WORK/src/twigs.ps1"
grep -qF "\$twigs_version = '$VERSION'" "$WORK/src/twigs.ps1" \
    || die "could not set the version in twigs.ps1 (expected a line: \$twigs_version = 'dev')"

# ---------------------------------------------------------------- run_twigs.bat
# Writes a launcher with every discovery option on and placeholders for the
# ThreatWorx connection details. $2 is the command that starts twigs.
write_bat() {
    local dest="$1" runner="$2"
    cat <<EOF | sed 's/$/\r/' > "$dest/run_twigs.bat"
@echo off
rem twigs $VERSION - Windows host discovery with all discovery options enabled:
rem   - host benchmark (HardeningKitty)
rem   - shadow AI discovery, including AI credential, package, browser history
rem     and WSL checks
rem
rem 1. Replace the CHANGE_ME values below with your ThreatWorx details.
rem    If twigs was installed with the MSI, they can stay CHANGE_ME: the
rem    values saved by the installer are used instead.
rem 2. Run this file, ideally from a command prompt opened with "Run as
rem    administrator". Without administrator rights it still runs, but skips
rem    the host benchmark, which needs them for accurate results.
rem
rem Extra twigs options can be added after the file name, for example:
rem   run_twigs.bat -assetname myhost -tags tag1,tag2 -out asset.json
setlocal

rem ThreatWorx instance, for example acme.threatworx.io
set "TW_INSTANCE=CHANGE_ME"
rem Email handle of the ThreatWorx user
set "TW_HANDLE=CHANGE_ME"
rem API token of the ThreatWorx user
set "TW_TOKEN=CHANGE_ME"

set TW_ARGS=
if not "%TW_INSTANCE%"=="CHANGE_ME" set TW_ARGS=%TW_ARGS% -instance "%TW_INSTANCE%"
if not "%TW_HANDLE%"=="CHANGE_ME" set TW_ARGS=%TW_ARGS% -handle "%TW_HANDLE%"
if not "%TW_TOKEN%"=="CHANGE_ME" set TW_ARGS=%TW_ARGS% -token "%TW_TOKEN%"
if not defined TW_ARGS (
    reg query "HKLM\SOFTWARE\ThreatWorx\twigs" /v Instance /reg:64 >nul 2>&1 || goto :not_configured
)

set "NO_HOST_BENCHMARK=false"
net session >nul 2>&1
if errorlevel 1 (
    echo WARNING: not running as administrator - skipping the host benchmark.
    echo          For a full run, use a command prompt opened with "Run as administrator".
    set "NO_HOST_BENCHMARK=true"
)

$runner -mode local %TW_ARGS% ^
    -no_host_benchmark %NO_HOST_BENCHMARK% ^
    -shadow_ai_scan true ^
    -shadow_ai_check_credentials true ^
    -shadow_ai_check_packages true ^
    -shadow_ai_check_browsing true ^
    -shadow_ai_check_wsl true ^
    %*
exit /b %ERRORLEVEL%

:not_configured
echo Edit %~nx0 and replace the CHANGE_ME values for TW_INSTANCE, TW_HANDLE and TW_TOKEN,
echo or install twigs with the MSI and pass TW_INSTANCE, TW_HANDLE and TW_TOKEN to it.
exit /b 1
EOF
}

# ---------------------------------------------------------------- twigs.ps1 zip
# Flat layout: twigs.ps1 imports .\HardeningKitty.psm1, which reads .\lists\.
PS_NAME="twigs-powershell-$VERSION"
PS_STAGE="$WORK/stage-ps/$PS_NAME"
echo "==> Staging $PS_NAME"
mkdir -p "$PS_STAGE"
cp "$WORK/src/twigs.ps1" "$PS_DIR/ShadowAI.psm1" "${COMMON_FILES[@]}" "$PS_STAGE/"
stage_hk "$PS_STAGE" true
write_bat "$PS_STAGE" 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0twigs.ps1"'

# ---------------------------------------------------------------- twigs.exe zip
# Inside twigs.exe, modules are pre-loaded from embedded source, so
# $PSScriptRoot is empty there. HardeningKitty uses it to find .\lists\, so the
# embedded copy is pointed at the exe's own folder instead. Only the copy that
# goes into the exe is changed; twigs.ps1 users get the original file.
echo "==> Building twigs.exe"
mkdir "$WORK/exe-src"
sed 's/\$PSScriptRoot/([System.AppDomain]::CurrentDomain.BaseDirectory)/g' \
    "$WORK/hk/HardeningKitty.psm1" > "$WORK/exe-src/HardeningKitty.psm1"
grep -q '\$PSScriptRoot' "$WORK/exe-src/HardeningKitty.psm1" && die "HardeningKitty patch for twigs.exe did not apply"

EXE_NAME="twigs-exe-$VERSION"
EXE_STAGE="$WORK/stage-exe/$EXE_NAME"
mkdir -p "$EXE_STAGE"
"$PS_DIR/ps2exe.sh" \
    -i "$WORK/src/twigs.ps1" \
    -o "$EXE_STAGE/twigs.exe" \
    -m "$PS_DIR/ShadowAI.psm1" \
    -m "$WORK/exe-src/HardeningKitty.psm1" \
    -v "$VERSION" \
    "${ICON_FLAG[@]}" "${ADMIN_FLAG[@]}"
cp "${COMMON_FILES[@]}" "$EXE_STAGE/"
stage_hk "$EXE_STAGE" false
write_bat "$EXE_STAGE" '"%~dp0twigs.exe"'

# ---------------------------------------------------------------- zips
echo "==> Writing zips to $OUT_DIR"
rm -f "$OUT_DIR/$PS_NAME.zip" "$OUT_DIR/$EXE_NAME.zip"
make_zip "$WORK/stage-ps" "$OUT_DIR/$PS_NAME.zip" "$PS_NAME"
make_zip "$WORK/stage-exe" "$OUT_DIR/$EXE_NAME.zip" "$EXE_NAME"
(cd "$OUT_DIR" && sha256sum "$PS_NAME.zip" "$EXE_NAME.zip" > SHA256SUMS)

echo
for z in "$PS_NAME.zip" "$EXE_NAME.zip"; do
    echo "$OUT_DIR/$z ($(du -h "$OUT_DIR/$z" | cut -f1))"
done
echo "$OUT_DIR/SHA256SUMS"
