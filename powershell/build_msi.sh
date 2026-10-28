#!/usr/bin/env bash
#
# build_msi.sh - Build the ThreatWorx twigs Windows installer (MSI) on Linux.
#
# Runs build.sh to build twigs.exe and the zips, then packages the exe zip
# into twigs-<version>-x64.msi, using wixl and msibuild from msitools
# (apt install wixl msitools).
#
# The MSI installs to C:\Program Files\ThreatWorx\twigs, adds that folder to
# the system PATH, and optionally saves the ThreatWorx connection details and
# a scheduled twigs run. Everything is set with MSI properties, for example:
#
#   msiexec /i twigs-1.3.24-x64.msi /qn TW_INSTANCE=acme.threatworx.io ^
#       TW_HANDLE=user@acme.com TW_TOKEN=xxxx
#
#   TW_INSTANCE, TW_HANDLE, TW_TOKEN
#         ThreatWorx connection details, saved under
#         HKLM\SOFTWARE\ThreatWorx\twigs (token in its Credentials subkey)
#         and used by twigs as defaults. Kept on upgrade when not given again.
#   TW_TOKEN_ACCESS=admins|users   (default: admins)
#         Who can read the saved token. "users" lets non-admin runs use it.
#   TW_SCHEDULE=daily|weekly|none  (default: daily)
#   TW_SCHEDULE_TIME=HH:MM         (default: 02:00; weekly runs on Sunday)
#         Scheduled task \ThreatWorx\twigs, run as SYSTEM with up to an hour
#         of random delay. Created only when instance, handle and token are
#         all known. Output goes to %ProgramData%\ThreatWorx\twigs\last_run.log.
#   INSTALLDIR=<folder>            (default: C:\Program Files\ThreatWorx\twigs\)
#
# Usage:
#   ./build_msi.sh [-v version] [-z twigs-exe.zip] [-o output_dir]
#
#   -v  version                 (default: twigs/__init__.py __version__)
#   -z  package this existing twigs.exe zip instead of running build.sh
#   -o  output directory        (default: powershell/dist)

set -euo pipefail

PS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$PS_DIR")"

# Never change: this is how Windows recognises new versions as upgrades
UPGRADE_CODE="FD0B4A27-BE34-466B-B516-54CBD5C0E9D3"
MANUFACTURER="ThreatWorx"
PRODUCT_NAME="ThreatWorx twigs"
REG_KEY='SOFTWARE\ThreatWorx\twigs'

VERSION=""
ZIP=""
OUT_DIR="$PS_DIR/dist"

usage() { awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "$0"; exit "${1:-0}"; }

while getopts ":v:z:o:h" opt; do
    case "$opt" in
        v) VERSION="$OPTARG" ;;
        z) ZIP="$OPTARG" ;;
        o) OUT_DIR="$OPTARG" ;;
        h) usage 0 ;;
        :) echo "Option -$OPTARG needs a value" >&2; usage 1 ;;
        *) echo "Unknown option -$OPTARG" >&2; usage 1 ;;
    esac
done

die() { echo "ERROR: $*" >&2; exit 1; }

for tool in wixl msibuild msiinfo unzip; do
    command -v "$tool" >/dev/null || die "$tool not found (apt install wixl msitools unzip)"
done

if [[ -z "$VERSION" ]]; then
    VERSION="$(sed -n "s/^__version__ = ['\"]\([^'\"]*\)['\"].*/\1/p" "$REPO_DIR/twigs/__init__.py")"
    [[ -n "$VERSION" ]] || die "could not read __version__ from twigs/__init__.py; pass -v"
fi
# MSI versions are numbers only (major.minor.build), e.g. 2.0.0-rc1 -> 2.0.0
MSI_VERSION="$(grep -oE '^[0-9]+(\.[0-9]+){0,2}' <<<"$VERSION")" || die "version $VERSION does not start with a number"

mkdir -p "$OUT_DIR"
OUT_DIR="$(realpath "$OUT_DIR")"
if [[ -n "$ZIP" ]]; then
    [[ -f "$ZIP" ]] || die "$ZIP not found"
else
    # Build twigs.exe and the zips first, so the MSI always has the current exe
    "$PS_DIR/build.sh" -v "$VERSION" -o "$OUT_DIR"
    echo
    ZIP="$OUT_DIR/twigs-exe-$VERSION.zip"
    [[ -f "$ZIP" ]] || die "build.sh did not produce $ZIP"
fi
ICON="$PS_DIR/favicon.ico"
MSI="$OUT_DIR/twigs-$VERSION-x64.msi"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> twigs MSI $VERSION (MSI version $MSI_VERSION) from $(basename "$ZIP")"

# ---------------------------------------------------------------- payload
mkdir "$WORK/zip"
unzip -q "$ZIP" -d "$WORK/zip"
PAYLOAD="$(find "$WORK/zip" -mindepth 1 -maxdepth 1 -type d | head -1)"
[[ -f "$PAYLOAD/twigs.exe" ]] || die "$ZIP does not contain twigs.exe"
[[ -f "$PAYLOAD/run_twigs.bat" ]] || die "$ZIP does not contain run_twigs.bat"

# Registers the scheduled task; the installer runs it with the TW_SCHEDULE values
cat <<'EOF' | sed 's/$/\r/' > "$PAYLOAD/schedule_task.ps1"
# Registers the \ThreatWorx\twigs scheduled task, which runs run_twigs.bat as
# SYSTEM. Run by the twigs installer; can also be run by hand as administrator:
#   powershell -ExecutionPolicy Bypass -File schedule_task.ps1 -Schedule weekly -Time 03:00
param([string]$Schedule = '', [string]$Time = '')

$logDir = Join-Path $env:ProgramData 'ThreatWorx\twigs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$log = Join-Path $logDir 'install.log'
function Write-Log([string]$Message) {
    Add-Content -Path $log -Value ('{0}  {1}' -f (Get-Date -Format 's'), $Message)
}

try {
    $ErrorActionPreference = 'Stop'
    if (!$Schedule) { $Schedule = 'daily' }
    if (!$Time) { $Time = '02:00' }
    $at = [datetime]::ParseExact($Time, 'HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
    # Random delay so a fleet of hosts does not report at the same moment
    $delay = New-TimeSpan -Hours 1
    switch ($Schedule.ToLower()) {
        'daily'  { $trigger = New-ScheduledTaskTrigger -Daily -At $at -RandomDelay $delay }
        'weekly' { $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At $at -RandomDelay $delay }
        default  { throw "unknown schedule '$Schedule' (use daily, weekly or none)" }
    }
    $bat = Join-Path $PSScriptRoot 'run_twigs.bat'
    $runLog = Join-Path $logDir 'last_run.log'
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" `
        -Argument "/c `"`"$bat`" > `"$runLog`" 2>&1`"" -WorkingDirectory $PSScriptRoot
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # StartWhenAvailable: run at next startup if the machine was off at the scheduled time
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Hours 4)
    Register-ScheduledTask -TaskPath '\ThreatWorx\' -TaskName 'twigs' -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Description 'ThreatWorx twigs host discovery' -Force | Out-Null
    Write-Log "Scheduled task \ThreatWorx\twigs registered: $Schedule at $Time, up to 1 hour random delay"
}
catch {
    Write-Log "Failed to register scheduled task \ThreatWorx\twigs: $_"
    exit 1
}
EOF

# ---------------------------------------------------------------- WiX source
xml_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' <<<"$1"; }
# MSI identifiers: letters, digits, underscores and dots, max 72 characters
msi_id() { local id; id="$(tr -c 'A-Za-z0-9_.\n' '_' <<<"$1")"; echo "${2}${id:0:60}"; }

COMPONENT_REFS=()
# Writes one component per file in directory $1
emit_files() {
    local dir="$1" f name id
    while IFS= read -r f; do
        name="$(basename "$f")"
        id="$(msi_id "${f#"$PAYLOAD"/}" f_)"
        echo "            <Component Id=\"c_${id#f_}\" Guid=\"*\" Win64=\"yes\">"
        echo "              <File Id=\"$id\" Source=\"$(xml_escape "$f")\" Name=\"$(xml_escape "$name")\" KeyPath=\"yes\" />"
        echo "            </Component>"
        COMPONENT_REFS+=("c_${id#f_}")
    done < <(find "$dir" -mindepth 1 -maxdepth 1 -type f | sort)
}

# Saved registry values: component id, key, value name, property
REG_VALUES=(
    "r_Instance    $REG_KEY              Instance     TW_INSTANCE"
    "r_Handle      $REG_KEY              Handle       TW_HANDLE"
    "r_Token       $REG_KEY\\Credentials Token        TW_TOKEN"
    "r_TokenAccess $REG_KEY              TokenAccess  TW_TOKEN_ACCESS"
    "r_Schedule    $REG_KEY              Schedule     TW_SCHEDULE"
    "r_ScheduleAt  $REG_KEY              ScheduleTime TW_SCHEDULE_TIME"
)

WXS="$WORK/twigs.wxs"
{
    cat <<EOF
<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="$PRODUCT_NAME" Language="1033" Version="$MSI_VERSION"
           Manufacturer="$MANUFACTURER" UpgradeCode="$UPGRADE_CODE">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine"
             Description="$PRODUCT_NAME $VERSION" Manufacturer="$MANUFACTURER" />
    <Media Id="1" Cabinet="twigs.cab" EmbedCab="yes" />
    <MajorUpgrade DowngradeErrorMessage="A newer version of $PRODUCT_NAME is already installed." />

    <Icon Id="twigs.ico" SourceFile="$(xml_escape "$ICON")" />
    <Property Id="ARPPRODUCTICON" Value="twigs.ico" />
    <Property Id="ARPNOMODIFY" Value="1" />
    <Property Id="MsiHiddenProperties" Value="TW_TOKEN;SAVED_TOKEN" />
EOF
    # Values saved by an earlier install, so an upgrade keeps them
    for entry in "${REG_VALUES[@]}"; do
        read -r id key name prop <<<"$entry"
        cat <<EOF
    <Property Id="SAVED_${prop#TW_}">
      <RegistrySearch Id="s_${id#r_}" Root="HKLM" Key="$key" Name="$name" Type="raw" Win64="yes" />
    </Property>
EOF
    done
    cat <<EOF

    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFiles64Folder">
        <Directory Id="VendorDir" Name="ThreatWorx">
          <Directory Id="INSTALLDIR" Name="twigs">
EOF
    emit_files "$PAYLOAD"
    for entry in "${REG_VALUES[@]}"; do
        read -r id key name prop <<<"$entry"
        cat <<EOF
            <Component Id="$id" Guid="*" Win64="yes">
              <RegistryValue Id="v_${id#r_}" Root="HKLM" Key="$key" Name="$name" Type="string" Value="[$prop]" KeyPath="yes" />
            </Component>
EOF
        COMPONENT_REFS+=("$id")
    done
    cat <<EOF
            <Component Id="r_InstallDir" Guid="*" Win64="yes">
              <RegistryValue Id="v_InstallDir" Root="HKLM" Key="$REG_KEY" Name="InstallDir" Type="string" Value="[INSTALLDIR]" KeyPath="yes" />
            </Component>
EOF
    COMPONENT_REFS+=(r_InstallDir)
    if [[ -d "$PAYLOAD/lists" ]]; then
        echo "            <Directory Id=\"ListsDir\" Name=\"lists\">"
        emit_files "$PAYLOAD/lists"
        echo "            </Directory>"
    fi
    cat <<EOF
          </Directory>
        </Directory>
      </Directory>
    </Directory>

    <Feature Id="Main" Title="$PRODUCT_NAME" Level="1">
EOF
    for c in "${COMPONENT_REFS[@]}"; do echo "      <ComponentRef Id=\"$c\" />"; done
    cat <<EOF
    </Feature>
  </Product>
</Wix>
EOF
} > "$WXS"

echo "==> Compiling with wixl"
wixl -a x64 -o "$WORK/twigs.msi" "$WXS" 2>"$WORK/wixl.log" || { cat "$WORK/wixl.log" >&2; die "wixl failed"; }
grep -q "ERROR" "$WORK/wixl.log" && { cat "$WORK/wixl.log" >&2; die "wixl reported errors"; }

# ---------------------------------------------------------------- tables wixl cannot write
# wixl 0.100 has no Environment, component conditions, custom actions or
# permissions, so they are added to the MSI's tables directly.
echo "==> Adding PATH, saved settings, token permissions and scheduled task"
sql() { msibuild "$WORK/twigs.msi" -q "$1" || die "msibuild failed: $1"; }
q() { sed "s/'/''/g" <<<"$1"; }   # SQL string escape

# Values are written only when the property is set, so nothing empty is saved
for entry in "${REG_VALUES[@]}"; do
    read -r id _ _ prop <<<"$entry"
    sql "UPDATE \`Component\` SET \`Condition\` = '$prop' WHERE \`Component\` = '$id'"
done

# Add the install folder to the end of the system PATH; removed on uninstall
EXE_COMPONENT="$(msi_id twigs.exe c_)"
sql "CREATE TABLE \`Environment\` (\`Environment\` CHAR(72) NOT NULL, \`Name\` CHAR(255) NOT NULL LOCALIZABLE, \`Value\` CHAR(255) LOCALIZABLE, \`Component_\` CHAR(72) NOT NULL PRIMARY KEY \`Environment\`)"
sql "INSERT INTO \`Environment\` (\`Environment\`, \`Name\`, \`Value\`, \`Component_\`) VALUES ('TwigsPath', '=-*PATH', '[~];[INSTALLDIR]', '$EXE_COMPONENT')"

# Token key: SYSTEM + Administrators only by default; TW_TOKEN_ACCESS=users adds read for Users
sql "CREATE TABLE \`MsiLockPermissionsEx\` (\`MsiLockPermissionsEx\` CHAR(72) NOT NULL, \`LockObject\` CHAR(72) NOT NULL, \`Table\` CHAR(32) NOT NULL, \`SDDLText\` CHAR(0) NOT NULL, \`Condition\` CHAR(255) PRIMARY KEY \`MsiLockPermissionsEx\`)"
sql "INSERT INTO \`MsiLockPermissionsEx\` (\`MsiLockPermissionsEx\`, \`LockObject\`, \`Table\`, \`SDDLText\`, \`Condition\`) VALUES ('TokenAdmins', 'v_Token', 'Registry', 'D:PAI(A;;KA;;;SY)(A;;KA;;;BA)', 'TW_TOKEN_ACCESS <> \"users\"')"
sql "INSERT INTO \`MsiLockPermissionsEx\` (\`MsiLockPermissionsEx\`, \`LockObject\`, \`Table\`, \`SDDLText\`, \`Condition\`) VALUES ('TokenUsers', 'v_Token', 'Registry', 'D:PAI(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)', 'TW_TOKEN_ACCESS = \"users\"')"

# Custom actions. Types: 51 = set property; 50 = run exe named by a property,
# +1024 deferred, +2048 as SYSTEM, +64 ignore exit code
add_ca() { sql "INSERT INTO \`CustomAction\` (\`Action\`, \`Type\`, \`Source\`, \`Target\`) VALUES ('$1', $2, '$(q "$3")', '$(q "$4")')"; }
add_seq() { sql "INSERT INTO \`$1\` (\`Action\`, \`Condition\`, \`Sequence\`) VALUES ('$2', '$(q "$3")', $4)"; }

# Keep values saved by an earlier install unless given again (right after AppSearch)
seq=51
for entry in "${REG_VALUES[@]}"; do
    read -r _ _ _ prop <<<"$entry"
    saved="SAVED_${prop#TW_}"
    add_ca "Keep$prop" 51 "$prop" "[$saved]"
    add_seq InstallUISequence "Keep$prop" "NOT $prop AND $saved" "$seq"
    add_seq InstallExecuteSequence "Keep$prop" "NOT $prop AND $saved" "$seq"
    seq=$((seq + 1))
done

add_ca SetSchtasksExe 51 SCHTASKS_EXE '[System64Folder]schtasks.exe'
add_ca SetPowerShellExe 51 POWERSHELL_EXE '[System64Folder]WindowsPowerShell\v1.0\powershell.exe'
add_seq InstallExecuteSequence SetSchtasksExe "" 60
add_seq InstallExecuteSequence SetPowerShellExe "" 61
# Any existing task is removed first; the task is then created again if wanted
add_ca DeleteTask 3186 SCHTASKS_EXE '/Delete /F /TN "\ThreatWorx\twigs"'
add_ca CreateTask 3186 POWERSHELL_EXE '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "[INSTALLDIR]schedule_task.ps1" -Schedule "[TW_SCHEDULE]" -Time "[TW_SCHEDULE_TIME]"'
add_seq InstallExecuteSequence DeleteTask "" 1502
add_seq InstallExecuteSequence CreateTask 'NOT (REMOVE~="ALL") AND TW_SCHEDULE<>"none" AND TW_INSTANCE AND TW_HANDLE AND TW_TOKEN' 5100

# Standard actions wixl leaves out: apply and remove the PATH change
add_seq InstallExecuteSequence RemoveEnvironmentStrings "" 3300
add_seq InstallExecuteSequence WriteEnvironmentStrings "" 5200
# Remove an older version before installing, so its task and PATH entry go first
sql "UPDATE \`InstallExecuteSequence\` SET \`Sequence\` = 1501 WHERE \`Action\` = 'RemoveExistingProducts'"

# Properties that may be passed on the command line to an elevated install
secure="$(msiinfo export "$WORK/twigs.msi" Property | awk -F'\t' '$1 == "SecureCustomProperties" { print $2 }')"
for entry in "${REG_VALUES[@]}"; do
    read -r _ _ _ prop <<<"$entry"
    secure="$secure;$prop;SAVED_${prop#TW_}"
done
sql "UPDATE \`Property\` SET \`Value\` = '${secure#;};INSTALLDIR' WHERE \`Property\` = 'SecureCustomProperties'"

cp "$WORK/twigs.msi" "$MSI"
echo
echo "Built $MSI ($(du -h "$MSI" | cut -f1))"
