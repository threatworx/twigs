# twigs for Windows (PowerShell, exe and MSI)

This folder holds the Windows version of twigs (`twigs.ps1` and
`ShadowAI.psm1`) and the Linux scripts that turn it into release artifacts:

| Script | Produces |
|---|---|
| [`build.sh`](#buildsh--zip-artifacts) | `twigs-powershell-<version>.zip`, `twigs-exe-<version>.zip`, `SHA256SUMS` |
| [`build_msi.sh`](#build_msish--windows-installer) | runs `build.sh`, then `twigs-<version>-x64.msi` from the exe zip |
| [`ps2exe.sh`](#ps2exesh--script-to-exe) | `twigs.exe` from `twigs.ps1` (called by `build.sh`) |

Everything builds on Linux with no Windows machine or Wine. A full release:

```bash
cd powershell
./build_msi.sh      # runs build.sh (zips, including twigs.exe), then builds the MSI
ls dist/
```

Run `./build.sh` on its own when only the zips are needed.

`ShadowAI.psm1` is also used by Python twigs: `twigs/windows.py` sends it to
remote Windows hosts over WinRM, and `setup.py` copies it into the Python
package at build time. Keep this folder as the only copy.

---

## build.sh — zip artifacts

```
./build.sh [-v version] [-k hk_version] [-o output_dir] [-a]
```

| Option | Default | Meaning |
|---|---|---|
| `-v version` | `__version__` in `twigs/__init__.py` | Version used in the zip names, set in `twigs.ps1` (`$twigs_version`) and as twigs.exe's file/product version |
| `-k hk_version` | latest HardeningKitty release | HardeningKitty tag, branch or commit to download, e.g. `v.0.9.4`, `master`, `da0976073caa` |
| `-o output_dir` | `powershell/dist` | Where the zips and `SHA256SUMS` are written |
| `-a` | off | Build twigs.exe to ask for administrator rights (UAC) when it starts |
| `-h` | | Show help |

`GITHUB_TOKEN`, if set (as on GitHub Actions), is used for the GitHub API calls
that find the latest HardeningKitty release.

### What it does

1. Downloads [HardeningKitty](https://github.com/scipag/HardeningKitty) at the
   chosen version and keeps only what twigs uses: the module, its default
   finding list, the signed list manifest and the licence. The list and manifest
   names are read from the module, so a release that renames them still builds.
2. Sets `$twigs_version` in a copy of `twigs.ps1`. The source copy stays `'dev'`.
3. Stages `twigs-powershell-<version>/` and builds twigs.exe with `ps2exe.sh`
   (embedding `ShadowAI.psm1` and HardeningKitty) into `twigs-exe-<version>/`.
4. Writes `run_twigs.bat` and `BUILD-INFO.txt` into both, zips them and writes
   `SHA256SUMS`.

### Zip contents

| File | PowerShell zip | Exe zip |
|---|:-:|:-:|
| `twigs.ps1`, `ShadowAI.psm1` | ✓ | embedded in twigs.exe |
| `HardeningKitty.psm1`, `HardeningKitty.psd1` | ✓ | embedded in twigs.exe |
| `twigs.exe` | | ✓ |
| `lists\` (HardeningKitty finding list and signed manifest) | ✓ | ✓ |
| `hk_metadata.json`, `shadow_ai_signatures.json`, `sqlite3.exe` | ✓ | ✓ |
| `run_twigs.bat` | ✓ | ✓ |
| `BUILD-INFO.txt` (twigs version, HardeningKitty version, commit and file SHA-256s) | ✓ | ✓ |
| `LICENSE-HardeningKitty.txt` | ✓ | ✓ |

`shadow_ai_signatures.json` comes from `../twigs/`; it is shared with the
Linux/macOS shadow AI implementation in Python twigs.

### run_twigs.bat

A launcher with every discovery option on: the host benchmark (HardeningKitty)
and shadow AI discovery with the credential, package, browser history and WSL
checks.

1. Replace the `CHANGE_ME` values for `TW_INSTANCE`, `TW_HANDLE` and `TW_TOKEN`
   at the top of the file. After an MSI install they can stay `CHANGE_ME`: the
   values saved by the installer are used instead.
2. Run it from a command prompt opened with **Run as administrator**.

Extra twigs options can follow the file name, for example
`run_twigs.bat -assetname myhost -tags tag1,tag2 -out asset.json`.

- Without administrator rights it still runs, prints a warning, and skips the
  host benchmark, which needs administrator rights for accurate results.
- If no values are filled in and no installer settings exist, it stops and says
  what to fill in.
- Its exit code is twigs' exit code.

### Requirements (build machine)

- Linux (tested on Ubuntu 20.04) with `bash`, `curl`, `tar`, `sha256sum`, and
  `zip` or `python3`
- dotnet SDK 6 or newer (for `ps2exe.sh`)
- Network access to GitHub (HardeningKitty) and nuget.org (first exe build only)

### Requirements (Windows, running the zips)

| | PowerShell zip | Exe zip |
|---|---|---|
| PowerShell 5.1 | required | required (twigs.exe runs on it) |
| .NET Framework | 4.5+ (needed by PowerShell 5.1) | 4.6.2+ |
| Built in on | Windows 10 / Server 2016 and later | Windows 10 1607 / Server 2016 and later |
| Older Windows | needs WMF 5.1 installed | needs WMF 5.1 and .NET 4.6.2 installed |

Administrator rights are needed for the host benchmark. Running as an
administrator (or SYSTEM) also lets shadow AI discovery cover every user profile
on the host; otherwise it covers the current user only.

### Limitations

- **Network at build time.** Every build downloads HardeningKitty from GitHub.
- **Not reproducible by default.** Without `-k`, the HardeningKitty version is
  whatever the latest release is at build time. Pass `-k <commit>` to repeat a
  build exactly; `BUILD-INFO.txt` records the commit used.
- **Only the default HardeningKitty finding list is shipped**, since that is the
  only one twigs uses. Other lists from the HardeningKitty repo are left out.
- **Version format.** Windows file versions are numbers only, so `-v 2.0.0-rc1`
  gives twigs.exe a file version of `2.0.0.0` (the product version keeps `2.0.0-rc1`).
- **twigs.ps1's Authenticode signature becomes invalid** in the built zip,
  because the version is written into the file. `run_twigs.bat` runs twigs.ps1
  with `-ExecutionPolicy Bypass`, so it is unaffected; running twigs.ps1 directly
  under an `AllSigned` or `RemoteSigned` policy needs a re-signed copy.
- **twigs.exe is not code-signed**, so Windows SmartScreen and some endpoint
  security tools may warn about or block it.
- **run_twigs.bat values** must not contain the characters `& | < > ^ % "`, which
  the Windows command prompt treats specially.
- **run_twigs.bat does not pause** at the end, so it can run unattended. When
  double-clicked, its window closes as soon as twigs finishes; run it from an
  open command prompt to see the output.

---

## build_msi.sh — Windows installer

```
./build_msi.sh [-v version] [-z twigs-exe.zip] [-o output_dir]
```

| Option | Default | Meaning |
|---|---|---|
| `-v version` | `__version__` in `twigs/__init__.py` | Version of the MSI. Only the leading numbers are used (`2.0.0-rc1` → `2.0.0`) |
| `-z zip` | | Package this existing exe zip instead of running `build.sh` |
| `-o output_dir` | `powershell/dist` | Where `twigs-<version>-x64.msi` is written |
| `-h` | | Show help |

By default `build_msi.sh` first runs `build.sh` with the same version and
output directory, so the MSI always contains a freshly built twigs.exe, and the
zips and `SHA256SUMS` are written alongside it. With `-z`, the given exe zip is
packaged as it is and nothing is rebuilt. Either way, `schedule_task.ps1`, which
registers the scheduled task, is added to the MSI.

### What the MSI installs

- The contents of the exe zip, in `C:\Program Files\ThreatWorx\twigs\`
- That folder at the end of the system `PATH`, so `twigs` and `run_twigs` work
  from any prompt
- Settings under `HKLM\SOFTWARE\ThreatWorx\twigs` (see below)
- Optionally, a scheduled task `\ThreatWorx\twigs`
- An Add/Remove Programs entry, **ThreatWorx twigs**, published by ThreatWorx

### Deploy options (MSI properties)

| Property | Default | Meaning |
|---|---|---|
| `TW_INSTANCE` | | ThreatWorx instance, e.g. `acme.threatworx.io` |
| `TW_HANDLE` | | Email handle of the ThreatWorx user |
| `TW_TOKEN` | | API token of the ThreatWorx user |
| `TW_TOKEN_ACCESS` | `admins` | Who can read the saved token: `admins` (Administrators and SYSTEM) or `users` (also all local users, so non-admin runs can use it) |
| `TW_SCHEDULE` | `daily` | `daily`, `weekly` (Sundays) or `none` |
| `TW_SCHEDULE_TIME` | `02:00` | Time of the scheduled run, 24-hour `HH:MM` |
| `INSTALLDIR` | `C:\Program Files\ThreatWorx\twigs\` | Install folder |

Each value is saved only if it was given. On an upgrade, values not given again
are kept from the previous install.

### Examples

Silent install with a daily run (most deployments):

```
msiexec /i twigs-1.3.24-x64.msi /qn TW_INSTANCE=acme.threatworx.io TW_HANDLE=user@acme.com TW_TOKEN=xxxx
```

Weekly at 03:00, token readable by all local users:

```
msiexec /i twigs-1.3.24-x64.msi /qn TW_INSTANCE=acme.threatworx.io TW_HANDLE=user@acme.com TW_TOKEN=xxxx TW_SCHEDULE=weekly TW_SCHEDULE_TIME=03:00 TW_TOKEN_ACCESS=users
```

Save the settings but create no scheduled run:

```
msiexec /i twigs-1.3.24-x64.msi /qn TW_INSTANCE=acme.threatworx.io TW_HANDLE=user@acme.com TW_TOKEN=xxxx TW_SCHEDULE=none
```

Install twigs only, with no saved settings and no scheduled run:

```
msiexec /i twigs-1.3.24-x64.msi /qn
```

Upgrade to a newer version, keeping all saved settings:

```
msiexec /i twigs-1.3.25-x64.msi /qn
```

Install with a detailed log (the token is hidden from the log):

```
msiexec /i twigs-1.3.24-x64.msi /qn /l*v twigs-install.log TW_INSTANCE=... TW_HANDLE=... TW_TOKEN=...
```

Uninstall:

```
msiexec /x twigs-1.3.24-x64.msi /qn
```

For Intune, SCCM/ConfigMgr or Group Policy, use the same command lines; these
tools run the install as SYSTEM, which can pass all the properties above.

### Saved settings (registry)

All under `HKLM\SOFTWARE\ThreatWorx\twigs` (64-bit registry view):

| Value | From |
|---|---|
| `Instance` | `TW_INSTANCE` |
| `Handle` | `TW_HANDLE` |
| `Credentials\Token` | `TW_TOKEN`, in a subkey with the `TW_TOKEN_ACCESS` permissions |
| `TokenAccess` | `TW_TOKEN_ACCESS` |
| `Schedule`, `ScheduleTime` | `TW_SCHEDULE`, `TW_SCHEDULE_TIME` |
| `InstallDir` | install folder, always written |

twigs.ps1 and twigs.exe use `Instance`, `Handle` and `Token` whenever
`-instance`, `-handle` or `-token` is not given on the command line. Command-line
values always win. A non-admin run that cannot read the token says so.

Uninstalling removes these values.

### Scheduled run

The scheduled run is optional, and **on by default**: when the connection
details are known, the MSI creates a daily task unless `TW_SCHEDULE=none` is
passed.

| Install | Scheduled task |
|---|---|
| `TW_INSTANCE`, `TW_HANDLE` and `TW_TOKEN` given | created, daily at 02:00 |
| …plus `TW_SCHEDULE=weekly` and/or `TW_SCHEDULE_TIME=HH:MM` | created, at that schedule |
| …plus `TW_SCHEDULE=none` | not created |
| any of the three missing, and not saved by an earlier install | not created |
| no properties, e.g. a double-clicked install | not created |

On an upgrade, a schedule saved by the earlier install (including `none`) is
kept unless `TW_SCHEDULE` is given again.

The task `\ThreatWorx\twigs` runs `run_twigs.bat` as **SYSTEM**, so it includes
the host benchmark and shadow AI discovery across every user profile.
- Up to one hour of random delay after `TW_SCHEDULE_TIME`, so a fleet of hosts
  does not report at the same moment
- Runs at the next startup if the machine was off at the scheduled time
- Stopped if still running after 4 hours; a run is skipped if the previous one
  is still going
- Output of the last run: `%ProgramData%\ThreatWorx\twigs\last_run.log`
- Task registration results and errors: `%ProgramData%\ThreatWorx\twigs\install.log`

Each install, upgrade or repair removes any existing task and creates it again
from the current settings. Uninstalling removes it.

To change the schedule by hand, run as administrator:

```
powershell -ExecutionPolicy Bypass -File "C:\Program Files\ThreatWorx\twigs\schedule_task.ps1" -Schedule weekly -Time 03:00
```

### Requirements (build machine)

- Linux with `wixl` and `msitools` (`apt install wixl msitools`) and `unzip`.
  On Ubuntu 20.04 `wixl` is a separate package from `msitools`.
- Everything `build.sh` needs (see above), unless an exe zip is passed with `-z`

### Requirements (Windows)

| Requirement | Why | Built in on |
|---|---|---|
| 64-bit Windows | the MSI is x64 only | almost all current systems |
| Windows Installer 5.0 | token key permissions | Windows 7 / Server 2008 R2 and later |
| .NET Framework 4.6.2, PowerShell 5.1 | twigs.exe | Windows 10 1607 / Server 2016 and later |
| ScheduledTasks PowerShell module | creating the scheduled task | Windows 8 / Server 2012 and later |
| Administrator rights or SYSTEM | per-machine install | |

In practice: Windows 10, Windows 11, and Windows Server 2016, 2019, 2022 and
2025, 64-bit, including Server Core.

### Limitations

- **No setup screens.** Settings can only be passed on the `msiexec` command
  line; a double-clicked install installs with defaults and saves no settings.
  (`wixl` cannot build MSI dialogs.)
- **64-bit Windows only.** 32-bit Windows is refused. Windows on ARM is untested.
- **No check for .NET or PowerShell versions.** On Windows older than
  10 / Server 2016 without .NET 4.6.2 and WMF 5.1, the MSI installs but twigs.exe
  does not run, and the scheduled task fails each time.
- **Task creation failures do not fail the install.** The reason is written to
  `%ProgramData%\ThreatWorx\twigs\install.log`.
- **Fixed schedule details.** Weekly runs are on Sundays, the random delay is one
  hour and the time limit four hours.
- **Every release needs a higher version.** Two different MSI builds of the same
  version are treated as separate products and are not upgraded over each other.
  Never change `UPGRADE_CODE` in `build_msi.sh`: it is how Windows recognises
  new versions as upgrades.
- **Changing saved settings without an upgrade.** Running the same version's MSI
  again with new values is not a supported way to change them (Windows treats
  it as a change to an existing install). Edit the registry values as
  administrator (and rerun `schedule_task.ps1` for the schedule), or uninstall
  and install again.
- **The token is stored as plain text** in the registry, protected only by the
  key's permissions. With `TW_TOKEN_ACCESS=users`, every local user can read it.
  It is hidden from MSI logs, but the `msiexec` command line itself may be
  visible to other processes and recorded by deployment tools.
- **The MSI is not code-signed**, so SmartScreen warns when it is downloaded and
  run interactively. `osslsigncode` can sign it on Linux with a code-signing
  certificate.
- **How it is built.** `wixl` 0.100 cannot write PATH entries, component
  conditions, custom actions or permissions, so `build_msi.sh` adds those tables
  to the MSI with `msibuild` after compiling.

---

## ps2exe.sh — script to exe

`build.sh` calls this; run it by hand only to build an exe outside a release.

```
./ps2exe.sh [-i script.ps1] [-o output.exe] [-m module.psm1]... [-a] [-v version] [-c icon.ico]
```

| Option | Default | Meaning |
|---|---|---|
| `-i script` | `twigs/twigs.ps1` (relative to the script; pass `-i twigs.ps1` here) | Script to convert |
| `-o exe` | `<script name>.exe` next to the script | Output exe |
| `-m module` | every `*.psm1` next to the script | Module to embed; repeat for several |
| `-a` | off | Ask for administrator rights (UAC) when the exe starts |
| `-v version` | `1.0.0` | File and product version |
| `-c icon` | none | `.ico` file for the exe |

It builds a small .NET Framework 4.6.2 console program with the dotnet SDK. The
program embeds the script and modules and runs them on the target's Windows
PowerShell 5.1, the same way the Windows-only ps2exe tool does: `$PSScriptRoot`
is empty and the exe's folder is used for files next to it.

### Requirements

- Build: dotnet SDK 6 or newer; nuget.org access for the first build
- Run: Windows with PowerShell 5.1 and .NET Framework 4.6.2 or later

### Limitations

- Modules are loaded from embedded source, so `$PSScriptRoot` is empty inside
  them. `build.sh` adjusts its embedded copy of HardeningKitty for this;
  other modules that rely on `$PSScriptRoot` need the same treatment.
- Progress bars (`Write-Progress`) are not shown, and nested prompts are not
  supported.
- `twigs.exe -?` prints the help comment at the top of the script instead of
  running it.
