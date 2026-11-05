# twigs for Windows (PowerShell, exe and MSI)

This folder holds the Windows version of twigs (`twigs.ps1` and
`ShadowAI.psm1`) and the Linux scripts that turn it into release artifacts:

| Script | Produces |
|---|---|
| [`build.sh`](#buildsh--zip-artifacts) | `twigs-powershell-<version>.zip`, `twigs-exe-<version>.zip`, `SHA256SUMS` |
| [`build_msi.sh`](#build_msish--windows-installer) | runs `build.sh`, then `twigs-<version>-x64.msi` from the exe zip |
| [`ps2exe.sh`](#ps2exesh--script-to-exe) | `twigs.exe` from `twigs.ps1` (called by `build.sh`) |
| [`install_osslsigncode.sh`](#install_osslsigncodesh--signing-tool) | builds and installs `osslsigncode` (Authenticode signing on Linux) |
| [`make_signing_cert.sh`](#make_signing_certsh--self-signed-certificate) | a self-signed code signing certificate for `build.sh` |

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
./build.sh [-v version] [-k hk_version] [-o output_dir] [-a] [-s]
```

| Option | Default | Meaning |
|---|---|---|
| `-v version` | `__version__` in `twigs/__init__.py` | Version used in the zip names, set in `twigs.ps1` (`$twigs_version`) and as twigs.exe's file/product version |
| `-k hk_version` | latest HardeningKitty release | HardeningKitty tag, branch or commit to download, e.g. `v.0.9.4`, `master`, `da0976073caa` |
| `-o output_dir` | `powershell/dist` | Where the zips and `SHA256SUMS` are written |
| `-a` | off | Build twigs.exe to ask for administrator rights (UAC) when it starts |
| `-s` | off | Require code signing: fail if no signing certificate is configured (see [Code signing](#code-signing)) |
| `-h` | | Show help |

`GITHUB_TOKEN`, if set (as on GitHub Actions), is used for the GitHub API calls
that find the latest HardeningKitty release.

### What it does

1. Downloads [HardeningKitty](https://github.com/scipag/HardeningKitty) at the
   chosen version and keeps only what twigs uses: the module, its default
   finding list, the signed list manifest and the licence. The list and manifest
   names are read from the module, so a release that renames them still builds.
2. Sets `$twigs_version` in a copy of `twigs.ps1`. The source copy stays `'dev'`.
   If a signing certificate is configured, signs that copy and `ShadowAI.psm1`.
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
| `BUILD-INFO.txt` (twigs version, signing certificate, HardeningKitty version, commit and file SHA-256s) | ✓ | ✓ |
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

### Code signing

Signing is optional. It is turned on by pointing `build.sh` at a PKCS#12
(`.p12`) file holding the code signing certificate and its private key. Without
one, the build is unsigned (or fails, with `-s`).

| Variable | Meaning |
|---|---|
| `TW_SIGN_P12` | The `.p12` (or `.pfx`) file with the certificate and private key |
| `TW_SIGN_PASS` | Its passphrase. If not set, `build.sh` asks for it when run from a terminal, and fails otherwise |
| `OSSLSIGNCODE` | osslsigncode binary. Default: from `PATH`, then `~/.local/bin/osslsigncode` |

```bash
./install_osslsigncode.sh                  # once per build machine

TW_SIGN_P12=/path/to/twigs-signing.p12 ./build.sh -s       # asks for the passphrase
TW_SIGN_P12=/path/to/twigs-signing.p12 TW_SIGN_PASS='...' ./build_msi.sh   # passes the variables on to build.sh
```

The passphrase is handed to `openssl` and `osslsigncode` in a temporary file
(mode 600, deleted at the end of the build), not on their command lines. Both
current (AES) and older (RC2 / 3DES) `.p12` encryption are accepted.

What is signed (Authenticode, SHA-256, with "ThreatWorx twigs" as the
description):

| File | Signed by the build |
|---|---|
| `twigs.ps1` | yes, after the version is set. This replaces the signature block in the source copy |
| `ShadowAI.psm1` | yes |
| `twigs.exe` | no. It embeds the signed `twigs.ps1` and `ShadowAI.psm1`, but the exe itself is unsigned |
| `HardeningKitty.psm1` / `.psd1` | no, they keep the HardeningKitty authors' own signature (scip ag), which stays valid because the files ship unchanged |
| the MSI and `schedule_task.ps1` | no (see the MSI limitations) |

After signing, each file's signature is checked against its contents and the
build fails if they don't match. The build also reports whether the
certificate chain is trusted on the build machine, but doesn't fail on that:
trust is decided on each Windows machine. The certificate's subject,
thumbprint and expiry date are written to `BUILD-INFO.txt`.

**No timestamp.** Signatures are not timestamped, so signing needs no network
access. A signature is valid only while the certificate is: when the
certificate expires, Windows treats files signed with it as having an invalid
signature, and they need to be rebuilt with a new certificate. `build.sh`
refuses an expired certificate and warns when it expires within 30 days.

**Trust on Windows.** A signature only helps where Windows trusts the
certificate:

- A certificate from a public CA is trusted everywhere.
- A self-signed certificate (from `make_signing_cert.sh`) is trusted only where
  its `.cer` file is imported into both **Trusted Root Certification
  Authorities** and **Trusted Publishers** for the machine. Use Group Policy or
  Intune, or run as administrator:
  `Import-Certificate -FilePath twigs-signing.cer -CertStoreLocation Cert:\LocalMachine\Root`
  and the same with `Cert:\LocalMachine\TrustedPublisher`. Elsewhere the
  signature shows as untrusted and `AllSigned` still refuses the scripts.

With the certificate trusted, `twigs.ps1` runs under the `AllSigned` and
`RemoteSigned` policies without `-ExecutionPolicy Bypass`. `run_twigs.bat`
uses `Bypass` either way.

**Keep the private key secret.** Anyone with the `.pfx` and its password can
sign code that machines trusting the certificate will run. Keep it outside the
repo, for example as a CI secret, and don't install a self-signed certificate
anywhere except the machines that need it.

### Requirements (build machine)

- Linux (tested on Ubuntu 20.04) with `bash`, `curl`, `tar`, `sha256sum`, and
  `zip` or `python3`
- dotnet SDK 6 or newer (for `ps2exe.sh`)
- Network access to GitHub (HardeningKitty) and nuget.org (first exe build only)
- For signing: osslsigncode 2.8 or newer (`install_osslsigncode.sh`) and `openssl`

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
- **Unsigned builds.** Without a signing certificate, the signature block kept
  in the source `twigs.ps1` becomes invalid in the zip, because the version is
  written into the file, and `ShadowAI.psm1` is unsigned. Running `twigs.ps1`
  directly under `AllSigned` or `RemoteSigned` then fails (`run_twigs.bat` uses
  `Bypass` and is unaffected). See [Code signing](#code-signing).
- **twigs.exe is never code-signed**, even when signing is configured, so
  Windows SmartScreen and some endpoint security tools may warn about or block it.
- **Signing needs a trusted certificate to be useful.** A self-signed signature
  is only trusted on machines that have its certificate installed.
- **Signed files expire with the certificate**, because they are not
  timestamped. Releases built before a certificate expires must be rebuilt
  after it is replaced.
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
  run interactively. twigs.exe inside it is not signed either.
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

---

## install_osslsigncode.sh — signing tool

Downloads, builds and installs [osslsigncode](https://github.com/mtrojnar/osslsigncode),
which signs PowerShell scripts, `.exe` and `.msi` files with Authenticode on
Linux. Signing PowerShell scripts needs osslsigncode 2.8 or newer. Ubuntu's own
package is older than that, so the script builds it from the upstream release.

```
./install_osslsigncode.sh [-v version] [-p prefix] [-f] [-t]
```

| Option | Default | Meaning |
|---|---|---|
| `-v version` | latest release | osslsigncode release tag to build, e.g. `2.14` |
| `-p prefix` | `/usr/local` as root, otherwise `~/.local` | Install prefix; the binary goes to `<prefix>/bin` |
| `-f` | off | Rebuild even if that version is already installed at the prefix |
| `-t` | off | Run the upstream test suite before installing |

Steps:

1. Installs any missing build packages with `apt-get`, using `sudo` when not
   root: `build-essential pkg-config libssl-dev libcurl4-openssl-dev
   zlib1g-dev curl ca-certificates python3`.
2. Uses the system `cmake` if it is 3.17 or newer. Otherwise (Ubuntu 20.04 has
   3.16), it installs a current cmake with pip into the temporary build
   directory only. The system cmake is not changed.
3. Downloads the release tarball and builds it in a temporary directory. It
   installs the binary, docs and bash completion under the prefix, then
   deletes the temporary directory.

Running it again with the same version does nothing. Use `-f` to rebuild.

### Requirements

- Ubuntu 20.04 or newer, or another Debian-based system
- Network access to github.com, and on Ubuntu 20.04 also to pypi.org (for cmake)
- `sudo` rights if build packages are missing or the prefix is not writable
- `GITHUB_TOKEN` (optional) is used for the GitHub API call that finds the latest release

### Limitations

- apt-based systems only.
- It doesn't add the prefix to `PATH`. `~/.local/bin` usually is on `PATH`
  already; the script prints a note if it isn't.
- It doesn't uninstall. To remove osslsigncode, delete `<prefix>/bin/osslsigncode`,
  `<prefix>/share/doc/osslsigncode` and
  `<prefix>/share/bash-completion/completions/osslsigncode.bash`.
- It only installs the tool. `build.sh` uses it when signing is configured
  (see [Code signing](#code-signing)).

---

## make_signing_cert.sh — self-signed certificate

Creates a self-signed code signing certificate for `build.sh`'s
`TW_SIGN_P12`. It is enough for machines you manage, where you can install the
certificate. For anything else, use a certificate from a public CA instead
(see [Code signing](#code-signing)).

```
./make_signing_cert.sh [-n common_name] [-d days] [-o output_dir] [-b basename] [-f]
```

| Option | Default | Meaning |
|---|---|---|
| `-n common_name` | `ThreatWorx twigs code signing` | Certificate subject (shown as the publisher on Windows) |
| `-d days` | `1095` (three years) | Validity |
| `-o output_dir` | current directory | Where the files are written |
| `-b basename` | `twigs-signing` | Output file name, without extension |
| `-f` | off | Overwrite existing files |

The `.pfx` password comes from `TW_SIGN_PASS`, or the script asks for it.

| File | Contents |
|---|---|
| `<basename>.pfx` | Certificate and private key, password protected, mode 600. **Keep secret.** Used as `TW_SIGN_P12` |
| `<basename>.cer` | Public certificate (DER), to import on Windows into Trusted Root and Trusted Publishers |
| `<basename>.pem` | The same public certificate in PEM form |

The certificate is RSA 3072 / SHA-256, with code signing usage. It is marked
as its own CA, which Windows needs to accept it from the Trusted Root store.

### Limitations

- A new certificate has a new thumbprint, so machines need the new `.cer` when
  it is replaced. `build.sh` doesn't timestamp, so files signed with the old
  certificate stop being valid when it expires.
- No revocation. If the key leaks, remove the certificate from every machine
  that trusts it.
- The `.pfx` uses AES-256 encryption, which Windows 10 1709 / Server 2019 and
  later can import. That only matters for signing on Windows: build.sh only
  needs it on Linux, and Windows machines only need the `.cer`.
