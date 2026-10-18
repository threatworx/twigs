# ShadowAI.psm1
#
# Shared shadow-AI discovery logic for Windows hosts. Consumed by:
#   - twigs.ps1 (standalone local discovery) via Import-Module, same pattern
#     used there for HardeningKitty.psm1
#   - twigs/windows.py (win_host / WinRM mode), which sends this file's
#     contents inline over the WinRM session since there is no file-copy
#     step in that path today
#
# Detection signatures live in shadow_ai_signatures.json (shared with the
# Linux/macOS implementation in twigs/shadow_ai.py) so the catalog of known
# AI tools/runtimes/models is maintained in one place. This module only
# contains the Windows-specific "how to check" logic.

function New-ShadowAIIssue {
    param([string]$TwcId, [string]$Title, [string]$Details, [string]$Rating, [string]$ObjectId, [string]$AssetId)
    return [ordered]@{
        twc_id      = "shadow-ai-$TwcId"
        asset_id    = $AssetId
        twc_title   = $Title
        details     = $Details
        rating      = $Rating
        object_id   = $ObjectId
        object_meta = ''
        type        = 'Shadow AI'
    }
}

function ConvertTo-ShadowAISlug {
    param([string[]]$Parts)
    $s = ($Parts -join '-').ToLower()
    $s = [regex]::Replace($s, '[^a-z0-9]+', '-').Trim('-')
    if ($s.Length -gt 80) { $s = $s.Substring(0, 80) }
    return $s
}

function Get-ShadowAIModelClass {
    param([string]$Name, $Families)
    $lname = $Name.ToLower()
    foreach ($fam in $Families) {
        foreach ($m in $fam.match) {
            if ($lname.Contains($m.ToLower())) {
                return @{ Class = 'public'; Vendor = $fam.vendor }
            }
        }
    }
    return @{ Class = 'custom'; Vendor = $null }
}

function Get-ShadowAIOllamaModelName {
    param([string]$Path)
    $tokens = $Path -split '[\\/]' | Where-Object { $_ -ne '' }
    if ($tokens.Length -ge 2) {
        return "$($tokens[$tokens.Length-2]):$($tokens[$tokens.Length-1])"
    }
    return $Path
}

function Invoke-ShadowAIVersionProbe {
    param([string]$Path, [int]$TimeoutMs = 3000)
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Path
        $psi.Arguments = '--version'
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardInput = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.StandardInput.Close()
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutMs)) {
            try { $proc.Kill() } catch {}
            return $null
        }
        $out = (($stdoutTask.Result + "`n" + $stderrTask.Result)).Trim()
        if ($out) {
            return ($out -split "`r?`n")[0]
        }
        return $null
    } catch {
        return $null
    }
}

function ConvertTo-ShadowAIWin32Arg {
    # Windows command-line argument quoting (CommandLineToArgvW convention):
    # wrap in double quotes, escape any embedded double quote. Needed because
    # temp/profile paths and SQL text may contain spaces (e.g. a user profile
    # path like "C:\Users\John Doe\AppData\Local\Temp\...").
    param([string]$Value)
    return '"' + ($Value -replace '"', '\"') + '"'
}

function Invoke-ShadowAISqliteQuery {
    # Returns an array of output lines on a clean, successful (exit code 0)
    # query, or $null on ANY failure - launch failure, timeout, non-zero
    # exit, or an unexpected exception. Callers must treat $null as "report
    # nothing for this query" rather than attempt to salvage partial output,
    # since a non-zero exit can still leave misleading text on stdout.
    param([string]$SqliteExePath, [string]$DbPath, [string]$Sql, [int]$TimeoutMs = 8000)
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $SqliteExePath
        $psi.Arguments = (ConvertTo-ShadowAIWin32Arg '-separator') + ' ' + (ConvertTo-ShadowAIWin32Arg '|') + ' ' +
            (ConvertTo-ShadowAIWin32Arg $DbPath) + ' ' + (ConvertTo-ShadowAIWin32Arg $Sql)
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardInput = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.StandardInput.Close()
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutMs)) {
            try { $proc.Kill() } catch {}
            return $null
        }
        if ($proc.ExitCode -ne 0) { return $null }
        $out = $stdoutTask.Result
        if (-not $out) { return @() }
        return @($out -split "`r?`n" | Where-Object { $_ -ne '' })
    } catch {
        return $null
    }
}

function Invoke-ShadowAIBoundedProcess {
    # Generic bounded external-process invocation: returns stdout lines on a
    # clean (exit code 0) run, or $null on ANY failure - launch failure,
    # timeout, non-zero exit, or an unexpected exception. Same hard-failure-
    # safety convention as Invoke-ShadowAISqliteQuery, generalized to an
    # arbitrary FileName/Arguments pair (used by the WSL CLI-tool probe).
    param([string]$FileName, [string]$Arguments, [int]$TimeoutMs = 8000)
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FileName
        $psi.Arguments = $Arguments
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardInput = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.StandardInput.Close()
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutMs)) {
            try { $proc.Kill() } catch {}
            return $null
        }
        if ($proc.ExitCode -ne 0) { return $null }
        $out = $stdoutTask.Result
        if (-not $out) { return @() }
        return @($out -split "`r?`n" | Where-Object { $_ -ne '' })
    } catch {
        return $null
    }
}

function Get-ShadowAIHfModelName {
    param([string]$DirName)
    if ($DirName.StartsWith('models--')) {
        $rest = $DirName.Substring(8)
        $segs = $rest -split '--'
        if ($segs.Length -ge 2) {
            $org = $segs[0]
            $model = ($segs[1..($segs.Length-1)] -join '--')
            return @{ Name = "$org/$model"; Org = $org }
        }
        return @{ Name = $rest; Org = $null }
    }
    return @{ Name = $DirName; Org = $null }
}

function ConvertTo-ShadowAIBrowsingCaseSql {
    param($AiChatDomains)
    $parts = @()
    foreach ($entry in $AiChatDomains) {
        $name = $entry.name -replace "'", "''"
        $conds = ($entry.domains | ForEach-Object { "url LIKE '%" + ($_ -replace "'", "''") + "%'" }) -join ' OR '
        $parts += "WHEN $conds THEN '$name'"
    }
    return "CASE " + ($parts -join ' ') + " ELSE '' END"
}

function Get-ShadowAIBrowsingSql {
    param([string]$Family, [string]$CaseExpr)
    if ($Family -eq 'chromium') {
        $table = 'urls'; $cntCol = 'visit_count'; $tsCol = 'last_visit_time'
    } else {
        $table = 'moz_places'; $cntCol = 'visit_count'; $tsCol = 'last_visit_date'
    }
    # The no-match ('') bucket is dropped in SQL itself rather than relying
    # on the caller to skip it.
    $inner = "SELECT $CaseExpr AS tag, SUM($cntCol) AS cnt, MAX($tsCol) AS ts FROM $table GROUP BY 1"
    return "SELECT tag, cnt, ts FROM ($inner) WHERE tag <> '';"
}

function ConvertFrom-ShadowAIBrowsingTimestamp {
    param([int64]$Value, [string]$Family)
    try {
        if ($Family -eq 'chromium') {
            # Chromium: microseconds since 1601-01-01 UTC. 1 microsecond = 10 .NET ticks (100ns).
            $epoch = [DateTime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
            $dt = $epoch.AddTicks($Value * 10)
        } else {
            # Firefox: microseconds since the Unix epoch.
            $dt = [DateTimeOffset]::FromUnixTimeMilliseconds([int64]($Value / 1000)).UtcDateTime
        }
        return $dt.ToString('yyyy-MM-dd')
    } catch {
        return $null
    }
}

<#
.SYNOPSIS
    Runs the shadow-AI discovery checks on the local Windows host.
.PARAMETER Signatures
    The parsed shadow_ai_signatures.json object (ConvertFrom-Json).
.PARAMETER InstalledProducts
    Already-collected "<Name> <Version>" product strings (reused to avoid
    re-querying the Uninstall registry keys a second time).
.PARAMETER AssetId
    The asset id the resulting config_issues should be attributed to.
.OUTPUTS
    Hashtable with keys: config_issues, products, tags
#>
function Invoke-ShadowAIScan {
    param(
        [Parameter(Mandatory=$true)] $Signatures,
        [Parameter(Mandatory=$true)] [AllowEmptyCollection()] [string[]]$InstalledProducts,
        [Parameter(Mandatory=$true)] [string]$AssetId,
        [bool]$CheckCredentials = $false,
        [bool]$CheckPackages = $false,
        [bool]$CheckBrowsing = $false,
        [bool]$CheckWsl = $false
    )

    $sig = $Signatures.windows
    $families = $Signatures.public_model_families
    $configIssues = New-Object System.Collections.Generic.List[object]
    $products = New-Object System.Collections.Generic.List[string]
    $tagsList = New-Object System.Collections.Generic.List[string]
    $foundAny = $false

    # --- Desktop apps: match against already-collected installed product names ---
    foreach ($app in $sig.desktop_apps) {
        $matchedEntry = $null
        foreach ($pattern in $app.match) {
            $hits = $InstalledProducts -match [regex]::Escape($pattern)
            if ($hits -and $hits.Count -gt 0) { $matchedEntry = $hits[0]; break }
        }
        if ($matchedEntry) {
            $foundAny = $true
            # $matchedEntry is already an element of $InstalledProducts, which the
            # caller (twigs.ps1 / windows.py) already carries as a product - do not
            # add it to $products again here, or it ends up duplicated verbatim.
            $tagsList.Add("SHADOW_AI:$($app.product)")
            $slug = ConvertTo-ShadowAISlug @('app', $app.product)
            $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($app.product) ($($app.category)) detected" "Found via installed-application registry entry [$matchedEntry]." '2' $app.product $AssetId))
        }
    }

    # --- Known filesystem paths ---
    foreach ($p in $sig.paths) {
        try {
            $expanded = $ExecutionContext.InvokeCommand.ExpandString($p.path)
        } catch { continue }
        if (Test-Path $expanded -ErrorAction SilentlyContinue) {
            $foundAny = $true
            $products.Add("$($p.product) (detected)")
            $tagsList.Add("SHADOW_AI:$($p.product)")
            $slug = ConvertTo-ShadowAISlug @('path', $p.product, $expanded)
            $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($p.product) ($($p.category)) detected" "Found at [$expanded]." '2' $expanded $AssetId))
        }
    }

    # --- CLI tools on PATH ---
    foreach ($cli in $sig.cli_tools) {
        $cmd = Get-Command $cli.bin -ErrorAction SilentlyContinue
        if ($cmd) {
            $foundAny = $true
            $verLine = Invoke-ShadowAIVersionProbe -Path $cmd.Source
            $verMatch = $null
            if ($verLine) { $verMatch = [regex]::Match($verLine, '\d+\.\d+(\.\d+)*') }
            if ($verMatch -and $verMatch.Success) {
                $products.Add("$($cli.product) $($verMatch.Value)")
            } else {
                $products.Add("$($cli.product) (detected)")
            }
            $tagsList.Add("SHADOW_AI:$($cli.product)")
            $details = "Binary [$($cli.bin)] found on PATH at [$($cmd.Source)]."
            if ($verLine) { $details += " Version output: $verLine" }
            $slug = ConvertTo-ShadowAISlug @('cli', $cli.product)
            $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($cli.product) ($($cli.category)) CLI available" $details '2' $cli.bin $AssetId))
        }
    }

    # --- Appx (Store) packages ---
    foreach ($ax in $sig.appx_packages) {
        try {
            $pkgs = Get-AppxPackage -Name $ax.match -ErrorAction SilentlyContinue
        } catch { $pkgs = $null }
        if ($pkgs) {
            $foundAny = $true
            $pkg = @($pkgs)[0]
            if ($pkg.Version) {
                $products.Add("$($ax.product) $($pkg.Version)")
            } else {
                $products.Add("$($ax.product) (detected)")
            }
            $tagsList.Add("SHADOW_AI:$($ax.product)")
            $slug = ConvertTo-ShadowAISlug @('appx', $ax.product)
            $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($ax.product) ($($ax.category)) installed" "Matched AppX package [$($pkg.PackageFullName)]." '2' $ax.match $AssetId))
        }
    }

    # --- Registry markers (feature toggles etc.) ---
    foreach ($rk in $sig.registry_run_keys) {
        if (Test-Path $rk -ErrorAction SilentlyContinue) {
            $foundAny = $true
            $tagsList.Add('SHADOW_AI:Windows Copilot')
            $slug = ConvertTo-ShadowAISlug @('reg', $rk)
            $configIssues.Add((New-ShadowAIIssue $slug 'Shadow AI: Windows Copilot registry marker present' "Registry key [$rk] exists." '2' $rk $AssetId))
        }
    }

    # --- Running processes ---
    try { $procs = Get-Process -ErrorAction SilentlyContinue } catch { $procs = @() }
    foreach ($proc in $sig.processes) {
        $match = $procs | Where-Object { $_.ProcessName -match $proc.match } | Select-Object -First 1
        if ($match) {
            $foundAny = $true
            $tagsList.Add("SHADOW_AI:$($proc.product)")
            $slug = ConvertTo-ShadowAISlug @('proc', $proc.product)
            $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($proc.product) ($($proc.category)) running" "Matching process [$($match.ProcessName)] (PID $($match.Id))." '3' $proc.product $AssetId))
        }
    }

    # --- Services ---
    try { $svcs = Get-Service -ErrorAction SilentlyContinue } catch { $svcs = @() }
    foreach ($svc in $sig.services) {
        $match = $svcs | Where-Object { $_.Name -match $svc.match -or $_.DisplayName -match $svc.match } | Select-Object -First 1
        if ($match -and $match.Status -eq 'Running') {
            $foundAny = $true
            $tagsList.Add("SHADOW_AI:$($svc.product)")
            $slug = ConvertTo-ShadowAISlug @('svc', $svc.product)
            $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($svc.product) ($($svc.category)) running as a service" "Service [$($match.Name)] is running." '3' $match.Name $AssetId))
        }
    }

    # --- Listening ports ---
    try { $conns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue } catch { $conns = @() }
    foreach ($portSig in $sig.ports) {
        $hit = $conns | Where-Object { $_.LocalPort -eq $portSig.port } | Select-Object -First 1
        if ($hit) {
            $ownerName = ''
            try {
                $ownerProc = Get-Process -Id $hit.OwningProcess -ErrorAction SilentlyContinue
                if ($ownerProc) { $ownerName = $ownerProc.ProcessName }
            } catch {}
            if ($portSig.process_match -and $ownerName -and -not ($ownerName -match $portSig.process_match)) { continue }
            $exposed = $hit.LocalAddress -eq '0.0.0.0' -or $hit.LocalAddress -eq '::'
            $rating = if ($exposed) { '4' } else { '3' }
            $exposureNote = if ($exposed) { ' This port is bound to all interfaces (0.0.0.0), not just localhost - it may be reachable from the network.' } else { ' Bound to localhost.' }
            $foundAny = $true
            $tagsList.Add("SHADOW_AI:$($portSig.product)")
            $slug = ConvertTo-ShadowAISlug @('port', $portSig.product, $portSig.port)
            $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($portSig.product) listening on port $($portSig.port)" "Owning process [$ownerName].$exposureNote" $rating "$($portSig.port)" $AssetId))
        }
    }

    # --- VS Code IDE extensions ---
    $extDirs = @()
    foreach ($base in @("$env:USERPROFILE\.vscode\extensions", "$env:USERPROFILE\.vscode-server\extensions")) {
        if (Test-Path $base -ErrorAction SilentlyContinue) {
            $extDirs += (Get-ChildItem -Path $base -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        }
    }
    $seenExt = @{}
    foreach ($extDir in $extDirs) {
        # VS Code extension dirs are named "<publisher>.<extension>-<version>";
        # capture the version so we can report it, not just presence.
        $extMatch = [regex]::Match($extDir, '^(.*?)-(\d+(?:\.\d+)*)(?:-[a-zA-Z0-9]+)?$')
        if ($extMatch.Success) {
            $extId = $extMatch.Groups[1].Value.ToLower()
            $extVersion = $extMatch.Groups[2].Value
        } else {
            $extId = $extDir.ToLower()
            $extVersion = $null
        }
        $ideMatch = $sig.ide_extensions | Where-Object { $_.vscode_id -and $_.vscode_id.ToLower() -eq $extId } | Select-Object -First 1
        if ($ideMatch -and -not $seenExt.ContainsKey($extId)) {
            $seenExt[$extId] = $true
            $foundAny = $true
            if ($extVersion) {
                $products.Add("$($ideMatch.product) $extVersion")
            } else {
                $products.Add("$($ideMatch.product) (detected)")
            }
            $tagsList.Add("SHADOW_AI:$($ideMatch.product)")
            $slug = ConvertTo-ShadowAISlug @('ideext', $ideMatch.product)
            $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($ideMatch.product) ($($ideMatch.category)) installed" "VS Code extension directory [$extDir] found." '2' $extDir $AssetId))
        }
    }

    # --- JetBrains IDE plugins (IntelliJ/PyCharm/Rider/WebStorm/...) ---
    # The VS Code check above only looks at .vscode/extensions - a real blind
    # spot for anyone using a JetBrains IDE instead. Matched by plugin
    # directory name (JetBrains keeps these human-readable, unlike VS Code's
    # "publisher.id-version" convention), not a deep plugin.xml/jar read -
    # same pragmatic name-pattern approach used for desktop_apps/appx_packages
    # elsewhere in this module.
    $jbPluginDirs = Get-ChildItem -Path "$env:APPDATA\JetBrains\*\plugins\*" -Directory -ErrorAction SilentlyContinue
    $seenJb = @{}
    foreach ($pd in $jbPluginDirs) {
        foreach ($ide in $sig.ide_extensions) {
            if (-not $ide.jetbrains_match) { continue }
            if ($seenJb.ContainsKey($ide.product)) { continue }
            $hit = $false
            foreach ($pat in $ide.jetbrains_match) {
                if ($pd.Name -match [regex]::Escape($pat)) { $hit = $true; break }
            }
            if ($hit) {
                $seenJb[$ide.product] = $true
                $foundAny = $true
                $products.Add("$($ide.product) (detected, JetBrains)")
                $tagsList.Add("SHADOW_AI:$($ide.product)")
                $slug = ConvertTo-ShadowAISlug @('jbplugin', $ide.product)
                $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($ide.product) ($($ide.category)) installed (JetBrains)" "JetBrains plugin directory [$($pd.FullName)] found." '2' $pd.FullName $AssetId))
            }
        }
    }

    # --- Visual Studio (VSIX) extensions ---
    # Separate from the VS Code check above - "Visual Studio" (devenv.exe) and
    # "Visual Studio Code" use entirely different extension mechanisms despite
    # the similar name. Extensions live under Publisher\Name\Version, hence
    # -Recurse; -Depth bounds it in case of unexpectedly deep nesting.
    $vsExtDirs = Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\VisualStudio\*\Extensions" -Recurse -Depth 3 -Directory -ErrorAction SilentlyContinue
    $seenVs = @{}
    foreach ($pd in $vsExtDirs) {
        foreach ($ide in $sig.ide_extensions) {
            if (-not $ide.vs_match) { continue }
            if ($seenVs.ContainsKey($ide.product)) { continue }
            $hit = $false
            foreach ($pat in $ide.vs_match) {
                if ($pd.Name -match [regex]::Escape($pat)) { $hit = $true; break }
            }
            if ($hit) {
                $seenVs[$ide.product] = $true
                $foundAny = $true
                $products.Add("$($ide.product) (detected, Visual Studio)")
                $tagsList.Add("SHADOW_AI:$($ide.product)")
                $slug = ConvertTo-ShadowAISlug @('vsext', $ide.product)
                $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($ide.product) ($($ide.category)) installed (Visual Studio)" "Visual Studio extension directory [$($pd.FullName)] found." '2' $pd.FullName $AssetId))
            }
        }
    }

    # --- Browser extensions (Chrome / Edge) ---
    $browserExtIds = @{}
    foreach ($browser in $sig.browser_extensions.PSObject.Properties) {
        foreach ($p in $browser.Value.PSObject.Properties) { $browserExtIds[$p.Name] = $p.Value }
    }
    $browserBases = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Extensions",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Extensions"
    )
    $seenBext = @{}
    foreach ($base in $browserBases) {
        $dirs = Get-ChildItem -Path $base -Directory -ErrorAction SilentlyContinue
        foreach ($d in $dirs) {
            $extName = $browserExtIds[$d.Name]
            if ($extName -and -not $seenBext.ContainsKey($d.Name)) {
                $seenBext[$d.Name] = $true
                $foundAny = $true
                $tagsList.Add("SHADOW_AI:$extName")
                $slug = ConvertTo-ShadowAISlug @('browserext', $extName, $d.Name)
                $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: browser extension $extName detected" "Extension ID [$($d.Name)] found in a browser profile." '2' $d.Name $AssetId))
            }
        }
    }

    # --- Browser "installed as app" (PWA) shortcuts for AI chat sites ---
    # Chrome/Edge's "Install <site> as app" creates a Start Menu/Desktop
    # shortcut that launches the browser in app mode for that one site -
    # a lightweight way to get a "desktop app" for e.g. ChatGPT/Claude/Gemini
    # that leaves no trace in the Uninstall registry or AppX packages, so it
    # is otherwise invisible to every check above. Requires both a name match
    # (the shortcut is normally named after the site) AND a browser-app-mode
    # target/arguments, to avoid false-positives on an unrelated shortcut that
    # happens to share a name.
    if ($Signatures.ai_chat_domains) {
        $shortcutDirs = @(
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
            "$env:USERPROFILE\Desktop"
        )
        $shortcuts = @()
        foreach ($dir in $shortcutDirs) {
            if (Test-Path $dir -ErrorAction SilentlyContinue) {
                $shortcuts += Get-ChildItem -Path $dir -Filter '*.lnk' -Recurse -ErrorAction SilentlyContinue
            }
        }
        if ($shortcuts.Count -gt 0) {
            $seenPwa = @{}
            $wsh = $null
            try { $wsh = New-Object -ComObject WScript.Shell } catch {}
            if ($wsh) {
                foreach ($lnk in $shortcuts) {
                    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($lnk.Name)
                    # Catalog names carry a "(web)" disambiguator (vs. e.g.
                    # a desktop-app entry of the same product) that a real
                    # PWA shortcut's filename - named after the page title at
                    # install time - would never include, so compare against
                    # the stripped form too.
                    $aiMatch = $Signatures.ai_chat_domains | Where-Object {
                        $baseName -eq $_.name -or $baseName -eq ($_.name -replace '\s*\(web\)$', '').Trim()
                    } | Select-Object -First 1
                    if (-not $aiMatch -or $seenPwa.ContainsKey($aiMatch.name)) { continue }
                    $isBrowserApp = $false
                    try {
                        $shortcut = $wsh.CreateShortcut($lnk.FullName)
                        $targetName = [System.IO.Path]::GetFileName($shortcut.TargetPath)
                        $isBrowserApp = ($targetName -match '^(chrome|msedge|msedgewebview2|brave|chromium)\.exe$') -and ($shortcut.Arguments -match '--app(-id)?=')
                    } catch {}
                    if ($isBrowserApp) {
                        $seenPwa[$aiMatch.name] = $true
                        $foundAny = $true
                        $tagsList.Add("SHADOW_AI:$($aiMatch.name)")
                        $slug = ConvertTo-ShadowAISlug @('pwa', $aiMatch.name)
                        $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($aiMatch.name) installed as a browser app (PWA)" "Shortcut [$($lnk.FullName)] launches a browser in app mode for this AI chat site - installed outside any managed software deployment, and would not appear in the Uninstall registry or AppX packages." '2' $lnk.FullName $AssetId))
                    }
                }
            }
        }
    }

    # --- Windows Firewall rules referencing local-LLM-server binaries ---
    # A persistence signal that survives even when the process/service isn't
    # currently running: Ollama/LM Studio/text-generation-webui/vLLM commonly
    # create an inbound allow rule the first time they bind a port, and that
    # rule remains after the app is closed. Bulk-fetch rules and application
    # filters once and join in memory (both expose the same InstanceID) rather
    # than querying per rule, which would be far slower against the hundreds
    # of built-in Windows Firewall rules a typical host already has.
    try {
        $fwRules = Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction SilentlyContinue
    } catch { $fwRules = $null }
    if ($fwRules) {
        try { $fwFilters = Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue } catch { $fwFilters = $null }
        $fwFilterByInstance = @{}
        if ($fwFilters) {
            foreach ($f in $fwFilters) { $fwFilterByInstance[$f.InstanceID] = $f }
        }
        $seenFw = @{}
        foreach ($rule in $fwRules) {
            if ($rule.Enabled -ne 'True' -and $rule.Enabled -ne $true) { continue }
            $appFilter = $fwFilterByInstance[$rule.InstanceID]
            $progPath = if ($appFilter -and $appFilter.Program -and $appFilter.Program -ne 'Any') { $appFilter.Program } else { $null }
            $haystack = "$($rule.DisplayName) $progPath"
            foreach ($proc in $sig.processes) {
                if ($seenFw.ContainsKey($proc.product)) { continue }
                # Word-boundary wrapped: a bare substring match would let
                # e.g. the "llama" alternative in llama.cpp server's pattern
                # match inside "Ollama"'s own rule/program-path text.
                if ($haystack -match ('\b(?:' + $proc.match + ')\b')) {
                    $seenFw[$proc.product] = $true
                    $foundAny = $true
                    $tagsList.Add("SHADOW_AI:$($proc.product)")
                    $slug = ConvertTo-ShadowAISlug @('firewall', $proc.product)
                    $detailProg = if ($progPath) { " Program [$progPath]." } else { '' }
                    $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: inbound firewall rule for $($proc.product) ($($proc.category))" "Firewall rule [$($rule.DisplayName)] allows inbound traffic.$detailProg This persists even when the application is not currently running, unlike the process/port/service checks above." '2' $rule.Name $AssetId))
                }
            }
        }
    }

    # --- Credential markers (presence only, never read values) ---
    if ($CheckCredentials) {
        foreach ($envVar in $sig.credential_markers.env_vars) {
            $val = [System.Environment]::GetEnvironmentVariable($envVar)
            if ($val) {
                $foundAny = $true
                $slug = ConvertTo-ShadowAISlug @('credenv', $envVar)
                $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: AI provider credential env var set [$envVar]" "Environment variable [$envVar] is set for this host/user. Value was not read." '4' $envVar $AssetId))
            }
        }
        foreach ($p in $sig.credential_markers.paths) {
            try { $expanded = $ExecutionContext.InvokeCommand.ExpandString($p) } catch { continue }
            if (Test-Path $expanded -ErrorAction SilentlyContinue) {
                $foundAny = $true
                $slug = ConvertTo-ShadowAISlug @('credpath', $expanded)
                $configIssues.Add((New-ShadowAIIssue $slug 'Shadow AI: AI tool credential/config file present' "Path [$expanded] exists. Contents were not read." '3' $expanded $AssetId))
            }
        }
    }

    # --- Locally stored models ---
    foreach ($ms in $sig.model_stores) {
        try { $storePath = $ExecutionContext.InvokeCommand.ExpandString($ms.path) } catch { continue }
        if (-not (Test-Path $storePath -ErrorAction SilentlyContinue)) { continue }

        if ($ms.type -eq 'ollama_manifest') {
            $files = Get-ChildItem -Path $storePath -Recurse -File -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                $rel = $f.FullName.Substring($storePath.Length).TrimStart('\', '/')
                $modelName = Get-ShadowAIOllamaModelName $rel
                $cls = Get-ShadowAIModelClass $modelName $families
                $foundAny = $true
                $products.Add("$($ms.runtime) Model: $modelName")
                $tagsList.Add("AI_MODEL:$modelName")
                $tagsList.Add("AI_MODEL_CLASS:$($cls.Class)")
                $rating = if ($cls.Class -eq 'custom') { '3' } else { '2' }
                $vendorNote = if ($cls.Vendor) { " Matches known public model family ($($cls.Vendor))." } else { ' Does not match a known public model family - treat as custom/unreviewed.' }
                $slug = ConvertTo-ShadowAISlug @('model', $ms.runtime, $modelName)
                $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($ms.runtime) model [$modelName] present ($($cls.Class))" "Found via $($ms.runtime) manifest at [$($f.FullName)].$vendorNote" $rating $f.FullName $AssetId))
            }
        }
        elseif ($ms.type -eq 'hf_cache') {
            $dirs = Get-ChildItem -Path $storePath -Directory -ErrorAction SilentlyContinue
            foreach ($d in $dirs) {
                $info = Get-ShadowAIHfModelName $d.Name
                $cls = Get-ShadowAIModelClass $info.Name $families
                $foundAny = $true
                $products.Add("$($ms.runtime) Model: $($info.Name)")
                $tagsList.Add("AI_MODEL:$($info.Name)")
                $tagsList.Add("AI_MODEL_CLASS:$($cls.Class)")
                $rating = if ($cls.Class -eq 'custom') { '3' } else { '2' }
                if ($cls.Class -eq 'custom' -and $info.Org) {
                    $details = "Found in Hugging Face cache. Publisher/org [$($info.Org)] does not match a known public model family - treat as custom/unreviewed."
                } elseif ($cls.Vendor) {
                    $details = "Found in Hugging Face cache. Matches known public model family ($($cls.Vendor))."
                } else {
                    $details = 'Found in Hugging Face cache.'
                }
                $slug = ConvertTo-ShadowAISlug @('model', $ms.runtime, $info.Name)
                $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($ms.runtime) model [$($info.Name)] present ($($cls.Class))" $details $rating $d.Name $AssetId))
            }
        }
        elseif ($ms.type -eq 'glob') {
            foreach ($ext in $ms.ext) {
                $files = Get-ChildItem -Path $storePath -Recurse -File -Filter "*$ext" -ErrorAction SilentlyContinue
                foreach ($f in $files) {
                    $cls = Get-ShadowAIModelClass $f.Name $families
                    $foundAny = $true
                    $sizeStr = '{0:N1} MB' -f ($f.Length / 1MB)
                    $products.Add("$($ms.runtime) Model: $($f.Name)")
                    $tagsList.Add("AI_MODEL:$($f.Name)")
                    $tagsList.Add("AI_MODEL_CLASS:$($cls.Class)")
                    $rating = if ($cls.Class -eq 'custom') { '3' } else { '2' }
                    $vendorNote = if ($cls.Vendor) { " Matches known public model family ($($cls.Vendor))." } else { ' Does not match a known public model family - treat as custom/unreviewed.' }
                    $slug = ConvertTo-ShadowAISlug @('model', $ms.runtime, $f.Name)
                    $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($ms.runtime) model file [$($f.Name)] present ($($cls.Class))" "Weight file at [$($f.FullName)] ($sizeStr).$vendorNote" $rating $f.FullName $AssetId))
                }
            }
        }
    }

    # --- Package manager SDK usage (opt-in, slower) ---
    if ($CheckPackages) {
        $pipCmd = Get-Command pip3 -ErrorAction SilentlyContinue
        if (-not $pipCmd) { $pipCmd = Get-Command pip -ErrorAction SilentlyContinue }
        if ($pipCmd) {
            $pipOut = & $pipCmd.Source list --disable-pip-version-check --format=freeze 2>$null
            foreach ($line in $pipOut) {
                $pipParts = $line -split '==', 2
                $name = $pipParts[0].Trim()
                $version = if ($pipParts.Length -gt 1) { $pipParts[1].Trim() } else { '' }
                if ($sig.packages.pip -contains $name.ToLower()) {
                    $foundAny = $true
                    $display = "$name $version".Trim()
                    $products.Add($display)
                    $slug = ConvertTo-ShadowAISlug @('pkg', 'pip', $name)
                    $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: AI SDK dependency installed [$display]" 'Found via pip package listing.' '2' $display $AssetId))
                }
            }
        }
        $npmCmd = Get-Command npm -ErrorAction SilentlyContinue
        if ($npmCmd) {
            try { $npmJson = & $npmCmd.Source ls -g --depth=0 --json 2>$null | ConvertFrom-Json } catch { $npmJson = $null }
            if ($npmJson -and $npmJson.dependencies) {
                foreach ($dep in $npmJson.dependencies.PSObject.Properties) {
                    if ($sig.packages.npm -contains $dep.Name) {
                        $foundAny = $true
                        $display = "$($dep.Name) $($dep.Value.version)"
                        $products.Add($display)
                        $slug = ConvertTo-ShadowAISlug @('pkg', 'npm', $dep.Name)
                        $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: AI SDK dependency installed [$display]" 'Found via npm global package listing.' '2' $display $AssetId))
                    }
                }
            }
        }

        # --- Windows package managers (winget / scoop / chocolatey) ---
        # These catch CLI tools installed through a package manager that
        # never touch Get-Command/PATH resolution directly - e.g. a scoop
        # shim PowerShell can't see yet, or a winget install that only
        # registers in the package database. Matched against cli_tools[].bin
        # (the command name, e.g. "ollama") rather than the display product
        # name, since package manager IDs are built from the former.
        $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
        if ($wingetCmd) {
            try { $wingetOut = & $wingetCmd.Source list --accept-source-agreements 2>$null } catch { $wingetOut = $null }
            if ($wingetOut) {
                foreach ($cli in $sig.cli_tools) {
                    if ($cli.skip_freetext_match) { continue }
                    $hit = $wingetOut | Where-Object { $_ -match ("\b" + [regex]::Escape($cli.bin) + "\b") } | Select-Object -First 1
                    if ($hit) {
                        $foundAny = $true
                        $display = "$($cli.product) (winget)"
                        $products.Add($display)
                        $tagsList.Add("SHADOW_AI:$($cli.product)")
                        $slug = ConvertTo-ShadowAISlug @('winget', $cli.product)
                        $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($cli.product) ($($cli.category)) found via winget" "Found via 'winget list'. Line: [$($hit.Trim())]" '2' $cli.bin $AssetId))
                    }
                }
            }
        }

        $scoopAppsDir = if ($env:SCOOP) { Join-Path $env:SCOOP 'apps' } else { "$env:USERPROFILE\scoop\apps" }
        if (Test-Path $scoopAppsDir -ErrorAction SilentlyContinue) {
            $scoopApps = Get-ChildItem -Path $scoopAppsDir -Directory -ErrorAction SilentlyContinue
            foreach ($cli in $sig.cli_tools) {
                if ($cli.skip_freetext_match) { continue }
                $hit = $scoopApps | Where-Object { $_.Name -match ("\b" + [regex]::Escape($cli.bin) + "\b") } | Select-Object -First 1
                if ($hit) {
                    $foundAny = $true
                    $display = "$($cli.product) (scoop)"
                    $products.Add($display)
                    $tagsList.Add("SHADOW_AI:$($cli.product)")
                    $slug = ConvertTo-ShadowAISlug @('scoop', $cli.product)
                    $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($cli.product) ($($cli.category)) found via scoop" "Found at [$($hit.FullName)]." '2' $hit.FullName $AssetId))
                }
            }
        }

        $chocoLibDir = if ($env:ChocolateyInstall) { Join-Path $env:ChocolateyInstall 'lib' } else { "$env:ProgramData\chocolatey\lib" }
        if (Test-Path $chocoLibDir -ErrorAction SilentlyContinue) {
            $chocoPkgs = Get-ChildItem -Path $chocoLibDir -Directory -ErrorAction SilentlyContinue
            foreach ($cli in $sig.cli_tools) {
                if ($cli.skip_freetext_match) { continue }
                $hit = $chocoPkgs | Where-Object { $_.Name -match ("\b" + [regex]::Escape($cli.bin) + "\b") } | Select-Object -First 1
                if ($hit) {
                    $foundAny = $true
                    $display = "$($cli.product) (chocolatey)"
                    $products.Add($display)
                    $tagsList.Add("SHADOW_AI:$($cli.product)")
                    $slug = ConvertTo-ShadowAISlug @('choco', $cli.product)
                    $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: $($cli.product) ($($cli.category)) found via Chocolatey" "Found at [$($hit.FullName)]." '2' $hit.FullName $AssetId))
                }
            }
        }
    }

    # --- Browser history (opt-in, separate from credentials/packages given
    # its sensitivity). Domain + visit count + last-visit date only - never
    # full URLs, search queries, or page content.
    #
    # Requires a working sqlite3: if it's unavailable, or a query fails for
    # ANY reason (launch failure, timeout, non-zero exit, corrupted/locked
    # copy, schema mismatch), nothing is reported for that profile - there is
    # deliberately no lower-fidelity "presence only" fallback here, since a
    # bare "this domain's string appears somewhere" signal with no count or
    # date was assessed as noise rather than a useful finding. ---
    if ($CheckBrowsing -and $sig.browser_profiles -and $Signatures.ai_chat_domains) {
        # Get-Command, not a hardcoded path: on twigs.ps1 this finds the
        # vendored sqlite3.exe once its folder is prepended to PATH by the
        # caller; on win_host/WinRM (where nothing is vendored into the
        # inlined script) it naturally finds nothing and the whole check is
        # skipped below.
        $sqliteCmd = Get-Command sqlite3 -ErrorAction SilentlyContinue
        if ($sqliteCmd) {
            $aiChatDomains = $Signatures.ai_chat_domains
            $caseExpr = ConvertTo-ShadowAIBrowsingCaseSql -AiChatDomains $aiChatDomains
            $sqlChromium = Get-ShadowAIBrowsingSql -Family 'chromium' -CaseExpr $caseExpr
            $sqlFirefox = Get-ShadowAIBrowsingSql -Family 'firefox' -CaseExpr $caseExpr

            $browseTmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("sa_browse_" + [Guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $browseTmpDir -Force -ErrorAction SilentlyContinue | Out-Null
            $browsingReported = @{}

            foreach ($bp in $sig.browser_profiles) {
                try { $bpBase = $ExecutionContext.InvokeCommand.ExpandString($bp.base) } catch { continue }
                if (-not (Test-Path $bpBase -ErrorAction SilentlyContinue)) { continue }
                $profileDirs = Get-ChildItem -Path $bpBase -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like $bp.profile_pattern }
                foreach ($pd in $profileDirs) {
                    $srcFile = Join-Path $pd.FullName $bp.file
                    if (-not (Test-Path $srcFile -ErrorAction SilentlyContinue)) { continue }
                    $copyPath = Join-Path $browseTmpDir ("sa_" + [Guid]::NewGuid().ToString('N'))
                    try { Copy-Item -Path $srcFile -Destination $copyPath -ErrorAction Stop } catch { continue }
                    $walSrc = "$srcFile-wal"
                    if (Test-Path $walSrc -ErrorAction SilentlyContinue) {
                        try { Copy-Item -Path $walSrc -Destination "$copyPath-wal" -ErrorAction SilentlyContinue } catch {}
                    }

                    $sql = if ($bp.family -eq 'chromium') { $sqlChromium } else { $sqlFirefox }
                    $rows = Invoke-ShadowAISqliteQuery -SqliteExePath $sqliteCmd.Source -DbPath $copyPath -Sql $sql

                    if ($null -ne $rows) {
                        foreach ($row in $rows) {
                            $fields = $row -split '\|'
                            if ($fields.Count -ge 3 -and $fields[0]) {
                                $cnt = [int64]0; [void][int64]::TryParse($fields[1], [ref]$cnt)
                                $ts = [int64]0; [void][int64]::TryParse($fields[2], [ref]$ts)
                                $key = "$($bp.browser)|$($fields[0])"
                                if (-not $browsingReported.ContainsKey($key)) {
                                    $browsingReported[$key] = [PSCustomObject]@{
                                        Browser = $bp.browser; Name = $fields[0]; Count = [int64]0; Ts = [int64]0
                                        Family = $bp.family
                                    }
                                }
                                $browsingReported[$key].Count += $cnt
                                if ($ts -gt $browsingReported[$key].Ts) { $browsingReported[$key].Ts = $ts }
                            }
                        }
                    }
                    # $rows -eq $null means the query failed for any reason -
                    # silently skip this profile, no fallback is reported.

                    Remove-Item -Path $copyPath, "$copyPath-wal" -ErrorAction SilentlyContinue
                }
            }
            Remove-Item -Path $browseTmpDir -Recurse -Force -ErrorAction SilentlyContinue

            foreach ($entry in $browsingReported.Values) {
                $foundAny = $true
                $tagsList.Add("SHADOW_AI:$($entry.Name)")
                $slug = ConvertTo-ShadowAISlug @('browse', $entry.Browser, $entry.Name)
                $dateStr = ConvertFrom-ShadowAIBrowsingTimestamp -Value $entry.Ts -Family $entry.Family
                $details = "Detected via $($entry.Browser) browsing history: $($entry.Count) visit(s)"
                if ($dateStr) { $details += ", last visit $dateStr" }
                $details += '. Only the domain and visit metadata were read - no URLs, search queries, or page content.'
                $configIssues.Add((New-ShadowAIIssue $slug "Shadow AI: browsing activity to $($entry.Name) detected ($($entry.Browser))" $details '3' $entry.Name $AssetId))
            }
        }
    }

    # --- WSL (Windows Subsystem for Linux) ---
    # AI tooling installed/run inside a WSL distro (ollama, aider, pip/npm
    # SDKs, local models) is invisible to every check above, which only looks
    # at native Windows paths/registry/processes - a real blind spot on
    # developer machines. Detecting WSL itself is cheap and always-on;
    # peeking inside a distro for specific CLI tools is opt-in (-CheckWsl)
    # since it spawns a real process inside the distro per distro checked.
    $wslCmd = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if ($wslCmd) {
        $wslListOut = Invoke-ShadowAIBoundedProcess -FileName $wslCmd.Source -Arguments '--list --quiet' -TimeoutMs 5000
        if ($null -ne $wslListOut) {
            # wsl.exe can emit UTF-16 with stray control characters when its
            # output is captured this way rather than shown in a console.
            $distros = $wslListOut | ForEach-Object { ($_ -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', '').Trim() } | Where-Object { $_ -ne '' }
            if ($distros.Count -gt 0) {
                $foundAny = $true
                $tagsList.Add('SHADOW_AI:WSL')
                $slug = ConvertTo-ShadowAISlug @('wsl', 'present')
                $details = "WSL distro(s) present: $($distros -join ', '). AI tooling installed or run inside WSL (CLI tools, pip/npm SDKs, local models) is not visible to this native-Windows scan - run twigs host mode against the distro directly for full coverage."
                if (-not $CheckWsl) { $details += ' Re-run with -CheckWsl for a bounded CLI-tool presence check inside each distro.' }
                $configIssues.Add((New-ShadowAIIssue $slug 'Shadow AI: WSL (Windows Subsystem for Linux) present' $details '2' ($distros -join ',') $AssetId))

                if ($CheckWsl) {
                    $wslBins = @($sig.cli_tools | ForEach-Object { $_.bin } | Where-Object { $_ } | Select-Object -Unique)
                    if ($wslBins.Count -gt 0) {
                        $probeScript = 'for b in ' + ($wslBins -join ' ') + '; do command -v "$b" >/dev/null 2>&1 && echo "$b"; done'
                        foreach ($distro in $distros) {
                            $wslArgs = '-d ' + (ConvertTo-ShadowAIWin32Arg $distro) + ' -- sh -lc ' + (ConvertTo-ShadowAIWin32Arg $probeScript)
                            $hits = Invoke-ShadowAIBoundedProcess -FileName $wslCmd.Source -Arguments $wslArgs -TimeoutMs 15000
                            if ($null -eq $hits) { continue }
                            foreach ($bin in $hits) {
                                $cliMatch = $sig.cli_tools | Where-Object { $_.bin -eq $bin } | Select-Object -First 1
                                if (-not $cliMatch) { continue }
                                $foundAny = $true
                                $tagsList.Add("SHADOW_AI:$($cliMatch.product)")
                                $slug2 = ConvertTo-ShadowAISlug @('wslcli', $distro, $cliMatch.product)
                                $configIssues.Add((New-ShadowAIIssue $slug2 "Shadow AI: $($cliMatch.product) ($($cliMatch.category)) CLI available inside WSL" "Binary [$bin] found on PATH inside WSL distro [$distro]." '2' "$($distro):$bin" $AssetId))
                            }
                        }
                    }
                }
            }
        }
    }

    if ($foundAny) { $tagsList.Add('Shadow AI') }
    $uniqueTags = @($tagsList | Select-Object -Unique)

    return @{
        config_issues = $configIssues.ToArray()
        products      = $products.ToArray()
        tags          = $uniqueTags
    }
}

Export-ModuleMember -Function Invoke-ShadowAIScan
