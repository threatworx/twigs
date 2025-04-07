<#
.SYNOPSIS
    Windows Host discovery script (twigs equivalent)
.DESCRIPTION
    This script helps discover Windows Host(s) as assets in ThreatWorx instance. It is equivalent to twigs.
.PARAMETER mode
    Specifies the discovery mode (local or remote).
.PARAMETER remote_hosts_csv
    Specifies path for CSV file containing details of remote hosts to be discovered. Optional.
.PARAMETER host_list
    Specifies path for CSV file to be secured. Format is same as remote hosts CSV. Optional.
.PARAMETER password
    A password used to encrypt / decrypt login information from the host list / remote hosts CSV file. Optional.
.PARAMETER handle
    Specifies the handle of the ThreatWorx user. Mandatory.
.PARAMETER token
    Specifies the API token of the ThreatWorx user. Optional.
.PARAMETER instance
    Specifies the ThreatWorx instance. Optional.
.PARAMETER out
    Specifies the output JSON filename to hold discovered asset details. Optional.
.PARAMETER assetid
    Specifies the identifier for the asset. Optional.
.PARAMETER assetname
    Specifies the name for the asset. Optional.
.PARAMETER tags
    Specify tags for the asset. Optional.
.PARAMETER tag_critical
    Tag the asset as critical. Optional. Possible values (true or false). Default is false.
.PARAMETER no_scan
    Do not initiate a baseline assessment. Optional. Possible values (true or false). Default is false.
.PARAMETER no_host_benchmark
    Do not run host benchmark tests. Optional. Possible values (true or false). Default is false.
.PARAMETER email_report
    After impact refresh is complete, email scan report to self. Optional. Possible values (true or false). Default is false.
.EXAMPLE
    .\twigs.ps1 -handle someuser@company.com -token XXXX -instance ACME.threatworx.io -out asset.json -assetid myassetid -assetname myassetname -tag_critical true -tags 'tag1','tag2' -email_report true
    .\twigs.ps1 -mode remote -remote_hosts_csv my_remote_hosts.csv -handle someuser@company.com -token XXXX -instance ACME.threatworx.io
.NOTES
    .    
#>
# Sample PowerShell based discovery script for Windows
param(
    [parameter(Mandatory=$false, HelpMessage='Local or Remote Windows host discovery')]
    [ValidateSet('local','remote')]
    [String]
    $mode='local',

    [parameter(Mandatory=$false, HelpMessage='Specify path for CSV file containing details of remote hosts to be discovered')]
    [String]
    $remote_hosts_csv,

    [parameter(Mandatory=$false, HelpMessage='Specifies path for CSV file to be secured. Format is same as remote hosts CSV.')]
    [String]
    $host_list,

    [parameter(Mandatory=$false, HelpMessage='A password used to encrypt / decrypt login information from the host list / remote hosts CSV file.')]
    [String]
    $password,

    [parameter(Mandatory=$true, HelpMessage='Enter the email handle for ThreatWorx instance')]
    [String]
    $handle,

    [parameter(Mandatory=$false, HelpMessage='Enter the API key for the specified email handle for ThreatWorx instance')]
    [String]
    $token,

    [parameter(Mandatory=$false, HelpMessage='Specify the ThreatWorx instance')]
    [String]
    $instance,

    [parameter(Mandatory=$false, HelpMessage='Specify the output JSON filename')]
    [String]
    $out,

    [parameter(Mandatory=$false, HelpMessage='Enter the Asset ID')]
    [String]
    $assetid,

    [parameter(Mandatory=$false, HelpMessage='Enter the Asset Name')]
    [String]
    $assetname,

    [parameter(Mandatory=$false, HelpMessage='Specify tags for the asset')]
    [String[]]
    $tags,

    [parameter(Mandatory=$false, HelpMessage='Tag the asset as critical. Possible values (true or false). Default is false')]
    [ValidateSet('true','false')]
    [String]
    $tag_critical='false',
    
    [parameter(Mandatory=$false, HelpMessage='Do not initiate a baseline assessment. Possible values (true or false). Default is false')]
    [ValidateSet('true','false')]
    [String]
    $no_scan='false',

    [parameter(Mandatory=$false, HelpMessage='Do not run host benchmark tests. Possible values (true or false). Default is false')]
    [ValidateSet('true','false')]
    [String]
    $no_host_benchmark='false',

    [parameter(Mandatory=$false, HelpMessage='After impact refresh is complete email scan report to self. Possible values (true or false). Default is false')]
    [ValidateSet('true','false')]
    [String]
    $email_report='false'
)

function ql { $Args }

function GetLastIpAddress {
    param ([string]$cidr )
    $bits = ql 0 128 192 224 240 248 252 254
    $net = $cidr.Split("/")
    $sn = $net[0]
    $octets = $sn.Split(".")

    [int]$mask = $net[1]
    $activ = $mask % 8
    $actval = $bits[$activ]
    $fulloctets = [System.Math]::Truncate($mask / 8)

    $ao = [int]$octets[$fulloctets]
    $mn = 256 - $actval
    $x = [System.Math]::Truncate($ao / $mn)
    $num = $x * $mn
    ## calculate active part of broadcast address
    $bd = $num + $mn -1
    switch ($fulloctets)
    {
        1
        {
            $fixed = $octets[0]
            $subnet = $fixed + "." + $num.ToString() + ".0.0"
            $strmask = "255." + $actval.ToString() + ".0.0"
            $broadcast = $fixed + "." + $bd.ToString() + ".255.255" 
            break
        }
        2
        {
            $fixed = $octets[0]+"."+$octets[1]
            $subnet = $fixed + "." + $num.ToString() + ".0"
            $strmask = "255.255." + $actval.ToString() + ".0"
            $broadcast = $fixed + "." + $bd.ToString() + ".255" 
            break
        }
        3
        {
            $fixed = $octets[0]+"."+$octets[1]+"."+$octets[2]
            $subnet = $fixed + "." + $num.ToString()
            $strmask = "255.255.255." + $actval.ToString()
            $broadcast = $fixed + "." + $bd.ToString()
            break
        }
    }

    $snoct = $subnet.Split(".")
    $snoct[3] = ([int]$snoct[3] + 1).ToString()
    $fip = $snoct[0]+"."+$snoct[1]+"."+$snoct[2]+"."+$snoct[3]
    $bdoct = $broadcast.Split(".")
    $bdoct[3] = ([int]$bdoct[3] - 1).ToString()
    $lip = $bdoct[0]+"."+$bdoct[1]+"."+$bdoct[2]+"."+$bdoct[3]
    return $broadcast
}

function GetNextIpAddress {
    param ([string]$address )

    $a = [System.Net.IpAddress]::Parse($address) ## turn the string to IP address
    $z = $a.GetAddressBytes() ## and then to an array of bytes
    if ($z[3] -eq 255) ## last octet full
    {
        $z[3] = 0 ## so reset

        if ($z[2] -eq 255) ## third octet full
        {
            $z[2] = 0 ## so reset   
            $z[1] += 1 ## increment second octet
        }
        else
        {
            $z[2] += 1 ##  increment third octect
        }
    }
    else
    {
        $z[3] += 1 ## increment last octet
    }
    $c = [System.Net.IpAddress]($z) ## recreate IP address
    return $c.ToString()
}

function ExpandCidr {
    param ([string]$cidr )

    $broken=@()
    $lastIP = GetLastIpAddress($cidr)
    $curradd = $cidr.Split("/")[0]
    do {
        $addr = GetNextIpAddress($curradd)
        #Write-Host $addr
        #$ipobj = Add-OneIP $addr
        if ($broken -notcontains $addr) {$broken += $addr}
        $curradd = $addr
    } until ($addr -eq $lastIP)
    return $broken
}

function Invoke-RemoteDiscovery {
    if (!$remote_hosts_csv -and !$host_list) {
        Write-Host "Error missing remote_hosts_csv and host_list argument. Either one must be specified for remote discovery"
        exit
    }
    if ($host_list) {
        Write-Host "Securing host list CSV file"
        if (!$password) {
            $password1 = Read-Host "Enter password: " -AsSecureString
            $password2 = Read-Host "Re-enter password: " -AsSecureString
            $raw_pwd1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password1))
            $raw_pwd2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password2))
            if ($raw_pwd1 -ne $raw_pwd2) {
                Write-Host "Passwords don't match. Try again."
                Exit
            }
            $password = $raw_pwd1
        }
        while ($password.length -lt 16) {
            $password = $password + $password
        }
        $password = $password.subString(0,16)
        $password = $password | ConvertTo-SecureString -AsPlainText -Force
        $hosts = Import-Csv $host_list
        foreach ($thost in $hosts) {
            if (!$thost.userpwd.StartsWith('__SECURE__:')) {
                $host_password = $thost.userpwd | ConvertTo-SecureString -AsPlainText -Force
                $enc_pwd = $host_password | ConvertFrom-SecureString -SecureKey $password
                $thost.userpwd = "__SECURE__:" + $enc_pwd
            }
        }
        $hosts | Export-Csv $host_list -NoTypeInformation
        Write-Host "Host list CSV file secured"
        Exit
    }
    Write-Host "Reading remote hosts CSV file..."
    $remote_hosts = Import-Csv $remote_hosts_csv
    Write-Host "Starting remote Windows host discovery..."
    $secure_password = $null
    foreach ($remote_host in $remote_hosts) {
        $remotehost = $remote_host.hostname
        if ($remote_host.userpwd.StartsWith("__SECURE__:")) {
            if (!$secured_password) {
                if (!$password) {
                    $password1 = Read-Host "Enter password: " -AsSecureString
                    $raw_password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password1))
                }
                else {
                    $raw_password = $password
                }
                while ($raw_password.length -lt 16) {
                    $raw_password = $raw_password + $raw_password
                }
                $raw_password = $raw_password.subString(0,16)
                $secured_password = $raw_password | ConvertTo-SecureString -AsPlainText -Force
            }
            $etext = $remote_host.userpwd.subString(11, $remote_host.userpwd.Length - 11)
            try {
                $dtext = $etext | ConvertTo-SecureString -SecureKey $secured_password -ErrorAction Stop
                $userPassword = $dtext
            }
            catch {
                Write-Host "Decryption failed, possibly due to incorrect password..."
                Exit
            }

        }
        else {
            $userPassword = $remote_host.userpwd | ConvertTo-SecureString -AsPlainText -Force
        }
        $logincredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $remote_host.userlogin, $userPassword
        if ($remotehost.indexof('/') -ne -1) {
            $remotehosts = ExpandCidr($remotehost)
        }
        else {
            $remotehosts = @()
            $remotehosts += $remotehost
        }
        foreach ($remotehost in $remotehosts) {
            Write-Host ''
            Write-Host ''
            Write-Host "Running remote discovery for: ",$remotehost
            $remoteSession = New-PSSession -ComputerName $remotehost -Credential $logincredentials
            if ($remoteSession -eq $null) {
                Write-Host "Connecting to remote host failed....skipping it"
                continue
            }
            $remote_folder = Invoke-Command -Session $remoteSession -ScriptBlock { $File = New-TemporaryFile; Remove-Item $File -Force; New-Item -Itemtype Directory -Path "$($ENV:Temp)\$($File.Name)"; }
            if ($PSScriptRoot) {
                Copy-Item $PSScriptRoot -Destination $remote_folder -ToSession $remoteSession -Recurse
                $remote_twigs_folder = $remote_folder.ToString() + "\twigs_PS"
                $remotescript = ".\twigs.ps1"
            }
            else {
                $FileLocation = Split-Path (Convert-Path -LiteralPath ([Environment]::GetCommandLineArgs()[0]))
                Copy-Item $FileLocation -Destination $remote_folder -ToSession $remoteSession -Recurse
                $remote_twigs_folder = $remote_folder.ToString() + "\twigs_EXE"
                $remotescript = ".\twigs.exe"
            }
            Invoke-Command -Session $remoteSession { Set-Location $using:remote_twigs_folder }
            Invoke-Command -Session $remoteSession -ScriptBlock { & $using:remotescript -mode 'local' -handle $using:handle -token $using:token -instance $using:instance -tags $using:tags -tag_critical $using:tag_critical -no_scan $using:no_scan -no_host_benchmark $using:no_host_benchmark -email_report $using:email_report}
            Invoke-Command -Session $remoteSession { Set-Location "..\..\" }
            Invoke-Command -Session $remoteSession { Remove-Item $using:remote_folder -Recurse }
            Remove-PSSession $remoteSession
            Write-Host "Completed remote discovery for: ",$remotehost
        }
    } 
    Write-Host "Completed remote Windows host discovery."
}

function Invoke-LocalDiscovery {
    if (!$token -and !$instance -and !$out) {
        Write-Host "Error missing token, instance and out arguments....nothing to do!"
        exit
    }

    if ($no_scan -eq "true" -and $email_report -eq "true") {
        Write-Host "Error conflicting options [no_scan] and [email_report] are specified!"
        exit
    }

    if (!$assetid) {
        $assetid = $env:ComputerName
    }
    if (!$assetname) {
        $assetname = $assetid
    }
    $assetid = $assetid.Replace("/","-")
    $assetid = $assetid.Replace(":","-")
    $assetname = $assetname.Replace("/","-")
    $assetname = $assetname.Replace(":","-")

    Write-Host 'Running discovery for Windows asset: ', $assetname
    Write-Host ''

    $tw_assets_url = 'https://' + $instance+ '/api/v2/assets/'
    $tw_scan_url = 'https://' + $instance+ '/api/v1/scans/'

    # Check if asset exists
    $asset_exists = 1

    if ($token -and $instance) {

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $url = $tw_assets_url + $assetid + '/?handle=' + $handle + '&token=' + $token + '&format=json'
        $http_method = 'Get'
        Write-Host 'Validating ThreatWorx credentials...'
        try {
            $response = Invoke-RestMethod -Method $http_method -Uri $url -ContentType 'application/json'
        }
        catch {
            if($_.Exception.Response.StatusCode.value__ -eq 404) {
                $asset_exists = 0
            }
            else {
                Write-Host 'Encountered fatal error (details below)'
                Write-Host "$_"
                Write-Host 'Exiting...'
                exit
            }
        }
        Write-Host 'ThreatWorx credentials validated.'
    }
    Write-Host ''
    Write-Host 'Extracting OS details...'
    $computer_info = Get-ComputerInfo
    $base_os = $computer_info.OsName
    Write-Host "OS:", $base_os

    $os_version = $null
    $os_version_ubr = $null
    $os_release_id = $null
    $os_arch = $null
    $os_version = $computer_info.OsVersion
    $os_version_ubr = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR
    if ($os_version_ubr) {
        $os_version_tokens = $os_version.ToString().Split(' ')
        $os_version = $os_version_tokens[0] + '.' + $os_version_ubr
        for ($i=1; $i -lt $os_version_tokens.Length; $i++) 
        {
            $os_version = $os_version + ' ' + $os_version_tokens[$i]
        }
    }
    $temp_str = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
    if ($temp_str) {
        $os_release_id = $temp_str.ToString().Trim()
    }
    $mc_arch = $computer_info.CsSystemType
    $bit_arch = $computer_info.OsArchitecture
    $os_arch = $bit_arch + ' ' + $mc_arch
    $os_arch = $os_arch.Trim()

    Write-Host ''
    Write-Host 'Extracting patch information...'
    $hot_fixes = Get-HotFix
    $patch_json_array = New-Object System.Collections.Generic.List[System.Object]
    foreach ($hot_fix in $hot_fixes) { $patch_entry_json = @{id=$hot_fix.HotFixID}; $patch_json_array.add($patch_entry_json)}
    Write-Host 'Number of patches found:', $patch_json_array.Count
    $patch_json = $patch_json_array | ConvertTo-Json
    $patch_json_str = $patch_json.ToString()

    Write-Host ''
    Write-Host 'Extracting products (using registry key)...'
    $unique_products = New-Object System.Collections.Generic.List[string]
    $product_json_array = New-Object System.Collections.Generic.List[string]
    $temp_array = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Publisher, DisplayName, DisplayVersion
    $temp_array | foreach { $var = $_ ; $product = $var.'DisplayName'; $vendor = $var.'Publisher'; $version = $var.'DisplayVersion'; if ($product -and $version) { $product_details = $product.Trim() + ' ' + $version.Trim(); $product_json_array.add($product_details); }}
    $temp_products_count = $temp_array.Length
    $temp_array = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Publisher, DisplayName, DisplayVersion
    $temp_array | foreach { $var = $_ ; $product = $var.'DisplayName'; $vendor = $var.'Publisher'; $version = $var.'DisplayVersion'; if ($product -and $version) { $product_details = $product.Trim() + ' ' + $version.Trim(); $product_json_array.add($product_details); }}
    $ie_version = Get-ItemProperty "HKLM:\Software\Microsoft\Internet Explorer" | Select-Object svcVersion, Version
    if ($ie_version.svcVersion -ne $null) {
        $product_json_array.add('Internet Explorer ' + $ie_version.svcVersion)
        $temp_products_count = $temp_products_count + 1
    }
    else {
        if ($ie_version.Version -ne $null) {
            $product_json_array.add('Internet Explorer ' + $ie_version.Version)
            $temp_products_count = $temp_products_count + 1
        }
    }
    $temp_products_count = $temp_products_count + $temp_array.Length
    Write-Host 'Number of products found (using registry key):', $temp_products_count
    Write-Host 'Number of products identified till now:', $product_json_array.Count

    Write-Host ''
    Write-Host 'Extracting products (using WMI)...'
    $temp_array = Get-WMIObject -ClassName Win32_Product
    foreach ($row in $temp_array) { $product_details = $row.Name.Trim() + ' ' + $row.Version.Trim(); if  ($product_json_array -notcontains $product_details) { $product_json_array.Add($product_details)} }
    Write-Host 'Number of products found (using wmic):', $temp_array.Count
    Write-Host 'Total number of unique products found:', $product_json_array.Count

    $tags_json_array = New-Object System.Collections.Generic.List[string]
    $tags_json_array.Add('OS_RELEASE:' + $base_os)
    if ($os_version) {
        $tags_json_array.Add('OS_VERSION:' + $os_version)
    }
    if ($os_release_id) {
        $tags_json_array.Add('OS_RELEASE_ID:' + $os_release_id)
    }
    if ($os_arch) {
        $tags_json_array.Add('OS_ARCH:' + $os_arch)
    }
    $tags_json_array.Add('Windows')
    if ($tag_critical -eq "true") {
        $tags_json_array.Add('CRITICALITY:5')
    }
    if ($tags) {
        foreach($tag in $tags) {
            # Special handling for twigs.exe which does not allow multiple tags (as it is requires array of strings)
            $temp_tags = $tag.Split(',')
            foreach($temp_tag in $temp_tags) {
                $tags_json_array.Add($temp_tag)
            }
        }
    }

    $misconfigs_json_array = New-Object System.Collections.Generic.List[System.Object]
    # Run host benchmark if specified
    if ($no_host_benchmark -eq "false") {
        $FileLocation = 
            if ($PSScriptRoot) { # running as .ps1 file
                $PSScriptRoot 
            } 
            else {               # running as .exe
                Split-Path (Convert-Path -LiteralPath ([Environment]::GetCommandLineArgs()[0]))
            }
        Write-Host "Running host benchmarks. This may take some time..."
        $hbm_csv_rpt = $FileLocation + '\twigs_hbm.csv'
        if (Test-Path $hbm_csv_rpt) { Remove-Item $hbm_csv_rpt }
        # If twigs.exe is running, then no need to source HardeningKitty as it is already included
        if ($PSScriptRoot) {
            # If twigs.ps1 is running, then source HardeningKitty
            $hk_script = $FileLocation + '\Invoke-HardeningKitty.ps1'
            Unblock-File $hk_script
            . ($hk_script)
        }
        Invoke-HardeningKitty -Mode Audit -Report -ReportFile $hbm_csv_rpt
        $misconfigs = Import-Csv $hbm_csv_rpt
        foreach ($misconfig in $misconfigs) {
            if ($misconfig.Severity -ne 'Passed') {
                if ($misconfig.Severity -eq 'Low') { $mc_rating = '2' }
                elseif ($misconfig.Severity -ne 'Medium') { $mc_rating = '3' }
                elseif ($misconfig.Severity -ne 'High') { $mc_rating = '5' }
                if ($misconfig.Result -eq '') { $cv = 'Not available' }
                else { $cv = $misconfig.Result }
                $details_msg = 'Current value is [' + $cv + '] and recommended value is [' + $misconfig.Recommended + '].'
                $misconfig_entry_json = @{asset_id=$assetid;twc_id=$misconfig.ID;twc_title=$misconfig.Name;type='Host Benchmark';details=$details_msg;rating=$mc_rating;object_id='';object_meta=''}
                $misconfigs_json_array.add($misconfig_entry_json)
            }
        }
        if (Test-Path $hbm_csv_rpt) { Remove-Item $hbm_csv_rpt }
    }

    $url = ''
    $http_method = ''
    if ($asset_exists -eq 0) {
        # If asset does not exist, then create one
        $http_method = 'Post'
        $url = $tw_assets_url + '?handle=' + $handle + '&token=' + $token + '&format=json'
    }
    else {
        # If asset exists, then update it
        $http_method = 'Put'
        $url = $tw_assets_url + $assetid + '/?handle=' + $handle + '&token=' + $token + '&format=json'
    }

    $current_ts = Get-Date -UFormat %s
    $current_ts = $current_ts.ToString().Split('.')[0]

    $payload = @{
        id=$assetid
        name=$assetname
        type='Windows'
        attack_surface_label='Corporate::Server::Windows'
        timestamp=$current_ts
        description=''
        owner=$handle
        patches=$patch_json_array
        products=$product_json_array
        config_issues=$misconfigs_json_array
        tags=$tags_json_array
    }
    $body = (ConvertTo-Json -Depth 100 $payload)

    # Remove any non-ascii characters
    $body = $body -replace '[^ -~]', ''

    $scan_type = $null
    if ($token -and $instance) {
        Write-Host ''
        if ($asset_exists -eq 0) {
            Write-Host 'Creating asset...'
        }
        else {
            Write-Host 'Updating asset...'
        }
        $response = Invoke-RestMethod -Method $http_method -Uri $url -ContentType 'application/json' -Body $body
        if ($asset_exists -eq 0) {
            Write-Host 'Successfully created asset'
        }
        else {
            Write-Host 'Successfully updated asset'
            if ($no_scan -eq "false") {
                if ($response.status -Match 'No product updates') {
                    Write-Host 'Asset products are not updated. No need for impact refresh.'
                    $no_scan = "true"
                }
                else {
                    if ($response.status -Match 'Full scan needed') {
                        $scan_type = 'F'
                    }
                    else {
                        $scan_type = 'Q'
                    }
                }
            }
        }

        if ($no_scan -eq "false") {
            $http_method = 'Post'
            $url = $tw_scan_url + '?handle=' + $handle + '&token=' + $token + '&format=json'
            $assets_array = New-Object System.Collections.Generic.List[string]
            $assets_array.Add($assetid)
            $payload = @{
                assets=$assets_array
            }
            if ($email_report -eq "true") {
                $payload["mode"] = "email"
            }
            if ($scan_type -eq 'F') {
                $payload["scan_type"] = "full"
                Write-Host "Starting full impact refresh..."
            }
            else {
                Write-Host "Starting incremental impact refresh..."
            }
            $temp_body = (ConvertTo-Json -Depth 100 $payload)
            $response = Invoke-RestMethod -Method $http_method -Uri $url -ContentType 'application/json' -Body $temp_body
            Write-Host 'Started impact refresh.'
        }
    }

    if ($out) {
        $temp_body = ($body | ConvertFrom-Json)
        $meta = @{
            generated_by=$handle
            generated_on=$current_ts
            tool_name='twigs-ps'
            tool_version='1.0.0'
        }
        $final_body = @{
            assets=@($temp_body)
            meta=$meta
        }
        ConvertTo-Json -Depth 100 $final_body | Out-File $out
    }
}

if ($PSVersionTable) {
    if ($PSVersionTable.PSVersion.Major -lt 3) {
        Write-Host 'Your PowerShell version is:', $PSVersionTable.PSVersion
        Write-Host 'This script requires PowerShell version 3 and higher...exiting'
        exit
    }
}
else {
    Write-Host "Unable to detect your PowerShell version...exiting"
    exit
}

if ($mode -eq "remote") {
    Invoke-RemoteDiscovery
}
else {
    Invoke-LocalDiscovery
}

# SIG # Begin signature block
# MIIG6AYJKoZIhvcNAQcCoIIG2TCCBtUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUqjp4y9Bh4nRtWQa+Oimtg8ix
# UrmgggQKMIIEBjCCAu6gAwIBAgIBATANBgkqhkiG9w0BAQsFADCBoDETMBEGA1UE
# AwwKVGhyZWF0V29yeDEYMBYGA1UECgwPVGhyZWF0V2F0Y2ggSW5jMRQwEgYDVQQL
# DAtFbmdpbmVlcmluZzETMBEGA1UECAwKQ2FsaWZvcm5pYTELMAkGA1UEBhMCVVMx
# EjAQBgNVBAcMCUxvcyBHYXRvczEjMCEGCSqGSIb3DQEJARYUcGFyZXNoQHRocmVh
# dHdvcnguaW8wHhcNMjQwNTA3MTUwNjQ0WhcNMjcwNTA3MTUwNjQ0WjCBoDETMBEG
# A1UEAwwKVGhyZWF0V29yeDEYMBYGA1UECgwPVGhyZWF0V2F0Y2ggSW5jMRQwEgYD
# VQQLDAtFbmdpbmVlcmluZzETMBEGA1UECAwKQ2FsaWZvcm5pYTELMAkGA1UEBhMC
# VVMxEjAQBgNVBAcMCUxvcyBHYXRvczEjMCEGCSqGSIb3DQEJARYUcGFyZXNoQHRo
# cmVhdHdvcnguaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCakSBa
# fxI5dlEt8fOssCOA/0D0N2OSS8vyzbjkLK1ZHAqUawV1+PLqiksc0I+C5OMq8dup
# QbdF6V3NO59TJ4h5DEy1uNBKfYyOZecZ/yZ+/uCcEeaV10kLBkR78D8MRUQoUcqP
# W7jgUzji75dX4+yXEB15zKdjWtoWldxzJ5O1QLmLGfiHgVRgG9AOP/cIMQN3n4sw
# bAwNKzDHTS+vJFcfOWypxsUjRHTouIVZYovMuUmCat+0QFv4yRwS463ISXW9js5q
# FEh2mGKiTCni8da5j0qKKlhjk/xi/vpolmGlwnX6LexrFk9olZdbqufAV3qxskDH
# N7niXpGegbD7NddBAgMBAAGjSTBHMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8E
# DDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUyo+KxnxIhm7IgQEKN44vFHfJ6jEwDQYJ
# KoZIhvcNAQELBQADggEBADDIL/zYH7rX1COCDneTEiZ0rEaaCjYeWqAl+bHdYG3i
# bjrwyshp8Z7McXJaKiFPrUHbw2NgdiijlaEoz/SR5JyEcwe5P++er9dPTWt+82hM
# OCs7BOJ/QuqZLhyWFlTJfTDbt0Dx5Ytc5OrUBQoGuwGpRT1LS1ZmqmCnhFnTBVYq
# 35B1qYOTgnE+9TyBc8FVuPKgEiint4fpDU9FYN0CRIZa6cydJ0nFK27jjK3mRRb5
# X7ecHhwhwXRTpEyAk4j/BUoSWIOywD1abInR38B5Gf6dSVu7Ohyj2Z18R8TfS11q
# 6YfNf+L4tirN/qcfzymea2swkxE0lFjKyIxw2sZYyFExggJIMIICRAIBATCBpjCB
# oDETMBEGA1UEAwwKVGhyZWF0V29yeDEYMBYGA1UECgwPVGhyZWF0V2F0Y2ggSW5j
# MRQwEgYDVQQLDAtFbmdpbmVlcmluZzETMBEGA1UECAwKQ2FsaWZvcm5pYTELMAkG
# A1UEBhMCVVMxEjAQBgNVBAcMCUxvcyBHYXRvczEjMCEGCSqGSIb3DQEJARYUcGFy
# ZXNoQHRocmVhdHdvcnguaW8CAQEwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFMvPCEre21mo2XEJ
# 4g+Pq6otWPuCMA0GCSqGSIb3DQEBAQUABIIBAE2Wx5bfHqte39vkhAYOZohzc7mQ
# kGr3r2rjFYDwjwJ+pDWB7ibZxZfQsnkRxwBkIjhjfBOVHurzB2XWQKWW4TuOmX/m
# 2e0hQLiLnu4mvIgzVlMwp2ax7Yyc64h/1Sh11/Leuew5mSrHa/oM3jUpAyW4QLKi
# +ZIK6+5jrO22qBZhanK7Uce4q+XYXo/cTYehI5UaCxX61Q6jsh/902ZNC8UumTC2
# DjlzbQ9Inw68TTQ2esRNPaJi2UJckGVVbU85SsBAao9StI8ybixSECdpFXhclJNP
# 9RaSWq53X/RmBYZmZlOEqpgC2g+3fUyzFReolEKrHhQPl1Os5LYsbFwO1D0=
# SIG # End signature block
