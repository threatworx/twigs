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
.PARAMETER tag_critical
    Tag the asset as critical. Optional.
.PARAMETER tags
    Specify tags for the asset. Optional.
.PARAMETER no_scan
    Do not initiate a baseline assessment. Optional.
.PARAMETER no_host_benchmark
    Do not run host benchmark tests. Optional.
.PARAMETER email_report
    After impact refresh is complete, email scan report to self. Optional.
.EXAMPLE
    .\twigs.ps1 -handle someuser@company.com -token XXXX -instance ACME.threatworx.io -out asset.json -assetid myassetid -assetname myassetname -tag_critical -tags 'tag1','tag2' -email_report
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

    [parameter(Mandatory=$false, HelpMessage='Tag the asset as critical')]
    [Switch]
    $tag_critical,
    
    [parameter(Mandatory=$false, HelpMessage='Do not initiate a baseline assessment')]
    [Switch]
    $no_scan,

    [parameter(Mandatory=$false, HelpMessage='Do not run host benchmark tests')]
    [Switch]
    $no_host_benchmark,

    [parameter(Mandatory=$false, HelpMessage='After impact refresh is complete email scan report to self')]
    [Switch]
    $email_report
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
    $scriptpath = $PSScriptRoot + '\twigs.ps1'
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
            Write-Host "Running remote discovery for: ",$remotehost
            Invoke-Command -ComputerName $remotehost -FilePath $scriptpath -ArgumentList 'local',$null,$null,$null,$handle,$token,$instance,$null,$null,$null,$null,$null,$null,$true -Credential $logincredentials
        }
    } 
    Write-Host "Completed remote Windows host discovery."
}

function Invoke-LocalDiscovery {
    if (!$token -and !$instance -and !$out) {
        Write-Host "Error missing token, instance and out arguments....nothing to do!"
        exit
    }

    if ($no_scan -and $email_report) {
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
        Write-Host 'Validating credentials...'
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
        Write-Host 'Credentials validated.'
    }
    Write-Host ''
    Write-Host 'Extracting OS details...'
    $temp_str = wmic os get Caption /format:list | Select-string -Pattern 'Caption'
    $base_os = $temp_str.ToString().Split('=')[1].Trim()
    Write-Host "OS:", $base_os

    $os_version = $null
    $os_release_id = $null
    $os_arch = $null
    $temp_str = systeminfo /fo csv | ConvertFrom-Csv | format-list -Property 'OS Version' | Out-String
    $os_version = $temp_str.ToString().Trim().Split(':')[1].Trim()
    $temp_str = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
    if ($temp_str) {
        $os_release_id = $temp_str.ToString().Trim()
    }
    $temp_str = systeminfo /fo csv | convertFrom-Csv | format-list -Property 'System Type' | Out-String
    $mc_arch = $temp_str.ToString().Trim().Split(':')[1].Trim()
    $temp_str = wmic os get OSArchitecture /format:list | Select-string -Pattern 'OSArchitecture'
    $bit_arch = $temp_str.ToString().Split('=')[1].Trim()
    $os_arch = $bit_arch + ' ' + $mc_arch
    $os_arch = $os_arch.Trim()

    Write-Host ''
    Write-Host 'Extracting patch information...'
    $patch_csv_file = 'wmic_patches.csv'
    wmic qfe get HotFixID /format:csv > $patch_csv_file
    Get-Content $patch_csv_file | where {$_ -ne ""} > "$patch_csv_file-temp" ; move "$patch_csv_file-temp" $patch_csv_file -Force
    $temp_array = Import-Csv -Path $patch_csv_file
    $patch_json_array = New-Object System.Collections.Generic.List[System.Object]
    foreach ($row in $temp_array) { $temp_kb_id = $row.HotFixID; $patch_entry_json = @{id=$temp_kb_id.Trim()}; $patch_json_array.add($patch_entry_json)}
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
    Write-Host 'Extracting products (using wmic)...'
    $product_csv_file = 'wmic_products.csv'
    # Qoute the comma characters in the command below since otherwise PowerShell will endup interpreting those...
    wmic product get name","vendor","version /format:csv > $product_csv_file
    Get-Content $product_csv_file | where {$_ -ne ""} > "$product_csv_file-temp" ; move "$product_csv_file-temp" $product_csv_file -Force
    $temp_array = Import-Csv -Path $product_csv_file
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
    if ($tag_critical) {
        $tags_json_array.Add('CRITICALITY:5')
    }
    if ($tags) {
        foreach($tag in $tags) {
            $tags_json_array.Add($tag)
        }
    }

    $misconfigs_json_array = New-Object System.Collections.Generic.List[System.Object]
    # Run host benchmark if specified
    if (-not $no_host_benchmark) {
        Write-Host "Running host benchmarks. This may take some time..."
        $hk_script = $PSScriptRoot + '\Invoke-HardeningKitty.ps1'
        $hbm_csv_rpt = $PSScriptRoot + '\twigs_hbm.csv'
        if (Test-Path $hbm_csv_rpt) { Remove-Item $hbm_csv_rpt }
        . ($hk_script)
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
                $misconfig_entry_json = @{asset_id='abcd';twc_id=$misconfig.ID;twc_title=$misconfig.Name;type='Host Benchmark';details=$details_msg;rating=$mc_rating;object_id='';object_meta=''}
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


    $payload = @{
        id=$assetid
        name=$assetname
        type='Windows'
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
            if (-not $no_scan -and $response.status -Match 'No product updates') {
                Write-Host 'Asset products are not updated. No need for impact refresh.'
                $no_scan = $true
            }
        }

        if (-not $no_scan) {
            $http_method = 'Post'
            $url = $tw_scan_url + '?handle=' + $handle + '&token=' + $token + '&format=json'
            $assets_array = New-Object System.Collections.Generic.List[string]
            $assets_array.Add($assetid)
            $payload = @{
                scan_type='full'
                assets=$assets_array
            }
            if ($email_report) {
                $payload["mode"] = "email"
            }
            $body = (ConvertTo-Json -Depth 100 $payload)
            Write-Host 'Starting impact refresh...'
            $response = Invoke-RestMethod -Method $http_method -Uri $url -ContentType 'application/json' -Body $body
            Write-Host 'Started impact refresh.'
        }
    }

    if ($out) {
        $temp_body = ($body | ConvertFrom-Json)
        ConvertTo-Json -Depth 100 @($temp_body) | Out-File $out
    }

    # Remove any temporary files
    Remove-Item -force -path $patch_csv_file
    Remove-Item -force -path $product_csv_file
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
# MIIGzAYJKoZIhvcNAQcCoIIGvTCCBrkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUjNSGjOLoq68QP+vHtHIDTCJu
# zVSgggPtMIID6TCCAtGgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBoTETMBEGA1UE
# AwwKVGhyZWF0V29yeDEYMBYGA1UECgwPVGhyZWF0V2F0Y2ggSW5jMRQwEgYDVQQL
# DAtFbmdpbmVlcmluZzETMBEGA1UECAwKQ2FsaWZvcm5pYTELMAkGA1UEBhMCVVMx
# EjAQBgNVBAcMCUxvcyBHYXRvczEkMCIGCSqGSIb3DQEJARYVcGFyZXNoQHRocmVh
# dHdhdGNoLmlvMB4XDTIyMDMyOTEwMDAxNFoXDTIzMDMyOTEwMDAxNFowgaExEzAR
# BgNVBAMMClRocmVhdFdvcngxGDAWBgNVBAoMD1RocmVhdFdhdGNoIEluYzEUMBIG
# A1UECwwLRW5naW5lZXJpbmcxEzARBgNVBAgMCkNhbGlmb3JuaWExCzAJBgNVBAYT
# AlVTMRIwEAYDVQQHDAlMb3MgR2F0b3MxJDAiBgkqhkiG9w0BCQEWFXBhcmVzaEB0
# aHJlYXR3YXRjaC5pbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOjn
# butJzEXyviidHxY+7DphV75ewtbE94Cat3gr20w6eFBrQGwzGHj95712qxW/DLuJ
# qA9NNm0FZfKi04fqHxtxQoJFyMhOd+8euNY1QSK61RctNkCBqgqHq8QeCjWGy1ca
# QWaOLMYbO4PXl+tugt0YbrgV/RBOY3Gf8RMcMWmuzxhP5EEt0v/HN4HKGbdFftdV
# m4wdp6tibn5+nGGlw773vTCQBWBDBDelEkb52OEZ9UP5GEf9NZA5QDLNzoC9Otxm
# XwCO4avnXMJvFDOqtkzE9JrDa4/l7/FlxbcSRUgikBO17jlBH2/Jvvlc+sT0tunq
# Db8MdsKx+KF4HBubnxsCAwEAAaMqMCgwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB
# /wQMMAoGCCsGAQUFBwMDMA0GCSqGSIb3DQEBCwUAA4IBAQBwrx14gKN0JYN9v/Bb
# cgUs1T5SxeMApOaXjcuflFCILwkvfMDCNqbVxbDv45n/7r9bIcLghQ70LE604CE0
# ddDJJ8ekNMaIwyP3nktyt+W2vhar2WZX8I1rwgvxqBuXioCdv7xzpq/tfSSvfFCE
# kpsoPDBeDvR+wsuCW+BiO9jW9bUduvvHg7DbkWyqWa/oUd/7mdLwwvhNF3tPfVk+
# 5PH95VK8m4npk+2Zm4zaQJKgE1WZXsz5VPcA63oZTFO4G54paosJUvZFPx37Vf1d
# vdfw7xZnhl8eT4m43Ewi1MqdsFGwLYfWO8WgDmdWj+WalHTM1VFJAO4g2vF8ZcMy
# IJRtMYICSTCCAkUCAQEwgacwgaExEzARBgNVBAMMClRocmVhdFdvcngxGDAWBgNV
# BAoMD1RocmVhdFdhdGNoIEluYzEUMBIGA1UECwwLRW5naW5lZXJpbmcxEzARBgNV
# BAgMCkNhbGlmb3JuaWExCzAJBgNVBAYTAlVTMRIwEAYDVQQHDAlMb3MgR2F0b3Mx
# JDAiBgkqhkiG9w0BCQEWFXBhcmVzaEB0aHJlYXR3YXRjaC5pbwIBATAJBgUrDgMC
# GgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYK
# KwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG
# 9w0BCQQxFgQUoEiPpyUpQ1vP7/AfqqoxZWbzhsIwDQYJKoZIhvcNAQEBBQAEggEA
# CvSsIX1VU2sxfwW+0gCTNH2Oay6tAo7v5fVD8rdk2efMBpFdCwXrQNbAVALfMkbt
# yICsg9Fl0hYPE45ZSMIQt4eq+JaeuDOUaitvIcBBlj7CM6kHIIYmmp/O3rnCcaH3
# rCslY8449+QYEiBhrHYF6JlWUaYpb87dNcOQNU0baEwAa8+Hkni8vbvHO/qu3PiU
# jhgf6oeHQOXMIlFI+6s73JiVqLZXF2Q/yGaRuhZJMTdd61tHD92LWU/8Nr/d6moR
# kWso+bfKl1vHQleccXtLwW5HFKufycMGi8P3sVkVgGUQv6897Kb1306abGZf0uPO
# EdjnSFPxYUPxbO73nGHdaQ==
# SIG # End signature block
