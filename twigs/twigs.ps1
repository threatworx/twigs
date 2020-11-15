<#
.SYNOPSIS
    Windows Host discovery script (twigs equivalent)
.DESCRIPTION
    This script helps discover Windows Host(s) as assets in ThreatWatch instance. It is equivalent to twigs.
.PARAMETER handle
    Specifies the handle of the ThreatWatch user. Mandatory.
.PARAMETER token
    Specifies the API token of the ThreatWatch user. Optional.
.PARAMETER instance
    Specifies the ThreatWatch instance. Optional.
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
.PARAMETER email_report
    After impact refresh is complete, email scan report to self. Optional.
.EXAMPLE
    .\twigs.ps1 -handle someuser@company.com -token XXXX -instance ACME.threatwatch.io -out asset.json -assetid myassetid -assetname myassetname -tag_critical -tags 'tag1','tag2' -email_report
.NOTES
    .    
#>
# Sample PowerShell based discovery script for Windows
param(
    [parameter(Mandatory=$true, HelpMessage='Enter the email handle for ThreatWatch instance')]
    [String]
    $handle,

    [parameter(Mandatory=$false, HelpMessage='Enter the API key for the specified email handle for ThreatWatch instance')]
    [String]
    $token,

    [parameter(Mandatory=$false, HelpMessage='Specify the ThreatWatch instance')]
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

    [parameter(Mandatory=$false, HelpMessage='Tag the asset as critical')]
    [Switch]
    $tag_critical,
	
    [parameter(Mandatory=$false, HelpMessage='Specify tags for the asset')]
    [String[]]
    $tags,

    [parameter(Mandatory=$false, HelpMessage='Do not initiate a baseline assessment')]
    [Switch]
    $no_scan,

    [parameter(Mandatory=$false, HelpMessage='After impact refresh is complete email scan report to self')]
    [Switch]
    $email_report
)

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

    Write-Host ''
}
Write-Host 'Running discovery for Windows...'

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


# SIG # Begin signature block
# MIIGzwYJKoZIhvcNAQcCoIIGwDCCBrwCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUGobnJtd7VQ4WuDZE+1JSgIfl
# ssugggPvMIID6zCCAtOgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBojEYMBYGA1UE
# AwwPVGhyZWF0V2F0Y2ggSW5jMRQwEgYDVQQKDAtUaHJlYXRXYXRjaDEUMBIGA1UE
# CwwLRW5naW5lZXJpbmcxEzARBgNVBAgMCkNhbGlmb3JuaWExCzAJBgNVBAYTAlVT
# MRIwEAYDVQQHDAlMb3MgR2F0b3MxJDAiBgkqhkiG9w0BCQEWFXBhcmVzaEB0aHJl
# YXR3YXRjaC5pbzAeFw0yMDAzMDUwOTA1NDhaFw0yMTAzMDUwOTA1NDhaMIGiMRgw
# FgYDVQQDDA9UaHJlYXRXYXRjaCBJbmMxFDASBgNVBAoMC1RocmVhdFdhdGNoMRQw
# EgYDVQQLDAtFbmdpbmVlcmluZzETMBEGA1UECAwKQ2FsaWZvcm5pYTELMAkGA1UE
# BhMCVVMxEjAQBgNVBAcMCUxvcyBHYXRvczEkMCIGCSqGSIb3DQEJARYVcGFyZXNo
# QHRocmVhdHdhdGNoLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# k1b5ECiLgexaGeo1TEpVsQ/YIbWXqwrl6UljGBjP77TjhWAFTsUkTV9cdG62xx4X
# wHN+9vtBnkQH695GhtZdR8eznPSh13qCscqzb48IBDVLfcCSNEMA51mQC9luLFzZ
# YB+p8yMuQMrFObEL2EqZnRQZNgzRl/nFjWChFM9YwuCf5OpP6NBuyZaMTS6d0iHg
# qm3udejdZqppF92UL7u9oS0gEHVY7xHfg1BUSlqfRWLH0q3TKyWJe+HZdgrwRgOF
# toCd9T6oQrFHVBs8txPqcoamazCncK2mXveGzepUGK4JU9cjSwBrWOt86MuoJoHv
# S13ogPiRX53YjE2dWUngOQIDAQABoyowKDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0l
# AQH/BAwwCgYIKwYBBQUHAwMwDQYJKoZIhvcNAQELBQADggEBABvV/gzUXYoGXQsj
# KqK1epGkeO/7kX01zWj24gSlnWXPeGb4j8agfQMgYwMGM2oMdNS2brZrdzlZ6Q1v
# 2h08uMWF6QdcbrLPrz/YUoHo7cP9+Jw4yBYTqwcW5sKplCMqap8yCoukjIG37H8X
# SfA2Rir5S5RNdnYvDuZkC2+0Y3jLFTlSLP3nyMzSmwP6hulw/hkSpd+L8SzxpGmD
# 4S5cQUQmmrm3wuHvUI+OVddplMG1yi+Cbx4eIU4pZIP4x5okbkZ5LylERgWEaHad
# cNiRtOsuvnxOKCLzSZKGz6AF8M/aXaUpnfm4bqMRq4aaDo9VtY+Tp8ZQJXD8UiwI
# hmthHKoxggJKMIICRgIBATCBqDCBojEYMBYGA1UEAwwPVGhyZWF0V2F0Y2ggSW5j
# MRQwEgYDVQQKDAtUaHJlYXRXYXRjaDEUMBIGA1UECwwLRW5naW5lZXJpbmcxEzAR
# BgNVBAgMCkNhbGlmb3JuaWExCzAJBgNVBAYTAlVTMRIwEAYDVQQHDAlMb3MgR2F0
# b3MxJDAiBgkqhkiG9w0BCQEWFXBhcmVzaEB0aHJlYXR3YXRjaC5pbwIBATAJBgUr
# DgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMx
# DAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkq
# hkiG9w0BCQQxFgQUbbRVepE+cYz+WJwXrdc5BPGmMbEwDQYJKoZIhvcNAQEBBQAE
# ggEAczJjoe0KPECjB/LNU3lpZFuVHX/4uMW1+DUo7lVP+aJFo6pxSZtBUTFKZk/v
# 2vAhQ0QIbjhQ4UqtuL8Pfz6VMEyw4kAKT/zakAmZzAP8fUdC/p299HPnm44DY2Wv
# likRm5BGZS1wtrqgU8Mp9vFz5V20pgRzjKnP5xovKiKTfYLB5nJDk92YY+3xjMEl
# vHxjOqqJNVNCU3NhZZf6Rj4Z6s5arQwnsHaO16GBgBlq66FRj5h32KzGmTAsB6Cv
# 9eCxKeKQR7o1Pc5ryqgprzsepHnV5z2N39YqjncofjCSBtnwBLlyPcbJ9LgSL+5q
# KAG2ULmwKDJnkKTkbH5K/w2a4g==
# SIG # End signature block
