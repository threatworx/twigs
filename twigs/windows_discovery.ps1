<#
.SYNOPSIS
    Windows Host discovery script (twigs equivalent)
.DESCRIPTION
    This script helps discovery Windows Host(s) as assets in ThreatWatch instance. It is equivalent to twigs.
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
.EXAMPLE
    .\windows_discovery.ps1 -handle someuser@company.com -token XXXX -instance ACME.threatwatch.io -out asset.json -assetid myassetid -assetname myassetname -tag_critical -tags 'tag1','tag2'
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
    $tags	
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

$ip_address = (get-netadapter | get-netipaddress | ? addressfamily -eq 'IPv4').ipaddress
if (!$assetid) {
    $assetid = $ip_address
}
if (!$assetname) {
    $assetname = $assetid
}
$assetid = $assetid.Replace("/","-")
$assetid = $assetid.Replace(":","-")
$assetname = $assetname.Replace("/","-")
$assetname = $assetname.Replace(":","-")

$tw_assets_url = 'https://' + $instance+ '/api/v2/assets/'

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

Write-Host ''
Write-Host 'Extracting service pack...'
$temp_str = wmic os get Caption /format:list | Select-string -Pattern 'CSDVersion'
if ($temp_str) { $os_sp = $temp_str.ToString().Split('=')[1].Trim(); Write-Host 'Service Pack:', $os_sp} else { Write-Host 'Service Pack: No service pack found' } 

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
Write-Host 'Number of products found (using registry key):', $temp_array.Length
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
$os_and_sp = $base_os + ' ' + $os_sp
$tags_json_array.Add('OS_RELEASE:' + $os_and_sp.Trim())
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
    }
}

if ($out) {
    # ConvertFrom-Json and ConvertTo-Json is required for pretty printing the JSON
    $body | ConvertFrom-Json | ConvertTo-Json -Depth 100 | Out-File $out
}

