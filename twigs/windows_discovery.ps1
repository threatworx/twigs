# Sample PowerShell based discovery script for Windows
param(
    [parameter(Mandatory=$true, HelpMessage='Enter the email handle for ThreatWatch instance')]
    [String]
    $tw_handle,

    [parameter(Mandatory=$true, HelpMessage='Enter the API key for the specified email handle for ThreatWatch instance')]
    [String]
    $tw_api_key,

    [parameter()]
    [String]
    $tw_instance,

    [parameter(Mandatory=$true, HelpMessage='Enter the Asset ID')]
    [String]
    $asset_id
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

if ( $tw_instance ) {
    $tw_assets_url = 'https://' + $tw_instance+ '/api/v2/assets/'
}
else {
    $tw_assets_url = 'https://threatwatch.io/api/v2/assets/'
}

# Check if asset exists
$asset_exists = 1

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$url = $tw_assets_url + $asset_id + '/?handle=' + $tw_handle + '&token=' + $tw_api_key + '&format=json'
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
$tags_json_array.Add('OS_RELEASE:' + $base_os + ' ' + $os_sp)
$tags_json_array.Add('Windows')

$url = ''
$http_method = ''
if ($asset_exists -eq 0) {
    # If asset does not exist, then create one
    $http_method = 'Post'
    $url = $tw_assets_url + '?handle=' + $tw_handle + '&token=' + $tw_api_key + '&format=json'
}
else {
    # If asset exists, then update it
    $http_method = 'Put'
    $url = $tw_assets_url + $asset_id + '/?handle=' + $tw_handle + '&token=' + $tw_api_key + '&format=json'
}


$payload = @{
	id=$asset_id
	name=$asset_id
	type='Windows'
	description=''
	owner=$tw_handle
	patches=$patch_json_array
	products=$product_json_array
	tags=$tags_json_array
}
$body = (ConvertTo-Json $payload)

# Remove any non-ascii characters
$body = $body -replace '[^ -~]', ''

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
