<#
.SYNOPSIS
    YARA Scanner Uploader for AnalysisHub
#>

param (
    [string]$BaseUrl = "http://192.168.100.94:3000/api/v1",
    [string]$Email = "admin@analysishub.local",
    [string]$Password = "Admin@123456"
)

$ErrorActionPreference = "Stop"

# 1. Login
Write-Host "[*] Logging in to $BaseUrl..." -ForegroundColor Cyan
$loginBody = @{ email = $Email; password = $Password } | ConvertTo-Json
try {
    $loginResponse = Invoke-RestMethod -Uri "$BaseUrl/auth/login" -Method Post -Body $loginBody -ContentType "application/json"
    $token = $loginResponse.data.token
} catch {
    Write-Host "[!] Login failed: $_" -ForegroundColor Red; exit 1
}

$headers = @{ Authorization = "Bearer $token" }

# 2. Upload
$bundlePath = Join-Path (Get-Location) "dist\yara-scanner-bundle.zip"
if (-not (Test-Path $bundlePath)) {
    Write-Host "[!] Bundle not found at $bundlePath. Run bundle.py first." -ForegroundColor Red; exit 1
}

Write-Host "[*] Uploading YARA Scanner bundle..." -ForegroundColor Cyan

$multipartBoundary = [System.Guid]::NewGuid().ToString()
$contentType = "multipart/form-data; boundary=$multipartBoundary"
$LF = "`r`n"
$bodyBuilder = New-Object System.Text.StringBuilder

$metadata = @{
    name = "YARA Scanner"
    category = "triage"
    platform = "both"
    executable_path = "{{OS}}/yara-scanner{{EXT}}"
    description = "Integrated YARA Scanner - hunts for backdoors on Windows and Linux."
}

foreach ($key in $metadata.Keys) {
    $bodyBuilder.Append("--$multipartBoundary$LF") | Out-Null
    $bodyBuilder.Append("Content-Disposition: form-data; name=""$key""$LF$LF") | Out-Null
    $bodyBuilder.Append("$($metadata[$key])$LF") | Out-Null
}

$bodyBuilder.Append("--$multipartBoundary$LF") | Out-Null
$bodyBuilder.Append("Content-Disposition: form-data; name=""file""; filename=""yara-scanner-bundle.zip""$LF") | Out-Null
$bodyBuilder.Append("Content-Type: application/octet-stream$LF$LF") | Out-Null

$headerBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyBuilder.ToString())
$fileBytes = [System.IO.File]::ReadAllBytes($bundlePath)
$footerBytes = [System.Text.Encoding]::UTF8.GetBytes("$LF--$multipartBoundary--$LF")

$fullBodyBytes = New-Object byte[] ($headerBytes.Length + $fileBytes.Length + $footerBytes.Length)
[System.Buffer]::BlockCopy($headerBytes, 0, $fullBodyBytes, 0, $headerBytes.Length)
[System.Buffer]::BlockCopy($fileBytes, 0, $fullBodyBytes, $headerBytes.Length, $fileBytes.Length)
[System.Buffer]::BlockCopy($footerBytes, 0, $fullBodyBytes, ($headerBytes.Length + $fileBytes.Length), $footerBytes.Length)

try {
    $response = Invoke-RestMethod -Uri "$BaseUrl/tools" -Method Post -Headers $headers -ContentType $contentType -Body $fullBodyBytes
    if ($response.success) {
        Write-Host "[+] Successfully uploaded YARA Scanner" -ForegroundColor Green
    } else {
        Write-Host "[!] Upload failed: $($response.error)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
}
