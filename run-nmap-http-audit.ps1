# Read-only NSE checks for the supplied application hostname, HTTPS port only.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('\A(?=.{1,253}\z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z')]
    [string]$TargetHost,
    [string]$OutDirectory,
    [switch]$PlanOnly
)

$ErrorActionPreference = 'Stop'
$auditTarget = $TargetHost.ToLowerInvariant()
$auditStamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmssZ')
$auditOutput = if ($OutDirectory) { $OutDirectory } else { Join-Path $PSScriptRoot "audit-results\nmap-http-$auditStamp" }
$outputPrefix = Join-Path $auditOutput 'scan'

# Deliberate script allowlist. No category-wide selection, version detection,
# OS detection, credential guessing, upload, or exploit scripts.
# The Host header and TLS name retain the application identity on a shared edge.
$nmapArguments = @(
    '-sT', '-Pn', '-n', '-p', '443', '--reason',
    '--max-retries', '1', '--max-parallelism', '1',
    '--host-timeout', '90s', '--script-timeout', '20s',
    '--script', 'http-title,http-headers,http-security-headers,ssl-cert',
    '--script-args', "http.host=$auditTarget,tls.servername=$auditTarget,http.max-body-size=262144,http.max-cache-size=524288,http.max-pipeline=1,http-title.url=/,http-headers.path=/,http-security-headers.path=/",
    '-oA', $outputPrefix,
    $auditTarget
)

if ($PlanOnly) {
    @{ target = $auditTarget; arguments = $nmapArguments } | ConvertTo-Json -Depth 4
    return
}
$nmapCommand = Get-Command nmap.exe -ErrorAction Stop
if (Test-Path -LiteralPath $auditOutput) {
    throw 'Output path already exists; choose a fresh -OutDirectory.'
}
New-Item -ItemType Directory -Path $auditOutput -ErrorAction Stop | Out-Null

$scriptDescription = @"
Scope: $auditTarget, TCP 443 only, one address chosen by Nmap.
Scripts: http-title, http-headers, http-security-headers, ssl-cert.
The HTTP scripts request the root page using HEAD/GET; ssl-cert retrieves the
presented edge certificate. Scripts may share cached responses. No request
count is inferred from the number of scripts. HTTP scripts can follow redirects;
stop and review a changed target/redirect before repeating this assessment.
CDN edge IPs/certificates may be shared infrastructure rather than a dedicated
application server. These checks do not establish a working attack or prove
the site secure. There is no TLS cipher sweep or destructive HTTP method test.
"@
$scriptDescription | Set-Content -LiteralPath (Join-Path $auditOutput 'scope.txt') -Encoding utf8
@{ executable = $nmapCommand.Source; arguments = $nmapArguments; started_at_utc = [DateTime]::UtcNow.ToString('o') } |
    ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $auditOutput 'invocation.json') -Encoding utf8

& $nmapCommand.Source @nmapArguments
$nmapExit = $LASTEXITCODE
Write-Output "Saved Nmap evidence: $auditOutput"
if ($nmapExit -ne 0) {
    throw "Nmap exited with code $nmapExit. Check the saved output; the assessment may be incomplete."
}
