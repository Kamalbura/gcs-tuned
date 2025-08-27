param(
    [string]$MosquittoRoot = 'C:\\Program Files\\mosquitto',
    [string]$BrokerCN = 'uav-broker.local',
    [string[]]$UavIds = @('uav1','uav2'),
    [string[]]$GcsIds = @('gcs1'),
    [switch]$Force,
    [switch]$Deploy
)

$ErrorActionPreference = 'Stop'

function Get-ScriptRoot {
    if ($PSScriptRoot) { return $PSScriptRoot }
    if ($PSCommandPath) { return Split-Path -Parent $PSCommandPath }
    return Split-Path -Parent $MyInvocation.MyCommand.Path
}

$root = Get-ScriptRoot
$opensslCnf = Join-Path $root 'openssl_uav.cnf'

$serverDir = Join-Path $MosquittoRoot 'server'
$clientsDir = Join-Path $MosquittoRoot 'clients'
$programData = 'C:\\ProgramData\\mosquitto'
$logDir = Join-Path $programData 'log'

New-Item -ItemType Directory -Force -Path $serverDir | Out-Null
New-Item -ItemType Directory -Force -Path $clientsDir | Out-Null
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

function Run($cmd) {
    Write-Host "→ $cmd" -ForegroundColor Cyan
    cmd /c $cmd
    if ($LASTEXITCODE -ne 0) { throw "Command failed: $cmd" }
}

function New-CA {
    $cakey = Join-Path $serverDir 'ca-key.pem'
    $cacert = Join-Path $serverDir 'ca-cert.pem'
    if ((Test-Path $cakey) -and (Test-Path $cacert) -and -not $Force) {
        Write-Host 'CA exists; use -Force to recreate.' -ForegroundColor Yellow
        return
    }
    if ($Force) { Remove-Item -Force -ErrorAction SilentlyContinue $cakey, $cacert }
    Run "openssl genrsa -out `"$cakey`" 2048"
    $dn = '/C=IN/ST=Telangana/L=Hyderabad/O=UAV-Fleet/OU=UAV Control CA/CN=MyUAV-CA/emailAddress=support@uavfleet.local'
    Run "openssl req -x509 -new -nodes -key `"$cakey`" -sha256 -days 3650 -out `"$cacert`" -subj `"$dn`" -config `"$opensslCnf`" -extensions v3_ca"
}

function New-ServerCert {
    $key = Join-Path $serverDir 'server-key.pem'
    $csr = Join-Path $serverDir 'server.csr'
    $crt = Join-Path $serverDir 'server-cert.pem'
    $cakey = Join-Path $serverDir 'ca-key.pem'
    $cacert = Join-Path $serverDir 'ca-cert.pem'

    if ($Force) { Remove-Item -Force -ErrorAction SilentlyContinue $key, $csr, $crt }

    Run "openssl genrsa -out `"$key`" 2048"
    $dn = "/C=IN/ST=Telangana/L=Hyderabad/O=UAV-Fleet/OU=UAV Control Server/CN=$BrokerCN/emailAddress=broker@uavfleet.local"
    Run "openssl req -new -key `"$key`" -out `"$csr`" -subj `"$dn`" -config `"$opensslCnf`""

    # Sign with SAN using v3_server
    Run "openssl x509 -req -in `"$csr`" -CA `"$cacert`" -CAkey `"$cakey`" -CAcreateserial -out `"$crt`" -days 825 -sha256 -extfile `"$opensslCnf`" -extensions v3_server"
}

function New-ClientCert {
    param(
        [string]$id,
        [string]$ou
    )
    $key = Join-Path $clientsDir "$id-key.pem"
    $csr = Join-Path $clientsDir "$id.csr"
    $crt = Join-Path $clientsDir "$id-cert.pem"
    $cakey = Join-Path $serverDir 'ca-key.pem'
    $cacert = Join-Path $serverDir 'ca-cert.pem'

    if ($Force) { Remove-Item -Force -ErrorAction SilentlyContinue $key, $csr, $crt }

    Run "openssl genrsa -out `"$key`" 2048"
    $dn = "/C=IN/ST=Telangana/L=Hyderabad/O=UAV-Fleet/OU=$ou/CN=$id/emailAddress=$id@uavfleet.local"
    Run "openssl req -new -key `"$key`" -out `"$csr`" -subj `"$dn`" -config `"$opensslCnf`""
    Run "openssl x509 -req -in `"$csr`" -CA `"$cacert`" -CAkey `"$cakey`" -CAcreateserial -out `"$crt`" -days 825 -sha256 -extfile `"$opensslCnf`" -extensions v3_client"
}

function Write-Acl {
    $acl = @()
    $acl += '# GCS permissions'
    foreach ($g in $GcsIds) {
        $acl += "user $g"
        $acl += 'topic read fleet/+/telemetry'
        $acl += 'topic write fleet/+/commands'
        $acl += ''
    }
    $acl += '# UAV permissions'
    foreach ($u in $UavIds) {
        $acl += "user $u"
        $acl += "topic write fleet/$u/telemetry"
        $acl += "topic read fleet/$u/commands"
        $acl += ''
    }
    $acl += '# Pattern rules (fallback)'
    $acl += 'pattern write fleet/%u/telemetry'
    $acl += 'pattern read fleet/%u/commands'

    $aclPath = Join-Path $serverDir 'swarm_acl.conf'
    Set-Content -Path $aclPath -Value ($acl -join [Environment]::NewLine) -Encoding ascii
}

function Write-MosquittoConf {
    $confPath = Join-Path $MosquittoRoot 'mosquitto.conf'
    $rootFS = ($MosquittoRoot -replace '\\','/')
    $conf = @(
        '# MQTT Broker for UAV Fleet',
        'listener 8883',
        "cafile $rootFS/server/ca-cert.pem",
        "certfile $rootFS/server/server-cert.pem",
        "keyfile $rootFS/server/server-key.pem",
        'require_certificate true',
        'use_identity_as_username true',
        'tls_version tlsv1.2',
        '',
        'allow_anonymous false',
        "acl_file $rootFS/server/swarm_acl.conf",
        '',
        'log_dest file C:/ProgramData/mosquitto/log/mosquitto.log',
        'log_type error warning notice',
        'connection_messages true'
    )
    Set-Content -Path $confPath -Value ($conf -join [Environment]::NewLine) -Encoding ascii
}

Write-Host 'Generating UAV PKI…' -ForegroundColor Green
New-CA
New-ServerCert
# Normalize and split potential comma-separated inputs
$uavList = @()
foreach ($u in $UavIds) { $uavList += ($u -split ',') }
$uavList = $uavList | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$gcsList = @()
foreach ($g in $GcsIds) { $gcsList += ($g -split ',') }
$gcsList = $gcsList | ForEach-Object { $_.Trim() } | Where-Object { $_ }

foreach ($id in $uavList) { New-ClientCert -id $id -ou 'UAV Client' }
foreach ($id in $gcsList) { New-ClientCert -id $id -ou 'Ground Control' }
Write-Acl
Write-MosquittoConf

# Ensure permissions for log dir (service runs as Local Service typically)
try {
    icacls "$logDir" /grant "NT AUTHORITY\LOCAL SERVICE:(OI)(CI)F" /T | Out-Null
} catch {
    Write-Warning ("Couldn't set ACL on {0}: {1}" -f $logDir, $_)
}

Write-Host 'Done. Files:' -ForegroundColor Green
Get-ChildItem $serverDir, $clientsDir | Format-Table -AutoSize
