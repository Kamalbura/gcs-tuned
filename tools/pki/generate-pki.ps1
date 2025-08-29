#requires -version 5.1
$ErrorActionPreference = 'Stop'

# UAVPI PKI generator (idempotent)
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$PKIDir   = Join-Path $RepoRoot 'pki'
$CertsDir = Join-Path (Split-Path -Parent $RepoRoot) 'certs'

# Adjust for current repo layout: tools/pki -> repo root
$Workspace = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$RootDir = Split-Path -Parent $Workspace
$Out = Join-Path $RootDir 'certs'

if (Test-Path $Out) { Remove-Item -Recurse -Force $Out }
New-Item -ItemType Directory -Force -Path $Out | Out-Null

# OpenSSL config
$OpenSSLConf = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'openssl.cnf'
if (!(Test-Path $OpenSSLConf)) { throw "Missing openssl.cnf at $OpenSSLConf" }

# Prepare CA database structure for index/serial if needed
Push-Location (Split-Path -Parent $OpenSSLConf)
if (!(Test-Path 'index.txt')) { New-Item -ItemType File -Name 'index.txt' | Out-Null }
if (!(Test-Path 'serial'))    { Set-Content -Path 'serial' -Value '1000' }
if (!(Test-Path 'newcerts'))  { New-Item -ItemType Directory -Name 'newcerts' | Out-Null }
Pop-Location

function New-Key {
    param([string]$Path, [int]$Bits)
    & openssl genrsa -out $Path $Bits | Out-Null
}

function New-CSR {
    param([string]$Key, [string]$CSR, [string]$CN)
    & openssl req -new -key $Key -out $CSR -subj "/CN=$CN" -config $OpenSSLConf | Out-Null
}

function SelfSign-CA {
    param([string]$Key, [string]$Cert)
    & openssl req -x509 -new -nodes -key $Key -sha256 -days 3650 -out $Cert -subj "/CN=UAVPI Root CA" -config $OpenSSLConf -extensions v3_ca | Out-Null
}

function Sign-Cert {
    param([string]$CSR, [string]$CACert, [string]$CAKey, [string]$OutCert, [string]$Ext)
    & openssl x509 -req -in $CSR -CA $CACert -CAkey $CAKey -CAcreateserial -out $OutCert -days 825 -sha256 -extfile $OpenSSLConf -extensions $Ext | Out-Null
}

# 1) Root CA
$CAKey  = Join-Path $Out 'ca-key.pem'
$CACert = Join-Path $Out 'ca-cert.pem'
New-Key -Path $CAKey -Bits 4096
SelfSign-CA -Key $CAKey -Cert $CACert

# 2) Server (broker)
$SrvKey = Join-Path $Out 'server-key.pem'
$SrvCSR = Join-Path $Out 'server-csr.pem'
$SrvCrt = Join-Path $Out 'server-cert.pem'
New-Key -Path $SrvKey -Bits 2048
New-CSR -Key $SrvKey -CSR $SrvCSR -CN 'uavpi-broker.local'
Sign-Cert -CSR $SrvCSR -CACert $CACert -CAKey $CAKey -OutCert $SrvCrt -Ext 'v3_server'

# 3) GCS client
$GKey = Join-Path $Out 'uavpi-gcs-key.pem'
$GCSR = Join-Path $Out 'uavpi-gcs-csr.pem'
$GCrt = Join-Path $Out 'uavpi-gcs-cert.pem'
New-Key -Path $GKey -Bits 2048
New-CSR -Key $GKey -CSR $GCSR -CN 'uavpi-gcs'
Sign-Cert -CSR $GCSR -CACert $CACert -CAKey $CAKey -OutCert $GCrt -Ext 'v3_client'

# 4) Drone clients
$drones = @('uavpi-drone-01','uavpi-drone-02','uavpi-drone-03')
foreach ($d in $drones) {
    $k = Join-Path $Out "$d-key.pem"
    $r = Join-Path $Out "$d-csr.pem"
    $c = Join-Path $Out "$d-cert.pem"
    New-Key -Path $k -Bits 2048
    New-CSR -Key $k -CSR $r -CN $d
    Sign-Cert -CSR $r -CACert $CACert -CAKey $CAKey -OutCert $c -Ext 'v3_client'
}

Write-Host "\nUAVPI PKI generated in $Out" -ForegroundColor Cyan
& openssl x509 -noout -subject -in $CACert
& openssl x509 -noout -subject -in $SrvCrt
& openssl x509 -noout -subject -in $GCrt
foreach ($d in $drones) { & openssl x509 -noout -subject -in (Join-Path $Out "$d-cert.pem") }

Write-Host "\nFiles:" -ForegroundColor Cyan
Get-ChildItem -Path $Out | Format-Table -AutoSize
