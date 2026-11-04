#Requires -Version 5.1
<#
.SYNOPSIS
    对 FolderLock 发布产物进行 Authenticode 代码签名（含 RFC3161 时间戳），并立即校验。

.DESCRIPTION
    证书来源二选一：
      -Thumbprint  使用证书存储（CurrentUser\My 或 LocalMachine\My）中已导入的证书；
      -PfxPath     使用 PFX 文件，密码来自 -PfxPassword 或环境变量（默认 CODE_SIGN_PFX_PASSWORD）。
    签名使用 signtool.exe（Windows SDK），必须带 RFC3161 时间戳，保证证书过期后签名仍然有效。
    每个文件签名后立即用 Get-AuthenticodeSignature 校验状态与签名者主题，任一失败即非零退出。

.PARAMETER AllowUntrustedChain
    仅供本地验证自签名证书使用：允许“签名有效但证书链不受信任”的状态通过。
    正式发布不得使用此开关。

.PARAMETER DryRun
    只打印将要执行的 signtool 命令，不实际签名。也可用 -WhatIf。

.EXAMPLE
    .\installer\sign.ps1 -Thumbprint 1A2B3C... -ExpectedPublisher "CN=VaultLock, O=Your Company"

.EXAMPLE
    $env:CODE_SIGN_PFX_PASSWORD = 'secret'
    .\installer\sign.ps1 -PfxPath .\cert\codesign.pfx

.EXAMPLE
    .\installer\sign.ps1 -Thumbprint 1A2B... -DryRun
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Thumbprint,

    [string]$PfxPath,

    [string]$PfxPassword,

    [string]$PfxPasswordEnv = "CODE_SIGN_PFX_PASSWORD",

    [string]$TimestampUrl = "http://timestamp.digicert.com",

    [string]$PublishDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) "artifacts\publish\win-x64"),

    [string[]]$Files,

    [string[]]$InstallerFiles,

    [string]$ExpectedPublisher,

    [string]$SigntoolPath,

    [switch]$AllowUntrustedChain,

    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Find-Signtool {
    param([string]$ExplicitPath)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        if (-not (Test-Path -LiteralPath $ExplicitPath)) {
            throw "未找到 signtool.exe：$ExplicitPath"
        }

        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }

    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $kitsRoots = @()
    if (${env:ProgramFiles(x86)}) {
        $kitsRoots += (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin")
        $kitsRoots += (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\8.1\bin")
    }

    if ($env:ProgramFiles) {
        $kitsRoots += (Join-Path $env:ProgramFiles "Windows Kits\10\bin")
    }

    foreach ($root in $kitsRoots) {
        if (-not (Test-Path -LiteralPath $root)) {
            continue
        }

        $candidate = Get-ChildItem -Path $root -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
            Sort-Object -Property FullName -Descending |
            Select-Object -First 1

        if ($candidate) {
            return $candidate.FullName
        }
    }

    throw "未找到 signtool.exe（属于 Windows SDK）。请安装 Windows SDK，或用 -SigntoolPath 指定完整路径。"
}

function Resolve-CertificateSource {
    if (-not [string]::IsNullOrWhiteSpace($Thumbprint)) {
        $normalized = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
        if ($normalized.Length -eq 0) {
            throw "证书指纹格式无效：$Thumbprint"
        }

        $found = @()
        foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
            $found += @(Get-ChildItem -Path $store -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -eq $normalized })
        }

        $certificate = $found | Where-Object { $_.HasPrivateKey } | Select-Object -First 1
        if (-not $certificate) {
            throw "证书存储中未找到带私钥的签名证书：$Thumbprint（请先导入到 CurrentUser\My 或 LocalMachine\My）。"
        }

        return [pscustomobject]@{
            Mode       = 'Store'
            Thumbprint = $certificate.Thumbprint
            Subject    = $certificate.Subject
            PfxPath    = $null
            Password   = $null
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($PfxPath)) {
        $resolved = Resolve-Path -LiteralPath $PfxPath -ErrorAction SilentlyContinue
        if (-not $resolved) {
            throw "未找到 PFX 文件：$PfxPath"
        }

        $password = $PfxPassword
        if ([string]::IsNullOrEmpty($password)) {
            $password = [Environment]::GetEnvironmentVariable($PfxPasswordEnv)
        }

        if ([string]::IsNullOrEmpty($password)) {
            throw "PFX 需要密码：请传 -PfxPassword，或设置环境变量 $PfxPasswordEnv。"
        }

        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($resolved.Path, $password)
        try {
            if (-not $certificate.HasPrivateKey) {
                throw "PFX 中不包含私钥：$($resolved.Path)"
            }

            $subject = $certificate.Subject
        }
        finally {
            $certificate.Dispose()
        }

        return [pscustomobject]@{
            Mode       = 'Pfx'
            Thumbprint = $null
            Subject    = $subject
            PfxPath    = $resolved.Path
            Password   = $password
        }
    }

    throw "必须指定证书来源：-Thumbprint（证书存储）或 -PfxPath（PFX 文件）。"
}

function Invoke-SignFile {
    param(
        [string]$File,
        [pscustomobject]$Source
    )

    $arguments = @('sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $TimestampUrl, '/v')
    if ($Source.Mode -eq 'Pfx') {
        $arguments += @('/f', $Source.PfxPath, '/p', $Source.Password)
    }
    else {
        $arguments += @('/sha1', $Source.Thumbprint)
    }

    $arguments += $File

    if ($DryRun -or $WhatIfPreference) {
        # 不打印 PFX 密码，避免泄露到日志/CI 输出。
        $display = ($arguments | ForEach-Object {
                if ($_ -eq $Source.Password -and $Source.Mode -eq 'Pfx') { '***' } else { $_ }
            }) -join ' '
        Write-Host "[dry-run] `"$script:Signtool`" $display" -ForegroundColor Yellow
        return
    }

    Write-Host "签名：$([IO.Path]::GetFileName($File))" -ForegroundColor Cyan
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        & $script:Signtool @arguments | Out-Host

        if ($LASTEXITCODE -eq 0) {
            return
        }

        if ($attempt -eq 1) {
            Write-Warning "signtool 第一次签名失败（退出码 $LASTEXITCODE），1 秒后重试（时间戳服务器偶发不可用）。"
            Start-Sleep -Seconds 1
        }
    }

    throw "signtool 签名失败（退出码 $LASTEXITCODE）：$File"
}

function Test-SignedFile {
    param(
        [string]$File,
        [pscustomobject]$Source,
        [string]$Publisher
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $File -ErrorAction Stop
    $subject = $null
    if ($signature.SignerCertificate) {
        $subject = $signature.SignerCertificate.Subject
    }

    $displaySubject = if ($subject) { $subject } else { '(无)' }
    Write-Host ("  校验：{0} -> Status={1}; Signer={2}" -f [IO.Path]::GetFileName($File), $signature.Status, $displaySubject) -ForegroundColor Gray

    if ($signature.Status -ne 'Valid') {
        $isUntrustedChain = $signature.Status -in @('NotTrusted', 'UnknownError')
        if ($AllowUntrustedChain -and $isUntrustedChain -and $subject) {
            Write-Warning "证书链不受信任（$($signature.Status)）：-AllowUntrustedChain 仅用于本地验证，禁止用于发布。"
        }
        else {
            throw "签名校验未通过（$File）：Status=$($signature.Status)；$($signature.StatusMessage)"
        }
    }

    if ([string]::IsNullOrWhiteSpace($subject)) {
        throw "无法读取签名者证书主题：$File"
    }

    if (-not [string]::IsNullOrWhiteSpace($Publisher)) {
        $normalizedActual = ($subject -replace '\s', '')
        $normalizedExpected = ($Publisher -replace '\s', '')
        if ($normalizedActual -ne $normalizedExpected) {
            throw "签名者与预期发布者不一致：实际[$subject]，预期[$Publisher]。"
        }

        Write-Host "  发布者匹配：$subject" -ForegroundColor Gray
    }
}

try {
    $source = Resolve-CertificateSource
    $script:Signtool = Find-Signtool -ExplicitPath $SigntoolPath
    $publisher = if ([string]::IsNullOrWhiteSpace($ExpectedPublisher)) { $source.Subject } else { $ExpectedPublisher }

    if ([string]::IsNullOrWhiteSpace($TimestampUrl)) {
        throw "必须提供 RFC3161 时间戳服务器（-TimestampUrl），否则证书过期后签名将失效。"
    }

    $targets = @()
    if ($Files) {
        $targets = @($Files)
    }
    else {
        $targets = @(
            (Join-Path $PublishDirectory 'FolderLock.App.exe'),
            (Join-Path $PublishDirectory 'FolderLock.Service.exe')
        )
    }

    if ($InstallerFiles) {
        $targets += @($InstallerFiles)
    }
    else {
        $artifacts = Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts'
        if (Test-Path -LiteralPath $artifacts) {
            $targets += @(Get-ChildItem -Path $artifacts -Filter 'FolderLock-Setup-*.exe' -File -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty FullName)
        }
    }

    $missing = @($targets | Where-Object { -not (Test-Path -LiteralPath $_) })
    if ($missing.Count -gt 0) {
        throw "待签名文件不存在：`n$($missing -join [Environment]::NewLine)"
    }

    Write-Host "证书来源：$($source.Mode)（主题：$($source.Subject)）" -ForegroundColor Cyan
    Write-Host "时间戳：$TimestampUrl" -ForegroundColor Cyan

    if ($DryRun -or $WhatIfPreference) {
        Write-Host "[dry-run] 不执行签名与校验。" -ForegroundColor Yellow
    }

    foreach ($target in $targets) {
        Invoke-SignFile -File $target -Source $source

        if (-not ($DryRun -or $WhatIfPreference)) {
            Test-SignedFile -File $target -Source $source -Publisher $publisher
        }
    }

    if ($DryRun -or $WhatIfPreference) {
        Write-Host "dry-run 完成：$($targets.Count) 个文件待签名，未做任何修改。" -ForegroundColor Yellow
        return
    }

    Write-Host "签名完成并通过校验：$($targets.Count) 个文件。" -ForegroundColor Green
}
catch {
    Write-Host "签名流程失败：$($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
