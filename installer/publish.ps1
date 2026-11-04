param(
    [string]$Configuration = "Release",
    [switch]$Sign,
    [string]$Thumbprint = "",
    [string]$PfxPath = "",
    [string]$PfxPassword = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$ExpectedPublisher = "",
    [string]$SigntoolPath = "",
    # 仅用于本地验证自签名证书：允许证书链不受信任的签名通过校验。正式发布不要使用。
    [switch]$AllowUntrustedChain,
    [switch]$NoHello
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

$appProject = Join-Path $root "src\FolderLock.App\FolderLock.App.csproj"
$serviceProject = Join-Path $root "src\FolderLock.Service\FolderLock.Service.csproj"

$helloFlag = "-p:FolderLockHello=$(-not $NoHello)".ToLower()

# 固定发布目录：安装器（FolderLock.iss）与 install-service.ps1 都读取此目录，
# 避免因 TFM 变化（net8.0-windows 与 net8.0-windows10.0.19041.0）导致路径不一致。
$publishDir = Join-Path $root "artifacts\publish\win-x64"

New-Item -ItemType Directory -Force -Path $publishDir | Out-Null

Write-Host "发布主程序 -> $publishDir  ($helloFlag)" -ForegroundColor Cyan
dotnet publish $appProject -c $Configuration -p:PublishProfile=win-x64 $helloFlag -o $publishDir

Write-Host "发布守护服务 -> $publishDir" -ForegroundColor Cyan
dotnet publish $serviceProject -c $Configuration -r win-x64 --self-contained false -o $publishDir

if ($Sign) {
    # 签名失败时 sign.ps1 会以非零码退出（exit 1），因此发布流程会在此中止，
    # 不会产出“未签名/签名错误”的发布包。
    Write-Host "代码签名（含 RFC3161 时间戳）..." -ForegroundColor Cyan

    $signArguments = @{
        PublishDirectory = $publishDir
        TimestampUrl     = $TimestampUrl
    }
    if ($Thumbprint) { $signArguments.Thumbprint = $Thumbprint }
    if ($PfxPath) { $signArguments.PfxPath = $PfxPath }
    if ($PfxPassword) { $signArguments.PfxPassword = $PfxPassword }
    if ($ExpectedPublisher) { $signArguments.ExpectedPublisher = $ExpectedPublisher }
    if ($SigntoolPath) { $signArguments.SigntoolPath = $SigntoolPath }
    if ($AllowUntrustedChain) { $signArguments.AllowUntrustedChain = $true }

    & (Join-Path $PSScriptRoot "sign.ps1") @signArguments
    if ($LASTEXITCODE -ne 0) {
        throw "代码签名失败（退出码 $LASTEXITCODE），发布已中止，不产出签名错误的包。"
    }
}
else {
    Write-Warning "未启用代码签名（-Sign）。默认警告模式下未签名的 FolderLock.Service.exe 仍可启动，但只有日志记录、没有签名保护；正式发布请签名并把 FOLDERLOCK_REQUIRE_SIGNATURE 设为 1。"
}

Write-Host "完成。产物目录：$publishDir" -ForegroundColor Green
Get-ChildItem $publishDir -Filter *.exe | Select-Object Name, Length
