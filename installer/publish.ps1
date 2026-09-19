param(
    [string]$Configuration = "Release",
    [string]$CertThumbprint = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [switch]$NoHello
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

$appProject = Join-Path $root "src\FolderLock.App\FolderLock.App.csproj"
$serviceProject = Join-Path $root "src\FolderLock.Service\FolderLock.Service.csproj"

$helloFlag = "-p:FolderLockHello=$(-not $NoHello)".ToLower()
$tfm = if ($NoHello) { "net8.0-windows" } else { "net8.0-windows10.0.19041.0" }
$publishDir = Join-Path $root "src\FolderLock.App\bin\$Configuration\$tfm\publish\win-x64"

New-Item -ItemType Directory -Force -Path $publishDir | Out-Null

Write-Host "发布主程序 -> $publishDir  ($helloFlag)" -ForegroundColor Cyan
dotnet publish $appProject -c $Configuration -p:PublishProfile=win-x64 $helloFlag -o $publishDir

Write-Host "发布守护服务 -> $publishDir" -ForegroundColor Cyan
dotnet publish $serviceProject -c $Configuration -r win-x64 --self-contained false -o $publishDir

if (-not [string]::IsNullOrWhiteSpace($CertThumbprint)) {
    Write-Host "对可执行文件进行代码签名..." -ForegroundColor Cyan
    $signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
    if (-not $signtool) {
        Write-Warning "未找到 signtool.exe（属于 Windows SDK），跳过签名。"
    }
    else {
        foreach ($exe in Get-ChildItem $publishDir -Filter *.exe) {
            & $signtool sign /sha1 $CertThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $exe.FullName
        }
    }
}

Write-Host "完成。产物目录：$publishDir" -ForegroundColor Green
Get-ChildItem $publishDir -Filter *.exe | Select-Object Name, Length
