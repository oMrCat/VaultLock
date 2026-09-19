param(
    [string]$ServiceExe = ""
)

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "请以管理员身份运行此脚本。"
}

if ([string]::IsNullOrWhiteSpace($ServiceExe)) {
    $ServiceExe = Join-Path $PSScriptRoot "..\src\FolderLock.App\bin\Release\net8.0-windows\publish\win-x64\FolderLock.Service.exe"
}

$ServiceExe = (Resolve-Path $ServiceExe).Path
$name = "FolderLockGuard"

sc.exe stop $name 2>$null | Out-Null
sc.exe delete $name 2>$null | Out-Null

sc.exe create $name binPath= "$ServiceExe" start= auto DisplayName= "FolderLock 守护服务"
sc.exe description $name "监控并自动恢复 FolderLock 的文件夹锁定。"
sc.exe failure $name reset= 86400 actions= restart/5000/restart/5000/restart/5000
sc.exe start $name

Write-Host "守护服务已安装并启动：$name" -ForegroundColor Green
