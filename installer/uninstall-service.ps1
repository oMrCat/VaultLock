$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "请以管理员身份运行此脚本。"
}

$name = "FolderLockGuard"
sc.exe stop $name 2>$null | Out-Null
sc.exe delete $name 2>$null | Out-Null
Write-Host "守护服务已卸载：$name" -ForegroundColor Green
