param(
    [string]$Repo = "oMrCat/VaultLock",
    [string]$WikiDir = ""
)

# Publishes the markdown pages in docs\wiki to the repository's GitHub wiki.
#
# NOTE: GitHub only creates the wiki git repository (<repo>.wiki.git) after the
# first page has been created through the web UI. If the clone below fails with
# "Repository not found", open https://github.com/<Repo>/wiki once and click
# "Create the first page", then run this script again.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($WikiDir)) {
    $WikiDir = Join-Path $root "docs\wiki"
}

if (-not (Test-Path $WikiDir)) {
    throw "Wiki source directory not found: $WikiDir"
}

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("vaultlock-wiki-" + [guid]::NewGuid().ToString("N"))
$url = "https://github.com/$Repo.wiki.git"

Write-Host "Cloning $url ..." -ForegroundColor Cyan
git clone $url $temp

try {
    Get-ChildItem (Join-Path $temp "*.md") -ErrorAction SilentlyContinue | Remove-Item -Force
    Copy-Item (Join-Path $WikiDir "*.md") $temp
    Push-Location $temp
    try
    {
        if (-not (git config user.email)) {
            git config user.email "130645935+oMrCat@users.noreply.github.com"
        }
        if (-not (git config user.name)) {
            git config user.name "oMrCat"
        }

        git add -A
        git commit -m "Docs: sync wiki from docs/wiki" 2>$null
        git push
    }
    finally {
        Pop-Location
    }

    Write-Host "Wiki published: https://github.com/$Repo/wiki" -ForegroundColor Green
}
finally {
    Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue
}
