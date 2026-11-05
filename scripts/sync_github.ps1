[CmdletBinding()]
param(
    [string]$CommitMessage = ""
)

$ErrorActionPreference = "Stop"
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

if ([string]::IsNullOrWhiteSpace($CommitMessage)) {
    $CommitMessage = "chore: sync project updates and diagnostic artifacts (" + (Get-Date).ToString("yyyy-MM-dd HH:mm") + ")"
}

# Pre-push privacy guard: block push if unmasked username or hostname appears in tracked/untracked candidate files
$uname = $env:USERNAME
$hname = $env:COMPUTERNAME
$statusLines = @(git status --porcelain)
if ($statusLines.Count -eq 0) {
    Write-Output "SKIP: Working tree clean, nothing new to push."
    exit 0
}

git add -A

$stagedFiles = @(git diff --cached --name-only)
$leaks = @()
foreach ($rel in $stagedFiles) {
    $full = Join-Path $ProjectRoot $rel
    if ((Test-Path $full) -and ($full -notmatch '\.(pyc|png|jpg|pdf|zip)$')) {
        $content = [System.IO.File]::ReadAllText($full, [System.Text.Encoding]::UTF8)
        if ($uname -and $content -match [regex]::Escape($uname)) {
            $leaks += ("Username in " + $rel)
        }
        if ($hname -and $content -match [regex]::Escape($hname)) {
            $leaks += ("Hostname in " + $rel)
        }
    }
}

if ($leaks.Count -gt 0) {
    git reset | Out-Null
    Write-Error ("ABORTED: Privacy guard detected unmasked identifiers before push: " + ($leaks -join "; "))
    exit 2
}

git commit -m $CommitMessage
git push -u origin main
Write-Output "OK: Successfully committed and pushed to origin/main."
