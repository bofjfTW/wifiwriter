[CmdletBinding()]
param(
    [string]$CommitMessage = "",
    [string[]]$Paths = @(),
    [switch]$StageSafeProjectFiles,
    [switch]$AllowProtectedBranch,
    [switch]$NoPush,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

$currentBranch = (& git rev-parse --abbrev-ref HEAD 2>$null).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($currentBranch)) {
    Write-Error "ABORTED: Unable to determine current Git branch."
    exit 1
}

if (($currentBranch -in @("main", "master")) -and (-not $AllowProtectedBranch)) {
    Write-Error ("ABORTED: Direct sync to protected branch '" + $currentBranch + "' is disabled in v0.2+. Switch to a feature/fix branch (e.g., fix/diagnostic-reliability-v02) and open a Pull Request.")
    exit 3
}

$SafeAllowedSpecs = @(
    ".gitignore",
    "AGENTS.md",
    "CHANGELOG.md",
    "README.md",
    "requirements.txt",
    "config/targets.example.json",
    "reports/.gitkeep",
    "src",
    "scripts",
    "docs",
    "tests",
    ".github"
)

if ($Paths.Count -gt 0) {
    foreach ($p in $Paths) {
        if (-not (Test-Path $p)) {
            Write-Error ("ABORTED: Specified path does not exist: " + $p)
            exit 1
        }
        & git add -- $p
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
} elseif ($StageSafeProjectFiles) {
    foreach ($spec in $SafeAllowedSpecs) {
        if (Test-Path $spec) {
            & git add -- $spec
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        }
    }
} else {
    $alreadyStaged = @(& git diff --cached --name-only)
    if ($alreadyStaged.Count -eq 0) {
        Write-Error "ABORTED: Unbounded 'git add -A' is prohibited. Stage explicit files first, pass -Paths <files>, or pass -StageSafeProjectFiles."
        exit 1
    }
}

$stagedAll = @(& git diff --cached --name-only)
if ($stagedAll.Count -eq 0) {
    Write-Output "SKIP: No staged changes to commit."
    exit 0
}

Write-Output "Running mandatory pre-commit privacy & allowlist scan (python -m src.privacy --check-staged)..."
& python -m src.privacy --check-staged
if ($LASTEXITCODE -ne 0) {
    Write-Error "ABORTED: Pre-commit privacy check failed. Commit and push cancelled."
    exit 2
}

if ($DryRun) {
    Write-Output ("DRY-RUN OK: Branch='" + $currentBranch + "', StagedFiles=" + $stagedAll.Count + ". No commit or push executed.")
    exit 0
}

if ([string]::IsNullOrWhiteSpace($CommitMessage)) {
    $CommitMessage = "chore: update wifiwriter safe code and documentation"
}

& git commit -m $CommitMessage
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($NoPush) {
    Write-Output ("OK: Committed safely on branch '" + $currentBranch + "' (-NoPush set).")
    exit 0
}

& git push -u origin $currentBranch
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Output ("OK: Safely committed and pushed branch '" + $currentBranch + "' to origin.")
