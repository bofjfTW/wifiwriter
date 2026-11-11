[CmdletBinding()]
param(
    [Alias("Message")]
    [string]$CommitMessage = "",
    [string[]]$Paths = @(),
    [switch]$StageSafeProjectFiles,
    [switch]$AllowProtectedBranch,
    [switch]$NoPush,
    [switch]$DryRun,
    [switch]$SkipTests,
    [string]$TestCommand = "",
    [string]$RepoRoot = "",
    [string]$ExpectedRemotePattern = "github\.com[:/]bofjfTW/wifiwriter",
    [switch]$AllowCustomRemote
)

$ErrorActionPreference = "Continue"  # native git stderr must not become terminating errors; every step checks $LASTEXITCODE
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$CodeRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $ProjectRoot = $CodeRoot
} else {
    $ProjectRoot = (Resolve-Path $RepoRoot).Path
}
Set-Location $ProjectRoot
$env:PYTHONPATH = $CodeRoot

$currentBranch = (& git rev-parse --abbrev-ref HEAD 2>$null).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($currentBranch) -or $currentBranch -eq "HEAD") {
    Write-Error "ABORTED: Unable to determine current Git branch (or in detached HEAD state)."
    exit 1
}

if (($currentBranch -in @("main", "master")) -and (-not $AllowProtectedBranch)) {
    Write-Error ("ABORTED: Direct sync to protected branch '" + $currentBranch + "' is disabled in v0.2+. Switch to a feature/fix branch (e.g., fix/fubon-campus-diagnostics-v04) and open a Pull Request.")
    exit 3
}

if (-not $NoPush) {
    $remoteUrl = (& git remote get-url origin 2>$null)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($remoteUrl)) {
        Write-Error "ABORTED: Git remote 'origin' is not configured."
        exit 4
    }
    $remoteUrl = $remoteUrl.Trim()
    if ((-not $AllowCustomRemote) -and ($remoteUrl -notmatch $ExpectedRemotePattern)) {
        Write-Error ("ABORTED: Git remote 'origin' URL '" + $remoteUrl + "' does not match expected pattern '" + $ExpectedRemotePattern + "'.")
        exit 4
    }
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
    ".github",
    ".agents/skills/github-safe-sync"
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
        $workingChanges = @(& git status --porcelain)
        if ($workingChanges.Count -eq 0) {
            Write-Output "SKIP: Working tree clean and no staged changes to commit."
            exit 0
        }
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
Push-Location $CodeRoot
& python -m src.privacy --check-staged --repo-root "$ProjectRoot"
$privacyExit = $LASTEXITCODE
Pop-Location
if ($privacyExit -ne 0) { $global:LASTEXITCODE = $privacyExit }
if ($LASTEXITCODE -ne 0) {
    Write-Error "ABORTED: Pre-commit privacy check failed. Commit and push cancelled."
    exit 2
}

if (-not $SkipTests) {
    Write-Output "Running automated test suite before commit..."
    if (-not [string]::IsNullOrWhiteSpace($TestCommand)) {
        Invoke-Expression $TestCommand
    } else {
        & python -m unittest discover -s tests
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Error "ABORTED: Automated tests failed. Commit and push cancelled."
        exit 5
    }
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

$localHeadSha = (& git rev-parse HEAD).Trim()

if ($NoPush) {
    Write-Output ("OK: Committed safely on branch '" + $currentBranch + "' (Commit=" + $localHeadSha + ", -NoPush set).")
    exit 0
}

# Check remote divergence before pushing (never use --force)
& git fetch origin $currentBranch 2>$null
if ($LASTEXITCODE -eq 0) {
    & git rev-parse --verify ("origin/" + $currentBranch) *> $null
    if ($LASTEXITCODE -eq 0) {
        & git merge-base --is-ancestor ("origin/" + $currentBranch) HEAD
        if ($LASTEXITCODE -ne 0) {
            Write-Error ("ABORTED: Remote branch 'origin/" + $currentBranch + "' has diverged (non-fast-forward conflict). Force push is strictly prohibited.")
            exit 6
        }
    }
}

& git push -u origin $currentBranch
if ($LASTEXITCODE -ne 0) {
    Write-Error ("ABORTED: Failed to push branch '" + $currentBranch + "' to origin (check authentication, permissions, or remote status).")
    exit 7
}

$remoteRefLine = (& git ls-remote --heads origin $currentBranch 2>$null)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($remoteRefLine)) {
    Write-Error ("ABORTED: Unable to verify remote branch '" + $currentBranch + "' via git ls-remote after push.")
    exit 8
}
$remoteSha = ($remoteRefLine -split "\s+")[0].Trim()
if ($remoteSha -ne $localHeadSha) {
    Write-Error ("ABORTED: Remote SHA (" + $remoteSha + ") does not match local HEAD SHA (" + $localHeadSha + ").")
    exit 8
}

Write-Output ("OK: Safely committed and pushed branch '" + $currentBranch + "' to origin (Commit=" + $localHeadSha + ").")
