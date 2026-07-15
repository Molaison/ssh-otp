# install.ps1 -- set up ssh-otp on Windows (idempotent).
#
#   pwsh -File $HOME\.ssh\ssh_otp\install.ps1
#
# Does NOT edit VS Code settings.json (it contains // comments; auto-parsing
# would corrupt it) or ~/.ssh/config. It:
#   * creates ~/.ssh/cm (ControlMaster socket dir)
#   * adds a guarded block to your PowerShell $PROFILE: puts ssh_otp\bin on PATH,
#     defines `ssh` as an argument-preserving wrapper function, plus
#     otp-up/otp-status/otp-down
#   * configures git core.sshCommand automatically (unless -SkipGitConfig)
[CmdletBinding()]
param(
  [string]$HomeDir = $HOME,
  [string]$ProfilePath = $PROFILE,
  [switch]$SkipGitConfig
)

$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "ssh-otp install: $dir"

$pythonExe = $null
foreach ($name in @('py.exe', 'python3.exe', 'python.exe')) {
  $command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($command) {
    $pythonExe = $command.Source
    break
  }
}
if (-not $pythonExe) {
  throw 'Python 3 was not found. Install Python or set SSH_TOTP_PYTHON before running install.ps1.'
}
Write-Host "  python: $pythonExe"

# 1. socket dir
New-Item -ItemType Directory -Force -Path "$HomeDir\.ssh\cm" | Out-Null

# 2. PowerShell profile block (idempotent via marker)
$marker = '# >>> ssh-otp >>>'
$dirForProfile = $dir.Replace("'", "''")
$pythonForProfile = $pythonExe.Replace("'", "''")
$block = @"
$marker
`$env:SSH_TOTP_PYTHON = '$pythonForProfile'
`$env:PATH = '$dirForProfile\bin;' + `$env:PATH
Remove-Item Alias:ssh -ErrorAction SilentlyContinue
function global:ssh { & '$dirForProfile\sshotp.cmd' @args }
function otp-up     { param([string[]]`$Hosts=@('x')) `$socks = if (`$env:SSH_OTP_SOCKS) { `$env:SSH_OTP_SOCKS } else { '127.0.0.1:7070' }; foreach (`$h in `$Hosts) { & '$dirForProfile\sshotp.cmd' -MNf -D `$socks `$h; if (`$LASTEXITCODE -eq 0) { "otp: master up (`$h, SOCKS `$socks)" } } }
function otp-status { param([string]`$Host_='x') & '$dirForProfile\sshotp.cmd' -O check `$Host_ }
function otp-down   { param([string]`$Host_='x') & '$dirForProfile\sshotp.cmd' -O exit  `$Host_ }
# <<< ssh-otp <<<
"@

$profileDir = Split-Path -Parent $ProfilePath
if ($profileDir) { New-Item -ItemType Directory -Force -Path $profileDir | Out-Null }
if (-not (Test-Path $ProfilePath)) { New-Item -ItemType File -Force -Path $ProfilePath | Out-Null }
if (Select-String -Path $ProfilePath -SimpleMatch $marker -Quiet) {
  $content = Get-Content -Raw -Path $ProfilePath
  $pattern = "(?s)\r?\n?# >>> ssh-otp >>>.*?# <<< ssh-otp <<<"
  $updated = [regex]::Replace($content, $pattern, "`r`n$block", 1)
  Set-Content -Path $ProfilePath -Value $updated
  Write-Host "  profile: updated ssh-otp block in $ProfilePath"
} else {
  Add-Content -Path $ProfilePath -Value "`r`n$block"
  Write-Host "  profile: added ssh-otp block to $ProfilePath"
}

# 3. Git integration
if (-not $SkipGitConfig) {
  $git = Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($git) {
    $gitWrapper = ($dir -replace '\\', '/') + '/sshotp.cmd'
    $gitCommand = '"' + $gitWrapper.Replace('"', '\"') + '"'
    & $git.Source config --global core.sshCommand $gitCommand
    if ($LASTEXITCODE -ne 0) { throw 'git core.sshCommand configuration failed' }
    Write-Host "  git: core.sshCommand=$gitCommand"
  } else {
    Write-Host '  git: not installed; skipped core.sshCommand'
  }
}

Write-Host ""
Write-Host "Done. Next:"
Write-Host "  * Configure host-specific values without editing SSH config: $dir\configure.cmd --help"
Write-Host "  * Open a new PowerShell window, then use ssh normally (x starts automatically)"
Write-Host "  * Manual controls remain available: otp-up x / otp-status x / otp-down x"
Write-Host "  * VS Code settings.json (add):  `"remote.SSH.path`": `"$($dir -replace '\\','\\')\\sshotp.cmd`""
