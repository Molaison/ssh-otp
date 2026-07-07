# install.ps1 -- set up ssh-otp on Windows (idempotent).
#
#   pwsh -File $HOME\.ssh\ssh_otp\install.ps1
#
# Does NOT edit VS Code settings.json (it contains // comments; auto-parsing
# would corrupt it) or ~/.ssh/config. It:
#   * creates ~/.ssh/cm (ControlMaster socket dir)
#   * adds a guarded block to your PowerShell $PROFILE: puts ssh_otp\bin on PATH,
#     aliases `ssh` to the wrapper, and defines otp-up/otp-status/otp-down
#   * prints the VS Code / git one-liners to apply by hand
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "ssh-otp install: $dir"

# 1. socket dir
New-Item -ItemType Directory -Force -Path "$HOME\.ssh\cm" | Out-Null

# 2. PowerShell profile block (idempotent via marker)
$marker = '# >>> ssh-otp >>>'
$block = @"
$marker
`$env:PATH = "$dir\bin;" + `$env:PATH
Set-Alias -Name ssh -Value "$dir\sshotp.cmd" -Scope Global -Option AllScope
function otp-up     { param([string[]]`$Hosts=@('X')) `$socks = if (`$env:SSH_OTP_SOCKS) { `$env:SSH_OTP_SOCKS } else { '127.0.0.1:7070' }; foreach (`$h in `$Hosts) { & "$dir\sshotp.cmd" -MNf -D `$socks `$h; if (`$LASTEXITCODE -eq 0) { "otp: master up (`$h, SOCKS `$socks)" } } }
function otp-status { param([string]`$Host_='X') & "$dir\sshotp.cmd" -O check `$Host_ }
function otp-down   { param([string]`$Host_='X') & "$dir\sshotp.cmd" -O exit  `$Host_ }
# <<< ssh-otp <<<
"@

if (-not (Test-Path $PROFILE)) { New-Item -ItemType File -Force -Path $PROFILE | Out-Null }
if (Select-String -Path $PROFILE -SimpleMatch $marker -Quiet) {
  Write-Host "  profile: already wired ($PROFILE)"
} else {
  Add-Content -Path $PROFILE -Value "`r`n$block"
  Write-Host "  profile: added ssh-otp block to $PROFILE"
}

Write-Host ""
Write-Host "Done. Next:"
Write-Host "  * New PowerShell window, then:  otp-up X ; ssh f101 true"
Write-Host "  * VS Code settings.json (add):  `"remote.SSH.path`": `"$($dir -replace '\\','\\')\\sshotp.cmd`""
Write-Host "  * git:  git config --global core.sshCommand `"$($dir -replace '\\','/')/sshotp.cmd`""
