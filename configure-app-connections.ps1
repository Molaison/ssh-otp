[CmdletBinding()]
param(
    [string]$Alias = "codex-totp-f102",
    [string]$TargetAlias = "debug",
    [string]$GatewayAlias = "X",
    [string]$SocksProxySha256 = "b4743701a1e83e4a01e881ee22db6cc37860f50f9ddc50c5a9c179665badcfce",
    [string]$AppAumid = "OpenAI.Codex_2p2nqsd0c76g0!App",
    [switch]$Apply,
    [switch]$OpenApp,
    [switch]$Connect
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
try {
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.ServicePointManager]::SecurityProtocol -bor
        [System.Net.SecurityProtocolType]::Tls12
}
catch {
}

$ConfigureSha256 = "485b46c8f69b02d22788477ccd40212fcfcaa9e9afaf2e8005a90b6880de60e6"
$RemoteBootstrapBase = "https://raw.githubusercontent.com/Molaison/ssh-otp/3172956af375ade337ed7190c2ad3b4c3b00d89a"
$RuntimeCommit = "a6930d6b84bc8cd1e2d6a437ee8d1c49869851da"
$RuntimeBase = "https://raw.githubusercontent.com/Molaison/ssh-otp/$RuntimeCommit"
$RuntimeFiles = @(
    @{
        Name = "ssh_totp.py"
        Sha256 = "8dbd25c2c300a6bd5f456c8c05b9d59703c39eae2939d3f422b40d35b8a2b5f5"
    },
    @{
        Name = "totp_askpass.py"
        Sha256 = "06a5d62729c0609b7387ca24e2ffa9abe2432ffab46c64ba781c126c41fc0b8f"
    },
    @{
        Name = "totp_askpass.cmd"
        Sha256 = "5b8f9a4adbcc182e04a0a3c527bacba37a2e1d03df3b1ec954d0cbdc8f9956cc"
    },
    @{
        Name = "find_python.cmd"
        Sha256 = "4a02fd76eb4bfb0eab0d8d172a1c433d849ea39d1d2e008d952bb2bb61ec92b5"
    }
)

function Assert-Alias {
    param([string]$Value, [string]$Label)

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch '^[A-Za-z0-9_.-]+$') {
        throw "$Label contains unsupported characters"
    }
}

function Assert-Sha256Text {
    param([string]$Value, [string]$Label)

    if ($Value -notmatch '^[0-9a-fA-F]{64}$') {
        throw "$Label must be a 64-character SHA-256 hex digest"
    }
}

function Assert-FileSha256 {
    param([string]$Path, [string]$Expected, [string]$Label)

    Assert-Sha256Text -Value $Expected -Label "$Label expected hash"
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label not found: $Path"
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) {
        throw "$Label SHA-256 mismatch: expected $($Expected.ToLowerInvariant()), got $actual"
    }
}

function Get-UserSid {
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Get-AclSidList {
    param([string]$Path)

    $result = @()
    foreach ($entry in (Get-Acl -LiteralPath $Path).Access) {
        try {
            $sid = $entry.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]
            ).Value
        }
        catch {
            $sid = $entry.IdentityReference.Value
        }
        $result += $sid
    }
    return $result
}

function Assert-AclOnlyUserSystemAdministrators {
    param([string]$Path, [string]$UserSid)

    $required = @($UserSid, "S-1-5-18", "S-1-5-32-544")
    $seen = Get-AclSidList -Path $Path
    foreach ($sid in $seen) {
        if ($required -notcontains $sid) {
            throw "ACL contains an unexpected principal for $Path"
        }
    }
    foreach ($sid in $required) {
        if ($seen -notcontains $sid) {
            throw "ACL is missing a required principal for $Path"
        }
    }
}

function Protect-CacheDirectory {
    param([string]$Path, [string]$UserSid)

    $icacls = (Get-Command icacls.exe -CommandType Application -ErrorAction Stop |
        Select-Object -First 1).Source

    & $icacls $Path /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "failed to remove inherited ACL from bootstrap cache"
    }
    foreach ($sid in @($UserSid, "S-1-5-18", "S-1-5-32-544")) {
        & $icacls $Path /grant:r "*$sid`:(OI)(CI)F" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "failed to restrict bootstrap cache ACL"
        }
    }
    Assert-AclOnlyUserSystemAdministrators -Path $Path -UserSid $UserSid
}

function Invoke-Download {
    param([string]$Uri, [string]$Destination)

    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination `
        -Headers @{ "User-Agent" = "ChatGPT-App-Connections-Bootstrap" }
}

function Ensure-CachedFile {
    param(
        [string]$Uri,
        [string]$Destination,
        [string]$Expected,
        [string]$Label
    )

    if (Test-Path -LiteralPath $Destination -PathType Leaf) {
        $actual = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -eq $Expected.ToLowerInvariant()) {
            return
        }
        Remove-Item -LiteralPath $Destination -Force
    }
    Invoke-Download -Uri $Uri -Destination $Destination
}

function Write-BytesIfChanged {
    param([string]$Path, [byte[]]$Bytes)

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $existing = [System.IO.File]::ReadAllBytes($Path)
        if ($existing.Length -eq $Bytes.Length) {
            $same = $true
            for ($index = 0; $index -lt $Bytes.Length; $index++) {
                if ($existing[$index] -ne $Bytes[$index]) {
                    $same = $false
                    break
                }
            }
            if ($same) {
                return
            }
        }
    }

    $directory = Split-Path -Parent $Path
    $temp = Join-Path $directory (
        "." + (Split-Path -Leaf $Path) + "." + [guid]::NewGuid().ToString("N") + ".tmp"
    )
    try {
        [System.IO.File]::WriteAllBytes($temp, $Bytes)
        if (Test-Path -LiteralPath $Path) {
            Move-Item -LiteralPath $temp -Destination $Path -Force
        }
        else {
            [System.IO.File]::Move($temp, $Path)
        }
    }
    finally {
        if (Test-Path -LiteralPath $temp) {
            Remove-Item -LiteralPath $temp -Force
        }
    }
}

function Resolve-Python {
    $launcher = Get-Command py.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $launcher) {
        try {
            $candidate = (& $launcher.Source -3 -c "import sys; print(sys.executable)" 2>$null |
                Select-Object -Last 1)
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($candidate)) {
                $candidate = [System.IO.Path]::GetFullPath($candidate.Trim())
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    return $candidate
                }
            }
        }
        catch {
        }
    }

    $candidates = @()
    foreach ($name in @("python.exe", "python3.exe")) {
        $candidates += @(Get-Command $name -CommandType Application -All `
            -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    }
    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if ($candidate -like "*\WindowsApps\*") {
            continue
        }
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            continue
        }
        try {
            $reported = (& $candidate -c "import sys; print(sys.executable)" 2>$null |
                Select-Object -Last 1)
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($reported)) {
                continue
            }
            $reported = [System.IO.Path]::GetFullPath($reported.Trim())
            if (Test-Path -LiteralPath $reported -PathType Leaf) {
                return $reported
            }
        }
        catch {
        }
    }
    throw "a functional Python 3 executable was not found"
}

function Resolve-GitSsh {
    $candidates = @()

    foreach ($git in @(Get-Command git.exe -CommandType Application -All `
            -ErrorAction SilentlyContinue)) {
        try {
            $gitRoot = Split-Path -Parent (Split-Path -Parent $git.Source)
            $candidates += Join-Path $gitRoot "usr\bin\ssh.exe"
        }
        catch {
        }
    }
    foreach ($ssh in @(Get-Command ssh.exe -CommandType Application -All `
            -ErrorAction SilentlyContinue)) {
        if ($ssh.Source -notlike "*\Windows\System32\*") {
            $candidates += $ssh.Source
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $candidates += Join-Path $env:USERPROFILE "scoop\apps\git\current\usr\bin\ssh.exe"
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $candidates += Join-Path $env:LOCALAPPDATA "Programs\Git\usr\bin\ssh.exe"
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $candidates += Join-Path $env:ProgramFiles "Git\usr\bin\ssh.exe"
    }
    if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
        $candidates += Join-Path ${env:ProgramFiles(x86)} "Git\usr\bin\ssh.exe"
    }
    $candidates += "D:\Git\usr\bin\ssh.exe"

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw "Git/MSYS ssh.exe was not found; refusing to use System32 ssh for SOCKS master"
}

function Get-FreeLoopbackPort {
    $listener = New-Object System.Net.Sockets.TcpListener(
        [System.Net.IPAddress]::Loopback,
        0
    )
    try {
        $listener.Start()
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Plan-MasterState {
    param([string]$ProfileDir, [string]$Alias, [string]$GatewayAlias)

    $statePath = Join-Path $ProfileDir "master_state.json"
    $existing = $null
    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        try {
            $existing = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        }
        catch {
            throw "existing master_state.json is not valid JSON"
        }
    }

    $effectiveGateway = $GatewayAlias
    $socks = ""
    $controlPath = ""
    if ($null -ne $existing) {
        $existingGateway = [string]$existing.gateway_alias
        if (-not [string]::IsNullOrWhiteSpace($existingGateway)) {
            if (-not [string]::Equals(
                $existingGateway,
                $GatewayAlias,
                [System.StringComparison]::OrdinalIgnoreCase
            )) {
                throw "existing master_state.json gateway_alias does not match GatewayAlias"
            }
            $effectiveGateway = $existingGateway
        }
        $socks = ([string]$existing.socks).Trim()
        $controlPath = ([string]$existing.control_path).Trim()
    }

    if ([string]::IsNullOrWhiteSpace($socks)) {
        $socks = "127.0.0.1:" + (Get-FreeLoopbackPort)
    }
    elseif ($socks -notmatch '^(127\.0\.0\.1|localhost):([1-9][0-9]{0,4})$' -or
        [int]$Matches[2] -gt 65535) {
        throw "existing master_state.json socks is not an independent loopback port"
    }

    if ([string]::IsNullOrWhiteSpace($controlPath)) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Alias))
        }
        finally {
            $sha.Dispose()
        }
        $digestHex = ([System.BitConverter]::ToString($digest)).Replace("-", "").ToLowerInvariant()
        $profileHome = [Environment]::GetFolderPath("UserProfile")
        if ([string]::IsNullOrWhiteSpace($profileHome)) {
            $profileHome = $HOME
        }
        $controlPath = [System.IO.Path]::GetFullPath(
            (Join-Path $profileHome (".ssh\cm\app-" + $digestHex.Substring(0, 8) + "-%C"))
        )
    }
    elseif ($controlPath -match '[\r\n]') {
        throw "existing master_state.json control_path is invalid"
    }

    return [ordered]@{
        gateway_alias = $effectiveGateway
        socks = $socks
        control_path = $controlPath
    }
}

function Add-AppActivationType {
    if ("ChatGPTAppConnections.AppActivator" -as [type]) {
        return
    }
    $source = @'
using System;
using System.Runtime.InteropServices;

namespace ChatGPTAppConnections
{
    public enum ActivateOptions
    {
        None = 0,
        NoErrorUI = 1,
        NoSplashScreen = 2
    }

    [ComImport]
    [Guid("2e941141-7f97-4756-ba1d-9decde894a3d")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IApplicationActivationManager
    {
        [PreserveSig]
        int ActivateApplication(
            [MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
            [MarshalAs(UnmanagedType.LPWStr)] string arguments,
            ActivateOptions options,
            out uint processId);

        [PreserveSig]
        int ActivateForFile(
            [MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
            IntPtr itemArray,
            [MarshalAs(UnmanagedType.LPWStr)] string verb,
            out uint processId);

        [PreserveSig]
        int ActivateForProtocol(
            [MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
            IntPtr itemArray,
            out uint processId);
    }

    [ComImport]
    [Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C")]
    public class ApplicationActivationManager
    {
    }

    public static class AppActivator
    {
        public static uint Activate(string appUserModelId, string arguments)
        {
            IApplicationActivationManager manager =
                (IApplicationActivationManager)new ApplicationActivationManager();
            uint processId;
            int hr = manager.ActivateApplication(
                appUserModelId,
                arguments,
                ActivateOptions.None,
                out processId);
            Marshal.ThrowExceptionForHR(hr);
            return processId;
        }
    }
}
'@
    Add-Type -TypeDefinition $source
}

function Open-AppUri {
    param([string]$Aumid, [string]$Uri)

    Add-AppActivationType
    $appPid = [uint32][ChatGPTAppConnections.AppActivator]::Activate($Aumid, $Uri)
    if ($appPid -eq 0) {
        throw "AppX activation did not return a process id"
    }
    return [int]$appPid
}

function Open-AppSettings {
    param([string]$Aumid)

    return (Open-AppUri -Aumid $Aumid -Uri "codex://settings/connections/ssh")
}

function Open-AppAddAlias {
    param([string]$Aumid, [string]$Alias)

    $link = "codex://settings/connections/ssh/add?name=" +
        [System.Uri]::EscapeDataString($Alias)
    return (Open-AppUri -Aumid $Aumid -Uri $link)
}

function Get-AppMainPid {
    param(
        [string]$Aumid,
        [int]$ActivationPid = 0,
        [int]$TimeoutSeconds = 15
    )

    $separator = $Aumid.IndexOf("!")
    if ($separator -lt 1) {
        throw "AppAumid does not contain a package family name"
    }
    $familyName = $Aumid.Substring(0, $separator)
    $packageName = ($familyName -split "_")[0]
    $installRoot = ""
    try {
        $package = Get-AppxPackage -Name $packageName -ErrorAction SilentlyContinue |
            Where-Object {
                [string]::Equals(
                    [string]$_.PackageFamilyName,
                    $familyName,
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            } |
            Select-Object -First 1
        if ($null -ne $package -and
            -not [string]::IsNullOrWhiteSpace([string]$package.InstallLocation)) {
            $installRoot = [System.IO.Path]::GetFullPath(
                [string]$package.InstallLocation
            ).TrimEnd("\") + "\"
        }
    }
    catch {
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    if (-not [string]::IsNullOrWhiteSpace($installRoot)) {
        while ([DateTime]::UtcNow -lt $deadline) {
            foreach ($process in @(Get-Process -Name ChatGPT -ErrorAction SilentlyContinue)) {
                try {
                    $processPath = [string]$process.Path
                    if ([string]::IsNullOrWhiteSpace($processPath) -or
                        -not $processPath.StartsWith(
                            $installRoot,
                            [System.StringComparison]::OrdinalIgnoreCase
                        )) {
                        continue
                    }
                    if ($process.MainWindowHandle -ne 0) {
                        return [int]$process.Id
                    }
                }
                catch {
                    continue
                }
            }
            Start-Sleep -Milliseconds 300
        }
    }

    throw "no running ChatGPT process matched the installed package location"
}

function Find-AppElement {
    param(
        [int]$AppPid,
        [string]$Alias,
        [int]$TimeoutSeconds = 30
    )

    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes

    $pidCondition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ProcessIdProperty,
        $AppPid
    )
    $windowCondition = New-Object System.Windows.Automation.AndCondition(
        $pidCondition,
        (New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Window
        ))
    )
    $connectZh = ([string][char]0x8FDE) + ([string][char]0x63A5)
    $wantedNames = @("Connect $Alias", ($connectZh + " " + $Alias))
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)

    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $windows = [System.Windows.Automation.AutomationElement]::RootElement.FindAll(
                [System.Windows.Automation.TreeScope]::Children,
                $windowCondition
            )
            foreach ($window in $windows) {
                try {
                    $elements = $window.FindAll(
                        [System.Windows.Automation.TreeScope]::Descendants,
                        [System.Windows.Automation.Condition]::TrueCondition
                    )
                }
                catch {
                    continue
                }
                foreach ($element in $elements) {
                    try {
                        $name = ([string]$element.Current.Name).Trim()
                    }
                    catch {
                        continue
                    }
                    if (-not ($wantedNames | Where-Object {
                        [string]::Equals(
                            $name,
                            $_,
                            [System.StringComparison]::OrdinalIgnoreCase
                        )
                    })) {
                        continue
                    }
                    $patternObject = $null
                    try {
                        $supported = $element.TryGetCurrentPattern(
                            [System.Windows.Automation.TogglePattern]::Pattern,
                            [ref]$patternObject
                        )
                    }
                    catch {
                        $supported = $false
                    }
                    if ($supported -and $null -ne $patternObject) {
                        return New-Object psobject -Property @{
                            Element = $element
                            Toggle = [System.Windows.Automation.TogglePattern]$patternObject
                            Name = $name
                        }
                    }
                }
            }
        }
        catch {
            # The App may be rebuilding its UIA tree while changing pages.
        }
        Start-Sleep -Milliseconds 300
    }
    return $null
}

function Enable-AliasToggleIfOff {
    param($Found)

    $state = $found.Toggle.Current.ToggleState
    if ($state -eq [System.Windows.Automation.ToggleState]::On) {
        Write-Host "connect_toggle=already-on"
        return
    }
    if ($state -ne [System.Windows.Automation.ToggleState]::Off) {
        throw "Connect control has an indeterminate toggle state; refusing to change it"
    }

    $found.Toggle.Toggle()
    Start-Sleep -Milliseconds 800
    $stateAfter = $found.Toggle.Current.ToggleState
    if ($stateAfter -eq [System.Windows.Automation.ToggleState]::Off) {
        throw "Connect toggle remained off after one activation"
    }
    if ($stateAfter -eq [System.Windows.Automation.ToggleState]::On) {
        Write-Host "connect_toggle=on"
        return
    }
    throw "Connect toggle did not reach an unambiguous on state"
}

function Connect-ConfiguredAlias {
    param([int]$AppPid, [string]$Alias)

    $found = Find-AppElement -AppPid $AppPid -Alias $Alias -TimeoutSeconds 30
    if ($null -eq $found) {
        throw "Connect control for the configured alias was not found within 30 seconds"
    }
    Enable-AliasToggleIfOff -Found $found
}

Assert-Alias -Value $Alias -Label "Alias"
Assert-Alias -Value $TargetAlias -Label "TargetAlias"
Assert-Alias -Value $GatewayAlias -Label "GatewayAlias"
if (-not $Apply -and $OpenApp) {
    throw "-OpenApp requires -Apply"
}
if ($Connect -and -not ($Apply -and $OpenApp)) {
    throw "-Connect requires -Apply and -OpenApp"
}
if ($PSBoundParameters.Count -eq 0) {
    Write-Host "Usage: & ([scriptblock]::Create((irm <configure-app-connections.ps1 URL>))) -Apply -OpenApp -SocksProxySha256 <sha256>"
    return
}
Assert-Sha256Text -Value $SocksProxySha256 -Label "SocksProxySha256"

$localConfigure = ""
$localProxy = ""
if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $candidateConfigure = Join-Path $PSScriptRoot "configure_app_connections.py"
    $candidateProxy = Join-Path $PSScriptRoot "otp_socks_proxy.py"
    if ((Test-Path -LiteralPath $candidateConfigure -PathType Leaf) -and
        (Test-Path -LiteralPath $candidateProxy -PathType Leaf)) {
        $localConfigure = $candidateConfigure
        $localProxy = $candidateProxy
    }
}

$userSid = Get-UserSid
$cacheBase = Join-Path $env:LOCALAPPDATA "ssh-otp-app-connections\bootstrap"
New-Item -ItemType Directory -Path $cacheBase -Force | Out-Null
$cacheKey = $ConfigureSha256.Substring(0, 12) + "-" +
    $SocksProxySha256.Substring(0, 12) + "-" + $RuntimeCommit.Substring(0, 12)
$cacheDir = Join-Path $cacheBase ("payloads-" + $cacheKey)
New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
Protect-CacheDirectory -Path $cacheDir -UserSid $userSid

if (-not [string]::IsNullOrWhiteSpace($localConfigure)) {
    $configurePath = $localConfigure
    $proxySource = $localProxy
}
else {
    $configurePath = Join-Path $cacheDir "configure_app_connections.py"
    $proxySource = Join-Path $cacheDir "otp_socks_proxy.py"
    Ensure-CachedFile -Uri "$RemoteBootstrapBase/configure_app_connections.py" `
        -Destination $configurePath -Expected $ConfigureSha256 `
        -Label "configure_app_connections.py"
    Ensure-CachedFile -Uri "$RemoteBootstrapBase/otp_socks_proxy.py" `
        -Destination $proxySource -Expected $SocksProxySha256 `
        -Label "otp_socks_proxy.py"
}
Assert-FileSha256 -Path $configurePath -Expected $ConfigureSha256 `
    -Label "configure_app_connections.py"
Assert-FileSha256 -Path $proxySource -Expected $SocksProxySha256 `
    -Label "otp_socks_proxy.py"
if ([string]::IsNullOrWhiteSpace($localConfigure)) {
    Assert-AclOnlyUserSystemAdministrators -Path $configurePath -UserSid $userSid
    Assert-AclOnlyUserSystemAdministrators -Path $proxySource -UserSid $userSid
}

$python = Resolve-Python
$realSsh = Resolve-GitSsh

$runtimeCache = Join-Path $cacheDir "runtime"
New-Item -ItemType Directory -Path $runtimeCache -Force | Out-Null
foreach ($entry in $RuntimeFiles) {
    $destination = Join-Path $runtimeCache $entry.Name
    Ensure-CachedFile -Uri "$RuntimeBase/$($entry.Name)" `
        -Destination $destination -Expected $entry.Sha256 -Label $entry.Name
}
foreach ($entry in $RuntimeFiles) {
    $destination = Join-Path $runtimeCache $entry.Name
    Assert-FileSha256 -Path $destination -Expected $entry.Sha256 `
        -Label $entry.Name
    Assert-AclOnlyUserSystemAdministrators -Path $destination -UserSid $userSid
}

$normalizedDir = Join-Path $cacheDir "normalized"
$normalizedRuntime = Join-Path $normalizedDir "runtime"
New-Item -ItemType Directory -Path $normalizedRuntime -Force | Out-Null
$bundleFiles = @()
foreach ($entry in $RuntimeFiles) {
    $rawPath = Join-Path $runtimeCache $entry.Name
    $destination = Join-Path $normalizedRuntime $entry.Name
    $sourceBytes = [System.IO.File]::ReadAllBytes($rawPath)
    if ($entry.Name.EndsWith(".cmd", [System.StringComparison]::OrdinalIgnoreCase)) {
        $text = [System.Text.Encoding]::UTF8.GetString($sourceBytes)
        $text = $text.Replace("`r`n", "`n").Replace("`r", "`n").Replace("`n", "`r`n")
        $deployBytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    }
    else {
        $deployBytes = $sourceBytes
    }
    Write-BytesIfChanged -Path $destination -Bytes $deployBytes
    if (-not $entry.Name.EndsWith(".cmd", [System.StringComparison]::OrdinalIgnoreCase)) {
        Assert-FileSha256 -Path $destination -Expected $entry.Sha256 `
            -Label "normalized $($entry.Name)"
    }
    Assert-AclOnlyUserSystemAdministrators -Path $destination -UserSid $userSid
    $bundleFiles += [ordered]@{
        relative_path = "runtime/" + $entry.Name
        source = [System.IO.Path]::GetFullPath($destination)
        sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

$normalizedProxy = Join-Path $normalizedDir "otp_socks_proxy.py"
Write-BytesIfChanged -Path $normalizedProxy `
    -Bytes ([System.IO.File]::ReadAllBytes($proxySource))
Assert-FileSha256 -Path $normalizedProxy -Expected $SocksProxySha256 `
    -Label "normalized otp_socks_proxy.py"
Assert-AclOnlyUserSystemAdministrators -Path $normalizedProxy -UserSid $userSid
$bundleFiles += [ordered]@{
    relative_path = "otp_socks_proxy.py"
    source = [System.IO.Path]::GetFullPath($normalizedProxy)
    sha256 = (Get-FileHash -LiteralPath $normalizedProxy -Algorithm SHA256).Hash.ToLowerInvariant()
}

$localAppData = $env:LOCALAPPDATA
if ([string]::IsNullOrWhiteSpace($localAppData)) {
    $localAppData = Join-Path $HOME "AppData\Local"
}
$profileDir = Join-Path $localAppData "ssh-otp-app-connections\$Alias"
$state = Plan-MasterState -ProfileDir $profileDir `
    -Alias $Alias -GatewayAlias $GatewayAlias

$bundle = [ordered]@{
    files = @($bundleFiles)
    master_state = $state
}
$bundlePath = Join-Path $cacheDir "socks-bundle.json"
$bundleJson = ($bundle | ConvertTo-Json -Depth 8) + [Environment]::NewLine
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
Write-BytesIfChanged -Path $bundlePath -Bytes $utf8NoBom.GetBytes($bundleJson)
Assert-AclOnlyUserSystemAdministrators -Path $bundlePath -UserSid $userSid

$configureArgs = @(
    "--alias", $Alias,
    "--target-alias", $TargetAlias,
    "--gateway-alias", $GatewayAlias,
    "--wrapper-dir", $normalizedRuntime,
    "--profile-dir", $profileDir,
    "--proxy-mode", "socks",
    "--socks-bundle", $bundlePath,
    "--real-git-ssh", $realSsh
)
if ($Apply) {
    $configureArgs += "--apply"
}

$configureOutput = @(& $python $configurePath @configureArgs 2>&1)
$configureExit = $LASTEXITCODE
foreach ($line in $configureOutput) {
    Write-Host ([string]$line)
}
if ($configureExit -ne 0) {
    throw "configure_app_connections.py failed with exit $configureExit"
}
if (-not $Apply) {
    Write-Host "DRY_RUN"
    return
}

if (-not (Test-Path -LiteralPath $profileDir -PathType Container)) {
    throw "configuration reported success but the profile directory is absent"
}

Write-Host "alias=$Alias"
Write-Host "profile_dir=$profileDir"
Write-Host "socks=$($state.socks)"

if ($OpenApp) {
    $activationPid = Open-AppSettings -Aumid $AppAumid
    $appPid = Get-AppMainPid -Aumid $AppAumid -ActivationPid $activationPid
    Write-Host "activation_pid=$activationPid"
    Write-Host "app_pid=$appPid"
    $existingToggle = Find-AppElement -AppPid $appPid -Alias $Alias -TimeoutSeconds 30
    if ($null -eq $existingToggle) {
        $addActivationPid = Open-AppAddAlias -Aumid $AppAumid -Alias $Alias
        $appPid = Get-AppMainPid -Aumid $AppAumid -ActivationPid $addActivationPid
        Write-Host "alias_exists=false"
        if ($Connect) {
            Connect-ConfiguredAlias -AppPid $appPid -Alias $Alias
        }
    }
    else {
        Write-Host "alias_exists=true"
        if ($Connect) {
            Enable-AliasToggleIfOff -Found $existingToggle
        }
    }
}

Write-Host "CONFIGURED alias=$Alias profile_dir=$profileDir"
