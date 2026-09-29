param(
    [ValidateSet('Install', 'Doctor', 'Repair', 'Rollback')]
    [string]$Mode = 'Doctor',
    [string]$Wheel,
    [string]$Workspace,
    [string]$Python = 'python',
    [string]$Root = (Join-Path $env:USERPROFILE '.local\share\OpenAgentSecretBox')
)

# Trusted operator tool. No target contents or submitted values are read.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = [IO.Path]::GetFullPath($Root)
if ((Split-Path $Root -Leaf) -ne 'OpenAgentSecretBox') {
    throw 'Installation root must be a dedicated directory named OpenAgentSecretBox.'
}
if ((Test-Path -LiteralPath $Root) -and
    ((Get-Item -LiteralPath $Root).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Installation root must not be a redirected directory.'
}
$manifestPath = Join-Path $Root 'current.json'
if ($Mode -eq 'Install') {
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    # Backups may contain MCP env settings; remove explicit as well as inherited grants.
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Root -AclObject $acl
} elseif (-not (Test-Path -LiteralPath $Root -PathType Container)) {
    throw 'Installation directory missing. Run Install first.'
}
$lock = [IO.File]::Open((Join-Path $Root 'manage.lock'), 'OpenOrCreate', 'ReadWrite', 'None')

function Invoke-Checked([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE) { throw ('Command failed: ' + (Split-Path $Exe -Leaf)) }
}
function Test-Runtime($State) {
    if (-not (Test-Path -LiteralPath $State.python -PathType Leaf)) {
        throw 'Runtime missing. Install a reviewed wheel; Repair only repairs registration.'
    }
    Invoke-Checked $State.python @((Join-Path $Root 'probe_mcp.py'), $State.workspace)
}
function Get-Args($State) {
    return @('-I', '-m', 'openagent_secretbox.mcp_server', '--workspace', $State.workspace,
        '--only-target', '.env.local')
}
function Register-State($State) {
    # codex add updates this entry only; never replace the complete configuration.
    $configRoot = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE '.codex' }
    $configFile = Join-Path $configRoot 'config.toml'
    if (Test-Path -LiteralPath $configFile) {
        $backup = Join-Path $Root ('codex-config-' + [guid]::NewGuid().ToString('N') + '.toml')
        Copy-Item -LiteralPath $configFile -Destination $backup
    }
    Invoke-Checked 'codex' (@('mcp', 'add', 'openagent-secretbox', '--', $State.python) + (Get-Args $State))
}
function Test-Registration($State) {
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $raw = & codex mcp get openagent-secretbox --json 2>$null
    } finally { $ErrorActionPreference = $savedPreference }
    if ($LASTEXITCODE) { throw 'MCP registration missing. Run Repair.' }
    $registered = ($raw -join "`n") | ConvertFrom-Json
    if (-not $registered.enabled -or $registered.transport.type -ne 'stdio' -or
        $registered.transport.command -ne $State.python -or
        (ConvertTo-Json -Compress @($registered.transport.args)) -cne
        (ConvertTo-Json -Compress @(Get-Args $State))) {
        throw 'MCP registration differs from approved installation. Run Repair.'
    }
    if ($registered.enabled_tools -or $registered.disabled_tools) {
        throw 'MCP tools are filtered by host configuration. Review filters before use.'
    }
    Write-Output ('PASS: registered workspace = ' + $State.workspace + '; only target = .env.local')
}
function Save-State($State) {
    $temporary = Join-Path $Root 'current.pending.json'
    [IO.File]::WriteAllText($temporary, ($State | ConvertTo-Json -Depth 8),
        (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $manifestPath -Force
}
function Add-Shortcuts {
    $desktop = [Environment]::GetFolderPath('Desktop')
    $shell = New-Object -ComObject WScript.Shell
    foreach ($action in @('Doctor', 'Repair')) {
        $path = Join-Path $desktop ('SecretBox ' + $action + '.lnk')
        if (-not (Test-Path -LiteralPath $path)) {
            $link = $shell.CreateShortcut($path)
            $link.TargetPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $link.Arguments = '-NoProfile -NoExit -ExecutionPolicy Bypass -File "' +
                (Join-Path $Root 'Manage-SecretBox.ps1') + '" -Mode ' + $action + ' -Root "' + $Root + '"'
            $link.WorkingDirectory = $Root
            $link.Save()
        }
    }
}

try {
    $current = if (Test-Path -LiteralPath $manifestPath) {
        Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } else { $null }
    if ($Mode -eq 'Install') {
        if (-not $Wheel -or -not $Workspace) { throw 'Install requires -Wheel and -Workspace.' }
        $wheelPath = (Resolve-Path -LiteralPath $Wheel).Path
        if ([IO.Path]::GetExtension($wheelPath) -ne '.whl') { throw 'Use a reviewed wheel.' }
        $workspaceItem = Get-Item -LiteralPath $Workspace
        if (-not $workspaceItem.PSIsContainer -or
            ($workspaceItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Workspace must be an existing non-redirected directory.'
        }
        $release = Join-Path $Root ('releases\' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $release -Force | Out-Null
        $artifact = Join-Path $release (Split-Path $wheelPath -Leaf)
        Copy-Item -LiteralPath $wheelPath -Destination $artifact
        Invoke-Checked $Python @('-m', 'venv', (Join-Path $release 'venv'))
        $runtime = Join-Path $release 'venv\Scripts\python.exe'
        Invoke-Checked $runtime @('-m', 'pip', '--disable-pip-version-check', 'install', ($artifact + '[mcp]'))
        Invoke-Checked $runtime @('-m', 'pip', 'check')
        $freeze = & $runtime -m pip freeze
        if ($LASTEXITCODE) { throw 'Cannot record installed dependencies.' }
        [IO.File]::WriteAllLines((Join-Path $release 'requirements-installed.txt'), [string[]]$freeze)
        $candidate = [pscustomobject]@{
            python = $runtime; workspace = $workspaceItem.FullName
            wheel_sha256 = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash
            previous = if ($current) { [pscustomobject]@{
                python = $current.python; workspace = $current.workspace
                wheel_sha256 = $current.wheel_sha256; previous = $null
            } } else { $null }
        }
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'probe_mcp.py') -Destination (Join-Path $Root 'probe_mcp.py') -Force
        Test-Runtime $candidate
        try {
            Register-State $candidate
            Test-Registration $candidate
            Save-State $candidate
        } catch {
            if ($current) { Register-State $current }
            throw
        }
        # Stable management entrypoint outside the repository and development venv.
        $installedManager = Join-Path $Root 'Manage-SecretBox.ps1'
        if ($PSCommandPath -ne $installedManager) {
            Copy-Item -LiteralPath $PSCommandPath -Destination $installedManager -Force
        }
        Add-Shortcuts
        Write-Output 'PASS: independent installation activated; previous runtime retained.'
    } else {
        if (-not $current) { throw 'No installation manifest. Run Install first.' }
        if ($Mode -eq 'Rollback') {
            if (-not $current.previous) { throw 'No earlier managed installation available.' }
            $previous = $current.previous
            Test-Runtime $previous
            Register-State $previous
            Test-Registration $previous
            Save-State $previous
            Write-Output 'PASS: previous runtime restored; other MCP entries unchanged.'
        } else {
            Test-Runtime $current
            if ($Mode -eq 'Repair') { Register-State $current }
            Test-Registration $current
            Write-Output 'PASS: runtime and registration healthy. Existing chats may need a fresh connection.'
        }
    }
} finally { $lock.Dispose() }
