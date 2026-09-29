param(
    [string]$DockerDesktop = 'D:\Apps\Docker\Docker\Docker Desktop.exe'
)

# Host workaround only. Never resets Docker or removes containers/volumes.
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $DockerDesktop -PathType Leaf)) {
    throw 'Docker Desktop executable not found.'
}
if (Get-Process 'Docker Desktop', 'com.docker.backend' -ErrorAction SilentlyContinue) {
    Write-Output 'Docker Desktop is already running. No runtime files were changed. If startup failed, quit Docker Desktop before using this launcher.'
    exit 0
}

$localData = [Environment]::GetFolderPath('LocalApplicationData')
$stamp = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
foreach ($entry in @(
    @{ Directory = 'Docker\run'; Socket = 'dockerInference' },
    @{ Directory = 'docker-secrets-engine'; Socket = 'engine.sock' }
)) {
    $runtime = Join-Path $localData $entry.Directory
    $socket = Join-Path $runtime $entry.Socket
    $item = Get-Item -LiteralPath $socket -Force -ErrorAction SilentlyContinue
    if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        $directory = Get-Item -LiteralPath $runtime -Force
        if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Refusing to move a redirected runtime directory.'
        }
        Rename-Item -LiteralPath $directory.FullName -NewName ($directory.Name + '.stale-' + $stamp)
        Write-Output ('Preserved stale socket directory: ' + $directory.FullName)
    }
}
Start-Process -FilePath $DockerDesktop -WindowStyle Hidden
Write-Output 'Docker Desktop launch requested. Existing images, containers and volumes are preserved.'
