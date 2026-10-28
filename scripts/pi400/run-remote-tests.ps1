param(
    [Parameter(Mandatory = $true)][string]$HostName,
    [Parameter(Mandatory = $true)][string]$UserName,
    [string]$RemoteWorkspace = "omp-validation",
    [string]$IdentityFile,
    [switch]$ApproveSetup,
    [string]$ResultsDirectory = "artifacts/pi400"
)
$ErrorActionPreference = "Stop"
if ($HostName -notmatch '^[A-Za-z0-9._:-]+$' -or $UserName -notmatch '^[A-Za-z0-9._-]+$') {
    throw "HostName or UserName contains unsupported characters"
}
if ($RemoteWorkspace -notmatch '^[A-Za-z0-9._/-]+$' -or $RemoteWorkspace.StartsWith('/')) {
    throw "RemoteWorkspace must be a relative path containing only letters, digits, dot, underscore, slash, or hyphen"
}
$destination = "$UserName@$HostName"
$sshArgs = @("-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes")
if ($IdentityFile) {
    if (-not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) { throw "IdentityFile does not exist" }
    $sshArgs += @("-i", (Resolve-Path -LiteralPath $IdentityFile).Path)
}

ssh @sshArgs $destination "true"
if ($ApproveSetup) {
    scp @sshArgs scripts/pi400/setup.sh "${destination}:setup-omp-pi400.sh"
    ssh @sshArgs $destination "sh setup-omp-pi400.sh"
}

$remote = "`$HOME/$RemoteWorkspace"
ssh @sshArgs $destination "test -d $remote/.git || git clone --filter=blob:none https://github.com/diOnysosdk/Open-Music-Protocol.git $remote"
ssh @sshArgs $destination "cd $remote && git fetch origin main && git checkout --detach $(git rev-parse HEAD) && sh scripts/pi400/validate.sh"
New-Item -ItemType Directory -Force -Path $ResultsDirectory | Out-Null
scp @sshArgs -r "${destination}:$RemoteWorkspace/target/pi400-validation/*" "$ResultsDirectory/"
Write-Host "Pi results copied to $ResultsDirectory"
