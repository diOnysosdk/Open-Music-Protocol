param(
    [Parameter(Mandatory = $true)][string]$HostName,
    [Parameter(Mandatory = $true)][string]$UserName,
    [string]$RemoteWorkspace = "omp-validation",
    [string]$IdentityFile,
    [ValidateRange(1, 65535)][int]$Port = 22,
    [switch]$ApproveSetup,
    [string]$ResultsDirectory = "validation/evidence/w8-11/collected"
)
$ErrorActionPreference = "Stop"
if ($HostName -notmatch '^[A-Za-z0-9._:-]+$' -or $UserName -notmatch '^[A-Za-z0-9._-]+$') {
    throw "HostName or UserName contains unsupported characters"
}
if ($RemoteWorkspace -notmatch '^[A-Za-z0-9._/-]+$' -or $RemoteWorkspace.StartsWith('/')) {
    throw "RemoteWorkspace must be a relative path containing only letters, digits, dot, underscore, slash, or hyphen"
}
$destination = "$UserName@$HostName"
$sshArgs = @("-p", "$Port", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes")
$scpArgs = @("-P", "$Port", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes")
if ($IdentityFile) {
    if (-not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) { throw "IdentityFile does not exist" }
    $key = (Resolve-Path -LiteralPath $IdentityFile).Path
    $sshArgs += @("-i", $key)
    $scpArgs += @("-i", $key)
}

ssh @sshArgs $destination "true"
if ($LASTEXITCODE -ne 0) { throw "SSH connectivity or host-key verification failed" }
if ($ApproveSetup) {
    scp @scpArgs scripts/pi400/setup.sh "${destination}:setup-omp-pi400.sh"
    if ($LASTEXITCODE -ne 0) { throw "Could not copy the setup script" }
    ssh @sshArgs $destination "sh setup-omp-pi400.sh"
    if ($LASTEXITCODE -ne 0) { throw "Pi prerequisite setup failed" }
}

$remote = "`$HOME/$RemoteWorkspace"
ssh @sshArgs $destination "test -d $remote/.git || git clone --filter=blob:none https://github.com/diOnysosdk/Open-Music-Protocol.git $remote"
if ($LASTEXITCODE -ne 0) { throw "Could not prepare the remote repository" }
$sha = git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw "Could not determine the local commit" }
$remoteEvidence = "validation/evidence/w8-11/$sha"
ssh @sshArgs $destination "cd $remote && git fetch origin main && git cat-file -e $sha^{commit} && git checkout --detach $sha && sh scripts/pi400/validate.sh $remoteEvidence"
$validationExit = $LASTEXITCODE
$localEvidence = Join-Path $ResultsDirectory $sha
New-Item -ItemType Directory -Force -Path $localEvidence | Out-Null
scp @scpArgs -r "${destination}:$RemoteWorkspace/$remoteEvidence/*" "$localEvidence/"
if ($LASTEXITCODE -ne 0) { throw "Validation evidence retrieval failed" }
if ($validationExit -ne 0) { throw "Pi validation returned exit code $validationExit; evidence was retrieved" }
Write-Host "Pi results copied to $ResultsDirectory"
