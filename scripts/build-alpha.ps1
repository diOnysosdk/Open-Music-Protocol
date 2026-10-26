param([string]$Output = "dist/omp-v0.2-alpha-windows-x86_64")
$ErrorActionPreference = "Stop"
cargo build --release --locked -p omp-cli -p omp-player
New-Item -ItemType Directory -Force -Path $Output | Out-Null
Copy-Item target/release/omp.exe $Output/
Copy-Item target/release/omp-player.exe $Output/
Copy-Item README.md,LICENSE-MIT,LICENSE-APACHE $Output/ -ErrorAction SilentlyContinue
Copy-Item docs/SECURITY.md,docs/alpha-installation-v0.2.md,docs/w8-alpha-readiness-v0.2.md,docs/w8-release-readiness-v0.2.md,docs/w8-alpha-candidate-report-v0.2.md $Output/
New-Item -ItemType Directory -Force -Path "$Output/sbom" | Out-Null
Get-ChildItem crates -Filter *.cdx.json -Recurse | Copy-Item -Destination "$Output/sbom"
New-Item -ItemType Directory -Force -Path "$Output/samples" | Out-Null
Copy-Item omp-spec-v0.2-draft/fixtures/audio/* "$Output/samples/"
Copy-Item omp-spec-v0.2-draft/fixtures/LICENSE.md "$Output/samples/LICENSE.md"
@'
OMP v0.2 - Experimental Alpha / Not Production Ready

This internal, unsigned candidate is not approved for publication or production use.
Verify SHA256SUMS through an independently authenticated channel before execution.
See w8-alpha-candidate-report-v0.2.md for limitations and security requirements.
'@ | Set-Content "$Output/EXPERIMENTAL-ALPHA.txt"
Get-ChildItem $Output -File -Recurse | Where-Object Name -ne SHA256SUMS | Get-FileHash -Algorithm SHA256 | ForEach-Object { "$($_.Hash.ToLowerInvariant())  $($_.Path.Substring((Resolve-Path $Output).Path.Length + 1).Replace('\\','/'))" } | Sort-Object | Set-Content "$Output/SHA256SUMS"
