param([string]$Output = "dist/omp-v0.2-alpha-windows-x86_64")
$ErrorActionPreference = "Stop"
cargo build --release --locked -p omp-cli -p omp-player
New-Item -ItemType Directory -Force -Path $Output | Out-Null
Copy-Item target/release/omp.exe $Output/
Copy-Item target/release/omp-player.exe $Output/
Copy-Item README.md,LICENSE-MIT,LICENSE-APACHE $Output/ -ErrorAction SilentlyContinue
Copy-Item docs/w8-alpha-readiness-v0.2.md,docs/w8-release-readiness-v0.2.md $Output/
Get-ChildItem $Output -File | Get-FileHash -Algorithm SHA256 | ForEach-Object { "$($_.Hash.ToLowerInvariant())  $($_.Path | Split-Path -Leaf)" } | Set-Content "$Output/SHA256SUMS"
