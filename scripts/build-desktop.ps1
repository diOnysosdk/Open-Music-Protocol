param([string]$Output = "dist/omp-v0.2-desktop-windows-x86_64")
$ErrorActionPreference = "Stop"
if (Test-Path -LiteralPath $Output) { throw "Output already exists: $Output" }
python scripts/verify-frozen.py
cargo build --release --locked -p omp-desktop -p omp-cli -p omp-player
New-Item -ItemType Directory -Path $Output | Out-Null
New-Item -ItemType Directory -Path "$Output/sbom" | Out-Null
Copy-Item target/release/omp-desktop.exe,target/release/omp.exe,target/release/omp-player.exe $Output/
Copy-Item README.md,Cargo.lock,LICENSE-MIT,LICENSE-APACHE,THIRD-PARTY-NOTICES.md $Output/
Copy-Item docs/SECURITY.md,docs/developer-quickstart-v0.2.md,docs/reference-apis-v0.2.md,docs/w10-implementation-report-v0.2.md $Output/
Copy-Item scripts/verify-alpha.py,scripts/audit-desktop.py $Output/
python scripts/generate-desktop-sbom.py "$Output/sbom/omp-desktop.cdx.json"
@'
OMP v0.2 Desktop Reference Player - Internal / Not Production Ready
W8-11 remains OPEN/HIGH. External alpha and production release are NO-GO.
'@ | Out-File -Encoding ascii "$Output/EXPERIMENTAL-DESKTOP.txt"
Get-ChildItem $Output -File -Recurse | Where-Object Name -ne SHA256SUMS | Get-FileHash -Algorithm SHA256 | ForEach-Object { "$($_.Hash.ToLowerInvariant())  $($_.Path.Substring((Resolve-Path $Output).Path.Length + 1).Replace('\','/'))" } | Sort-Object | Out-File -Encoding ascii "$Output/SHA256SUMS"
python scripts/verify-alpha.py $Output
python scripts/audit-desktop.py $Output windows
