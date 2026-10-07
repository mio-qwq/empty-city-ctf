$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'
$files = @('empty_city.exe', 'source.c')
foreach ($name in $files) {
    if (-not (Test-Path -LiteralPath (Join-Path $dist $name) -PathType Leaf)) { throw "Missing release input: $name. Build the challenge first." }
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$temporary = Join-Path $dist ('players-' + [Guid]::NewGuid().ToString('N') + '.zip')
$archive = [IO.Compression.ZipFile]::Open($temporary, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($name in $files) {
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, (Join-Path $dist $name), $name, [IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
} finally { $archive.Dispose() }
$archive = [IO.Compression.ZipFile]::OpenRead($temporary)
try {
    $names = @($archive.Entries | ForEach-Object { $_.FullName } | Sort-Object)
    if (($names -join '|') -cne (($files | Sort-Object) -join '|')) { throw 'Unexpected player archive contents.' }
} finally { $archive.Dispose() }
$destination = Join-Path $dist 'empty_city_players.zip'
Move-Item -LiteralPath $temporary -Destination $destination -Force
$hashes = foreach ($name in @('empty_city.exe', 'source.c', 'empty_city_players.zip')) {
    $hash = (Get-FileHash -LiteralPath (Join-Path $dist $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $name"
}
[IO.File]::WriteAllLines((Join-Path $dist 'SHA256SUMS.txt'), $hashes, [Text.UTF8Encoding]::new($false))
Write-Host "Packaged: $destination (empty_city.exe + source.c only)"
