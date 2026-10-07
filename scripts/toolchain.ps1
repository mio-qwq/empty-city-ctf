# Shared discovery for the main challenge and the standalone examples.
function Resolve-CityVisualStudio {
    param([string]$VsRoot)
    if (-not $VsRoot -and $env:VSINSTALLDIR) { $VsRoot = $env:VSINSTALLDIR }
    if (-not $VsRoot) {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (Test-Path -LiteralPath $vswhere) {
            $VsRoot = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
            if ($LASTEXITCODE -ne 0) { throw 'Visual Studio discovery failed.' }
        }
    }
    if (-not $VsRoot) { throw 'MSVC not found. Install Visual Studio C++ desktop tools, or provide -VsRoot.' }
    $VsRoot = (Resolve-Path -LiteralPath $VsRoot).Path
    foreach ($batch in @('vcvars32.bat', 'vcvars64.bat')) {
        $environment = Join-Path $VsRoot ('VC\Auxiliary\Build\' + $batch)
        if (-not (Test-Path -LiteralPath $environment -PathType Leaf)) { throw "Missing MSVC environment: $environment" }
    }
    return $VsRoot
}

function Resolve-CityNasm {
    param([string]$Nasm)
    if (-not $Nasm) { $Nasm = 'nasm' }
    $application = Get-Command $Nasm -CommandType Application -ErrorAction SilentlyContinue
    if (-not $application) { throw 'NASM not found. Add nasm to PATH, or provide -Nasm with the path to nasm.exe.' }
    return $application.Source
}
