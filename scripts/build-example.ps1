param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('demo-x64', 'blob-x64', 'blob-x86', 'tls-probe-x86', 'veh-probe-x86')]
    [string]$Example,
    [string]$VsRoot
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'toolchain.ps1')
$VsRoot = Resolve-CityVisualStudio -VsRoot $VsRoot
$settings = @{
    'demo-x64' = @{Source='demo-x64\empty_city_demo.c';Name='empty_city_demo';Arch='64';Flags='/section:.data,RW /opt:noref /export:main';Warnings='/W4 /WX-'}
    'blob-x64' = @{Source='blob-x64\empty_city_blob_only.c';Name='empty_city_blob_only';Arch='64';Flags='/section:.data,ERW /export:main';Warnings='/W4 /WX-'}
    'blob-x86' = @{Source='blob-x86\empty_city_blob32.c';Name='empty_city_blob32';Arch='32';Flags='/section:.data,RW /merge:.CRT=.rdata';Warnings='/W4 /WX'}
    'tls-probe-x86' = @{Source='probes\tls_probe32.c';Name='tls_probe32';Arch='32';Flags='';Warnings='/W4 /WX'}
    'veh-probe-x86' = @{Source='probes\veh_probe32.c';Name='veh_probe32';Arch='32';Flags='/section:.blob,ERW';Warnings=''}
}
$selected = $settings[$Example]
$vcvars = Join-Path $VsRoot ('VC\Auxiliary\Build\vcvars' + $selected.Arch + '.bat')
$source = Join-Path $root ('examples\' + $selected.Source)
$output = Join-Path $root ('build\examples\' + $Example)
New-Item -ItemType Directory -Path $output -Force | Out-Null
$obj = Join-Path $output ($selected.Name + '.obj')
$exe = Join-Path $output ($selected.Name + '.exe')
$lib = Join-Path $output ($selected.Name + '.lib')
cmd.exe /d /s /c "call `"$vcvars`" >nul && cl /nologo /c /TC /Od /GS- /Zl /utf-8 $($selected.Warnings) `"$source`" /Fo`"$obj`" && link /nologo /subsystem:console /entry:main /nodefaultlib /nxcompat:no $($selected.Flags) /out:`"$exe`" /implib:`"$lib`" `"$obj`" kernel32.lib"
if ($LASTEXITCODE -ne 0) { throw "Example build failed: $LASTEXITCODE" }
Write-Host "Built: $exe"
