param(
    [string]$Nasm,
    [string]$VsRoot
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'toolchain.ps1')
$Nasm = Resolve-CityNasm -Nasm $Nasm
$VsRoot = Resolve-CityVisualStudio -VsRoot $VsRoot
$vcvars = Join-Path $VsRoot 'VC\Auxiliary\Build\vcvars32.bat'
if (-not (Get-Command node -CommandType Application -ErrorAction SilentlyContinue)) { throw 'Node.js is required. Install it and add node to PATH.' }
New-Item -ItemType Directory -Force -Path (Join-Path $root 'build'),(Join-Path $root 'dist') | Out-Null

& node (Join-Path $root 'tools\generate.mjs') constants
if ($LASTEXITCODE -ne 0) { throw 'Generating XTEA constants failed.' }
& $Nasm -f bin -I "$root\build\" -o "$root\build\blob.bin" -l "$root\build\blob.lst" "$root\src\blob.asm"
if ($LASTEXITCODE -ne 0) { throw 'Assembling the data blob failed.' }
& node (Join-Path $root 'tools\generate.mjs') embed
if ($LASTEXITCODE -ne 0) { throw 'Embedding the data blob failed.' }

cmd.exe /d /s /c "call `"$vcvars`" >nul && cl /nologo /c /TC /Od /GS- /Zl /utf-8 /W4 /WX /I`"$root\build`" `"$root\src\empty_city.c`" /Fo`"$root\build\empty_city.obj`" && link /nologo /subsystem:windows /entry:main /nodefaultlib /nxcompat:no /section:.data,RW /merge:.CRT=.rdata /debug:none /out:`"$root\dist\empty_city.exe`" /implib:`"$root\build\empty_city.lib`" `"$root\build\empty_city.obj`" kernel32.lib user32.lib"
if ($LASTEXITCODE -ne 0) { throw "Compile/link failed: $LASTEXITCODE" }
Write-Host "Built: $root\dist\empty_city.exe"
