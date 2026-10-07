param([string]$VsRoot)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot '..\..\scripts\build-example.ps1') -Example 'veh-probe-x86' -VsRoot $VsRoot
