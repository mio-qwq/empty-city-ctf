param([string]$VsRoot)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot '..\..\scripts\build-example.ps1') -Example 'demo-x64' -VsRoot $VsRoot
