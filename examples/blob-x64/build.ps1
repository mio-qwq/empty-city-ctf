param([string]$VsRoot)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot '..\..\scripts\build-example.ps1') -Example 'blob-x64' -VsRoot $VsRoot
