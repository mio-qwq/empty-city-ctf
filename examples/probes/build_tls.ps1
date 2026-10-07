param([string]$VsRoot)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot '..\..\scripts\build-example.ps1') -Example 'tls-probe-x86' -VsRoot $VsRoot
