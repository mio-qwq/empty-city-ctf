$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'dist\empty_city.exe'
$answer = Get-Content -Raw -LiteralPath (Join-Path $root 'build\author\answer.json') | ConvertFrom-Json
$flag = [Text.Encoding]::ASCII.GetBytes($answer.flag)
$runRoot = Join-Path $root ('build\test-runs\' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null

# Test only windows belonging to the process launched by this test runner.
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class CityDialogTest {
    public delegate bool EnumProc(IntPtr hwnd, IntPtr arg);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc proc, IntPtr arg);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr parent, EnumProc proc, IntPtr arg);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int length);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr hwnd, StringBuilder text, int length);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool PostMessage(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);
    public static IntPtr Find(uint wantedPid) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((hwnd, arg) => {
            uint pid; GetWindowThreadProcessId(hwnd, out pid);
            if (pid == wantedPid) {
                var type = new StringBuilder(64); GetClassName(hwnd, type, type.Capacity);
                if (type.ToString() == "#32770") { found=hwnd; return false; }
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }
    public static string Text(IntPtr hwnd) {
        var text = new StringBuilder(8192); GetWindowText(hwnd, text, text.Capacity);
        return text.ToString();
    }
    public static string[] Children(IntPtr hwnd) {
        var lines = new List<string>();
        EnumChildWindows(hwnd, (child, arg) => { lines.Add(Text(child)); return true; }, IntPtr.Zero);
        return lines.ToArray();
    }
}
'@

$results = [Collections.Generic.List[object]]::new()
function Invoke-Case {
    param([string]$Name, [byte[]]$Content, [switch]$Missing, [switch]$Directory,
          [switch]$Locked, [switch]$Correct, [string]$Executable = $exe)
    $cwd = Join-Path $runRoot $Name
    New-Item -ItemType Directory -Path $cwd | Out-Null
    $file = Join-Path $cwd 'flag'
    $lock = $null
    if ($Directory) { New-Item -ItemType Directory -Path $file | Out-Null }
    elseif (-not $Missing) { [IO.File]::WriteAllBytes($file, $Content) }
    if ($Locked) { $lock = [IO.File]::Open($file, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
    $info = [Diagnostics.ProcessStartInfo]::new($Executable)
    $info.WorkingDirectory = $cwd
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $p = [Diagnostics.Process]::Start($info)
    $dialog = [IntPtr]::Zero
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while (-not $p.HasExited -and [DateTime]::UtcNow -lt $deadline) {
            $dialog = [CityDialogTest]::Find([uint32]$p.Id)
            if ($dialog -ne [IntPtr]::Zero) { break }
            Start-Sleep -Milliseconds 25
        }
        if ($Correct) {
            if ($dialog -eq [IntPtr]::Zero) { throw "$Name did not display the success dialog." }
            $title = [CityDialogTest]::Text($dialog)
            $children = [CityDialogTest]::Children($dialog)
            if ($title -cne $answer.title -or -not ($children -ccontains $answer.message)) {
                throw "$Name displayed unexpected message text: $title / $children"
            }
            [CityDialogTest]::PostMessage($dialog, 0x10, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
        } elseif ($dialog -ne [IntPtr]::Zero) { throw "$Name unexpectedly displayed a dialog." }
        if (-not $p.WaitForExit(5000)) {
            $remaining = [CityDialogTest]::Find([uint32]$p.Id)
            throw "$Name did not exit; remaining dialog handle=$remaining."
        }
        $out = $p.StandardOutput.ReadToEnd()
        $err = $p.StandardError.ReadToEnd()
        if ($p.ExitCode -ne 0 -or $out.Length -ne 0 -or $err.Length -ne 0) {
            throw "$Name failed silent/zero-exit check: $($p.ExitCode) / $out / $err"
        }
        if (-not $Missing -and -not $Directory -and -not $Locked) {
            $after = [IO.File]::ReadAllBytes($file)
            if ([Convert]::ToBase64String($after) -ne [Convert]::ToBase64String($Content)) { throw "$Name modified the input file." }
        }
        $results.Add([PSCustomObject]@{Case=$Name;Passed=$true;MessageBox=[bool]$Correct;ExitCode=$p.ExitCode})
        Write-Host "PASS $Name"
    } finally {
        if (-not $p.HasExited) { $p.Kill(); $p.WaitForExit() }
        $p.Dispose()
        if ($lock) { $lock.Dispose() }
    }
}

Invoke-Case -Name missing -Missing
Invoke-Case -Name empty -Content ([byte[]]::new(0))
Invoke-Case -Name wrong-short -Content ([Text.Encoding]::ASCII.GetBytes('PKWCTF{wrong}'))
Invoke-Case -Name directory -Directory
Invoke-Case -Name unreadable-locked -Content $flag -Locked
Invoke-Case -Name newline-lf -Content ([byte[]]($flag + [byte[]]@(10)))
Invoke-Case -Name newline-crlf -Content ([byte[]]($flag + [byte[]]@(13,10)))
Invoke-Case -Name utf8-bom -Content ([byte[]]([byte[]]@(239,187,191) + $flag))
Invoke-Case -Name trailing-null -Content ([byte[]]($flag + [byte[]]@(0)))
Invoke-Case -Name oversized -Content ([byte[]]::new(1024))
for ($i=0; $i -lt $flag.Length; $i+=8) {
    $bad = [byte[]]$flag.Clone()
    $bad[$i] = $bad[$i] -bxor 1
    Invoke-Case -Name "wrong-block-$([int]($i/8))" -Content $bad
}

# A real valid flag next to the executable must not override another CWD.
$elsewhere = Join-Path $runRoot 'exe-folder'
New-Item -ItemType Directory -Path $elsewhere | Out-Null
Copy-Item -LiteralPath $exe -Destination (Join-Path $elsewhere 'empty_city.exe')
[IO.File]::WriteAllBytes((Join-Path $elsewhere 'flag'), $flag)
Invoke-Case -Name working-directory -Missing -Executable (Join-Path $elsewhere 'empty_city.exe')
Invoke-Case -Name correct -Content $flag -Correct

$report = [PSCustomObject]@{Executable=$exe;RunDirectory=$runRoot;Tests=$results}
New-Item -ItemType Directory -Path (Join-Path $root 'build\reports') -Force | Out-Null
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root 'build\reports\verification.json') -Encoding utf8
Write-Host "$($results.Count) integration checks passed."
