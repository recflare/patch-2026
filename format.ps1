[CmdletBinding()]
param([switch]$Check)
$ErrorActionPreference = 'Stop'

$command = Get-Command clang-format -ErrorAction SilentlyContinue
$formatter = if ($command) { $command.Source } else { $null }
if (!$formatter) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $installations = & $vswhere -all -products '*' -property installationPath
        foreach ($installation in $installations) {
            $candidate = Join-Path $installation 'VC\Tools\Llvm\bin\clang-format.exe'
            if (Test-Path -LiteralPath $candidate) {
                $formatter = $candidate
                break
            }
        }
    }
}
if (!$formatter) {
    throw 'clang-format is required. Install the Visual Studio C++ Clang tools or add clang-format to PATH.'
}

$roots = @('2026Patch\src', 'PreserveProxy') |
    ForEach-Object { Join-Path $PSScriptRoot $_ }
# Vendored dependencies retain
# upstream formatting/license text. Include the separator to exclude descendants
# without accidentally excluding a first-party directory with a similar prefix.
$dependencyRoot = (Join-Path $PSScriptRoot '2026Patch\src\Utils\deps') + [IO.Path]::DirectorySeparatorChar
$sources = Get-ChildItem -LiteralPath $roots -Recurse -File |
    Where-Object {
        $_.Extension -in '.cpp', '.h' -and
        !$_.FullName.StartsWith($dependencyRoot, [StringComparison]::OrdinalIgnoreCase)
    } |
    Sort-Object FullName |
    ForEach-Object FullName

if ($Check) {
    & $formatter --dry-run --Werror $sources
} else {
    & $formatter -i $sources
}
if ($LASTEXITCODE -ne 0) {
    throw 'C++ formatting check failed. Run ./format.ps1 and review the changes.'
}
