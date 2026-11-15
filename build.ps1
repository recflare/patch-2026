[CmdletBinding()]
param(
    [switch]$Package,
    [string]$ConfigurationFile,
    [string]$TachyonPublicKey
)
$ErrorActionPreference = 'Stop'
# Resolve script-relative defaults after parameter binding. Windows PowerShell
# invoked by build.cmd does not expose PSScriptRoot in this parameter initializer.
if (!$ConfigurationFile) { $ConfigurationFile = Join-Path $PSScriptRoot '2026patch.ini' }
function Assert-PublicKey([string]$Text) {
    # Packaging accepts only the two public RSA fields, never a server private key.
    # Validate before compiling/copying files so a rejected input cannot replace
    # the release INI. Runtime validation remains independent of this XML reader.
    [xml]$xml = $Text
    if ($xml.DocumentElement.Name -ne 'RSAKeyValue' -or $xml.DocumentElement.Attributes.Count -ne 0 -or
        !$xml.RSAKeyValue.Modulus -or !$xml.RSAKeyValue.Exponent -or $Text.Length -gt 4096 -or
        $xml.RSAKeyValue.ChildNodes.Count -ne 2) {
        throw 'Package requires a public RSA key containing only Modulus and Exponent.'
    }
    foreach ($field in $xml.RSAKeyValue.ChildNodes) {
        if ($field.Attributes.Count -ne 0 -or $field.ChildNodes.Count -ne 1 -or
            $field.FirstChild.NodeType -ne [System.Xml.XmlNodeType]::Text) {
            throw 'Public RSA fields must contain Base64 text only.'
        }
        $bytes = [Convert]::FromBase64String($field.InnerText)
        if (!$bytes.Length) { throw 'Public RSA fields must not be empty.' }
    }
    return $xml.DocumentElement.OuterXml
}
if ($Package) {
    $ConfigurationFile = (Resolve-Path -LiteralPath $ConfigurationFile).Path
    $ini = [IO.File]::ReadAllText($ConfigurationFile)
}
if ($Package -and $TachyonPublicKey) {
    $TachyonPublicKey = (Resolve-Path -LiteralPath $TachyonPublicKey).Path
    $keyText = [IO.File]::ReadAllText($TachyonPublicKey)
    $publicKeyXml = Assert-PublicKey $keyText
    if ($ini -notmatch '(?m)^VoiceKeyXml=.*$') { throw 'ConfigurationFile must contain VoiceKeyXml=.' }
    $ini = [regex]::Replace($ini, '(?m)^VoiceKeyXml=[^\r\n]*', "VoiceKeyXml=$publicKeyXml")
}
if ($Package) {
    foreach ($match in [regex]::Matches($ini, '(?m)^\s*VoiceKeyXml\s*=([^\r\n]*)')) {
        if ($match.Groups[1].Value.Trim()) { $null = Assert-PublicKey $match.Groups[1].Value.Trim() }
    }
    if ($ini -match '<(?:D|P|Q|DP|DQ|InverseQ)(?:\s|>)') { throw 'Never package private RSA key fields.' }
}
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$installation) { throw 'Visual Studio C++ x64 build tools are required.' }
# PreserveLoader's trampoline is assembly; locate this toolset's ml64 (same component as Cl).
$msvcToolset = @(Get-ChildItem (Join-Path $installation 'VC\Tools\MSVC') -Directory |
    Sort-Object Name -Descending | Select-Object -First 1)[0].FullName
$ml64 = Join-Path $msvcToolset 'bin\Hostx64\x64\ml64.exe'
if (!(Test-Path $ml64)) { throw 'Visual Studio C++ x64 build tools are required (ml64.exe not found).' }
$developerCommand = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
$output = Join-Path $PSScriptRoot 'x64\Release'
$build = Join-Path $PSScriptRoot 'x64\Build'
New-Item -ItemType Directory -Force -Path $output | Out-Null
New-Item -ItemType Directory -Force -Path $build | Out-Null
$recipe = Join-Path $build 'build-patch26.cmd'
# Explicit compiler inputs define the DLL source boundary. MinHook is
# compiled as C and left unformatted; first-party binaries use the same C++17
# runtime and warning settings. Intermediates stay separate from distributable files.
$commands = @"
@echo off
set "PATH=$([IO.Path]::GetDirectoryName($vswhere));%PATH%"
call "$developerCommand" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b 1
cl /nologo /O2 /c /TC ..\..\2026Patch\src\Utils\deps\minhook\src\hook.c ..\..\2026Patch\src\Utils\deps\minhook\src\buffer.c ..\..\2026Patch\src\Utils\deps\minhook\src\trampoline.c ..\..\2026Patch\src\Utils\deps\minhook\src\hde\hde64.c
if errorlevel 1 exit /b 1
cl /nologo /W4 /O2 /MT /EHsc /std:c++17 /LD ..\..\2026Patch\src\main.cpp ..\..\2026Patch\src\RR\Patching\Patches.cpp hook.obj buffer.obj trampoline.obj hde64.obj /link /OUT:2026patch.dll
if errorlevel 1 exit /b 1
cl /nologo /W4 /O2 /MT /EHsc /std:c++17 ..\..\Injector\injector.cpp /link /OUT:Injector.exe
if errorlevel 1 exit /b 1
"$ml64" /nologo /c ..\..\PreserveProxy\jjiEVn.asm /FojjiEVn.obj
if errorlevel 1 exit /b 1
cl /nologo /W4 /O2 /MT /EHsc /std:c++17 /LD ..\..\PreserveProxy\proxy.cpp jjiEVn.obj /link /DEF:"..\..\PreserveProxy\PreserveLoader.def" /OUT:PreserveLoader.dll
if errorlevel 1 exit /b 1
exit /b %errorlevel%
"@
[IO.File]::WriteAllText($recipe, $commands, [Text.Encoding]::ASCII)
Push-Location $build
try {
    & $env:ComSpec /d /c $recipe
    if ($LASTEXITCODE -ne 0) { throw "Native build failed: $LASTEXITCODE" }
} finally { Pop-Location }
foreach ($name in @('2026patch.dll', 'Injector.exe', 'PreserveLoader.dll')) {
    Copy-Item -LiteralPath (Join-Path $build $name) -Destination (Join-Path $output $name)
}
Write-Host "Built Injector.exe, 2026patch.dll and PreserveLoader.dll in $output"

if ($Package) {
    [IO.File]::WriteAllText((Join-Path $output '2026patch.ini'), $ini, [Text.Encoding]::ASCII)
    foreach ($name in @('RecRoomScreen.bat', 'RecRoomVR.bat', 'Install-PreserveLoader.bat', 'RecRoomPreserve.bat', 'Restore-RefereeProtector.bat')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $output $name)
    }
    # Do not archive the output directory: it can contain local test settings,
    # old artifacts or operator key files. Only these nine drop-in files ship.
    $files = @('2026patch.dll', 'Injector.exe', 'PreserveLoader.dll', '2026patch.ini',
        'RecRoomScreen.bat', 'RecRoomVR.bat', 'Install-PreserveLoader.bat',
        'RecRoomPreserve.bat', 'Restore-RefereeProtector.bat') |
        ForEach-Object { Join-Path $output $_ }
    $zip = Join-Path $output 'Patch26Dist.zip'
    Compress-Archive -LiteralPath $files -DestinationPath $zip -Force
    Write-Host "Drop-in package: $zip"
}
