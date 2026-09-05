$ErrorActionPreference = 'Stop'
$compilerPath = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compilerPath)) {
    $compilerPath = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
}
Push-Location -LiteralPath $PSScriptRoot
try {
    & $compilerPath /nologo /target:winexe /platform:x64 /optimize+ /utf8output '/win32manifest:app.manifest' '/out:..\程序断网工具-v2.exe' /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Core.dll /reference:Microsoft.CSharp.dll 'Program.cs' 'Firewall.cs' 'StrongFirewall.cs'
    if ($LASTEXITCODE -ne 0) { throw 'Compilation failed.' }
    Write-Host 'Build completed.'
} finally {
    Pop-Location
}
