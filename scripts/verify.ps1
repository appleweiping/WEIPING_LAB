param(
    [switch]$SkipUi
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$VerificationFailure = $null
$ProjectPython = Join-Path $Root ".venv\Scripts\python.exe"
if ($env:WEIPING_LAB_VERIFY_PYTHON) {
    $Python = $env:WEIPING_LAB_VERIFY_PYTHON
} elseif (Test-Path -LiteralPath $ProjectPython) {
    $Python = $ProjectPython
} else {
    $Python = "python"
}

function Invoke-ExternalGate {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )

    & $Command
    if ($LASTEXITCODE -ne 0) {
        $gateExitCode = [int]$LASTEXITCODE
        $failure = [System.InvalidOperationException]::new(
            "$Name failed with exit code $gateExitCode"
        )
        $failure.Data["ExitCode"] = $gateExitCode
        throw $failure
    }
}

Push-Location $Root
try {
    Invoke-ExternalGate "Python dependency consistency" { & $Python -m pip check }
    Invoke-ExternalGate "Python dependency audit" { & $Python -m pip_audit }
    Invoke-ExternalGate "pytest" { & $Python -m pytest -q }
    Invoke-ExternalGate "ruff check" { & $Python scripts\run_ruff.py check lab cli api tests scripts }
    Invoke-ExternalGate "ruff format" { & $Python scripts\run_ruff.py format --check lab cli api tests scripts }
    Invoke-ExternalGate "release scan" { & $Python scripts\release_scan.py }

    if (-not $SkipUi) {
        Invoke-ExternalGate "UI lint" { npm --prefix ui run lint }
        Invoke-ExternalGate "UI build" { npm --prefix ui run build }
        Invoke-ExternalGate "UI audit" {
            npm --prefix ui audit --audit-level=low --registry=https://registry.npmjs.org
        }
    }
} catch {
    $VerificationFailure = $_
} finally {
    Pop-Location
}

if ($null -ne $VerificationFailure) {
    $gateExitCode = $VerificationFailure.Exception.Data["ExitCode"]
    if ($null -ne $gateExitCode) {
        [Console]::Error.WriteLine($VerificationFailure.Exception.Message)
        exit [int]$gateExitCode
    }
    throw $VerificationFailure
}
