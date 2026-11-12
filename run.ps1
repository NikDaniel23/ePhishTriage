# Start ePhishTriage with API keys from Infisical.
#
#   .\run.ps1                                  # dashboard
#   .\run.ps1 cli samples\01_obvious_phish.eml # command line, live intel
#
# If the Infisical CLI is installed and this folder is linked to a project
# (.infisical.yaml exists), the keys are fetched from Infisical and passed to
# the app as environment variables for this run only: they are never written
# to a file. Otherwise the app starts without keys (offline intel still works).
#
# Change -Environment to the Infisical environment holding your keys (dev, staging, prod).
param(
    [string]$Mode = "app",
    [string]$File = "",
    [string]$Environment = "dev"
)

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Error "No .venv found. Run: python -m venv .venv; .venv\Scripts\python -m pip install -r requirements.txt"
    exit 1
}

if ($Mode -eq "cli") {
    if (-not $File) { Write-Error "Usage: .\run.ps1 cli <path to .eml or .msg>"; exit 1 }
    $command = @($python, (Join-Path $PSScriptRoot "cli.py"), $File, "--live")
} else {
    $command = @($python, "-m", "streamlit", "run", (Join-Path $PSScriptRoot "app.py"))
}

$haveCli = [bool](Get-Command infisical -ErrorAction SilentlyContinue)
$linked = Test-Path (Join-Path $PSScriptRoot ".infisical.yaml")

if ($haveCli -and $linked) {
    Write-Host "Fetching API keys from Infisical (env: $Environment)..."
    & infisical secrets-manager run --env=$Environment -- @command
} else {
    if (-not $haveCli) { Write-Warning "Infisical CLI not found: starting without API keys. See GUIDE.md." }
    elseif (-not $linked) { Write-Warning "Folder not linked to Infisical (run 'infisical init'): starting without API keys." }
    & $command[0] $command[1..($command.Length - 1)]
}
exit $LASTEXITCODE
