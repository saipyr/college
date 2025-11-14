param(
  [Parameter(Mandatory=$true)][string]$ServerUrl,
  [Parameter(Mandatory=$true)][string]$Token,
  [string]$PythonPath = "C:\Python311\python.exe",
  [switch]$CreateScheduledTask
)

$ErrorActionPreference = "Stop"

# Ensure python exists
if (!(Test-Path $PythonPath)) {
  Write-Error "Python not found: $PythonPath"
}

$Args = "-m remotecli.agent.__main__ --server-url `"$ServerUrl`" --token `"$Token`" --auto-remediate"
$BinPath = "`"$PythonPath`" $Args"

# Create Windows service
try {
  New-Service -Name "SEHCSAgent" -BinaryPathName $BinPath -DisplayName "SEHCS Agent" -Description "Runs SEHCS compliance agent." -StartupType Automatic
  Write-Host "Service SEHCSAgent created."
} catch {
  Write-Warning "Service may already exist. Attempting to update."
  sc.exe config SEHCSAgent binPath= $BinPath | Out-Null
}

# Optional: scheduled task to run hourly (recommended for periodic execution)
if ($CreateScheduledTask) {
  $Action = New-ScheduledTaskAction -Execute $PythonPath -Argument $Args
  $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
  $Trigger.Repetition = New-ScheduledTaskRepetition -Interval (New-TimeSpan -Hours 1) -StopAtDurationEnd:$false
  Register-ScheduledTask -TaskName "SEHCSAgentHourly" -Action $Action -Trigger $Trigger -Description "Run SEHCS Agent hourly" -User "SYSTEM" -RunLevel Highest -Force
  Write-Host "Scheduled task SEHCSAgentHourly created."
}