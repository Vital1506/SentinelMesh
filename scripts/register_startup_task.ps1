param(
    [string]$TaskName = "SentinelMesh",
    [string]$WorkingDirectory = (Resolve-Path "$PSScriptRoot\..").Path
)

$python = Join-Path $WorkingDirectory ".venv\Scripts\python.exe"
$action = New-ScheduledTaskAction -Execute $python -Argument "-m sentinelmesh serve" -WorkingDirectory $WorkingDirectory
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force
