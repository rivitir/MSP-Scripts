$monitorStatus=""
$protectionStatus=""
$monitorBuildId=""
$agentLoadedStatus=""
$javaAgentStatus=""
$mitigationPolicyName=""
$ngavHealth="Unknown"

#External Functions can set a global error message for processing
$global:errorMsg = $null

#Run a discovery to see if SentinelOne Successfully Installed
function checkSentinelOne {
  $s1_jsonObj = $null
  
  try {
    $helper = New-Object -ComObject "SentinelHelper.1" -errorvariable s1Error
    $s1_jsonObj = $helper.GetAgentStatusJSON()
  } 
  catch {
    Set-Variable -Name errorMsg -Value $s1Error -Scope Global
  }
  return $s1_jsonObj
}

function ConvertFrom-Json20($item) {
  add-type -assembly system.web.extensions
  $ps_js=new-object system.web.script.serialization.javascriptSerializer
  
  #The comma operator is the array construction operator in PowerShell
  return ,$ps_js.DeserializeObject($item)
}

$sentinelCtlCheck = Get-ChildItem -Path "$env:SystemDrive\Program Files\SentinelOne" -Filter "sentinelctl.exe" -Recurse | Select -Last 1
if($sentinelCtlCheck) {
  $sentinelCtlPath = $sentinelCtlCheck.FullName
  $sentinelCtlArguments = "status"
  $sentinelCtlProcessCfg = New-Object System.Diagnostics.ProcessStartInfo
  $sentinelCtlProcessCfg.FileName = $sentinelCtlPath
  $sentinelCtlProcessCfg.RedirectStandardError = $true
  $sentinelCtlProcessCfg.RedirectStandardOutput = $true
  $sentinelCtlProcessCfg.UseShellExecute = $false
  $sentinelCtlProcessCfg.Arguments = $sentinelCtlArguments
  $sentinelCtlProcess = New-Object System.Diagnostics.Process
  $sentinelCtlProcess.StartInfo = $sentinelCtlProcessCfg
  $sentinelCtlProcess.Start() | Out-Null
  $sentinelCtlProcess.WaitForExit()
  $sentinelCtlProcessOutput = $sentinelCtlProcess.StandardOutput.ReadToEnd()
  $sentinelCtlProcessErrors = $sentinelCtlProcess.StandardError.ReadToEnd()
  $sentinelCtlProcessExitCode = $sentinelCtlProcess.ExitCode
  
  if($sentinelCtlProcessOutput.Length -gt 0) {
    $sentinelCtlProcessOutputArray = $sentinelCtlProcessOutput.Split("`n")
    foreach ($entry in $sentinelCtlProcessOutputArray) {
      if($entry -like '*SentinelMonitor*' ) {
        $monitorStatus = $entry -Replace '^.*SentinelMonitor is ',''
      }
      elseif ($entry -like '*Self-Protection*') {
        $protectionStatus = $entry -Replace '^.*Self-Protection status: ',''
      }
      elseif ($entry -like '*Monitor Build*') {
        $monitorBuildId = $entry -Replace '^.*Monitor Build id: ',''
      }
      elseif ($entry -like '*SentinelAgent*') {
        $agentLoadedStatus = $entry -Replace '^.*SentinelAgent is ',''
      }
      elseif ($entry -like '*Java*') {
        $javaAgentStatus = $entry -Replace '^.*Java Agent is ',''
      }
      elseif ($entry -like '*Mitigation*') {
        $mitigationPolicyName = $entry -Replace '^.*Mitigation policy: ',''
      }
    }
  }
}

if($monitorStatus -match '^loaded.*') {
  $monitorStatusId=1
  $monitorStatus = "Normal"
}
elseif($monitorStatus -eq "") {
  $monitorStatusId=3
  $monitorStatus = "No Status Returned"
}
else {
  $monitorStatusId=2
}

if($protectionStatus -match '^On.*') {
  $protectionStatusId=1
  $protectionStatus = "Normal"
}
elseif($protectionStatus -eq "") {
  $protectionStatusId=3
  $protectionStatus = "No Status Returned"
}
else {
  $protectionStatusId=2
}

if($agentLoadedStatus -match '^loaded.*') {
  $agentLoadedStatusId=1 
  $agentLoadedStatus = "Normal"
}
elseif($agentLoadedStatus -match '^running as PPL.*') {
  $agentLoadedStatusId=1
  $agentLoadedStatus = "Normal"
}
elseif($agentLoadedStatus -eq "") {
  $agentLoadedStatusId=3
  $agentLoadedStatus = "No Status Returned"
}
else {
  $agentLoadedStatusId=2
}

$s1_jsonObj = checkSentinelOne
if (!($global:errorMsg)) {
  $jsonObj = ConvertFrom-Json20($s1_jsonObj)
  $s1_agentActiveThreatsPresentStatus = $jsonObj.'active-threats-present'

  if ($s1_agentActiveThreatsPresentStatus -notmatch '^False.*') {
    $s1_agentActiveThreatsPresentStatusId = 2
  }
  else {
    $s1_agentActiveThreatsPresentStatusId = 1
  }
}
else {
  $s1_agentActiveThreatsPresentStatus = "No Status Returned"
  $s1_agentActiveThreatsPresentStatusId = 3
}

# Check for the SentinelOne
$s1_Reg = $True
$s1_Serv = $True
$s1_Proc = $True

# Check to see if the registry key exists. If it does exist, then we need to confirm the uninstall path is set.
$s1_RegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Sentinel Agent"
if (!(Test-Path $s1_RegKey)) { $s1_Reg = $FALSE } 
else { $s1_RegVal = Get-ItemProperty $s1_RegKey | select UninstallString }

If ($s1_RegVal -eq $null) { $s1_Reg = $FALSE } 
else { }

# Check to see if the Windows service exists
$s1_ServiceAgent = get-service | Where-Object {$_.Name -match "SentinelAgent"} | select Name
if ($s1_ServiceAgent -ne $null) { } 
else { $s1_Serv = $FALSE }

# Check to see if the process is running
$s1_ProcessAgent = get-process | Where-Object {$_.ProcessName -match "SentinelAgent"} | select Name
if ($s1_ProcessAgent -ne $null) { } 
else { $s1_Proc = $FALSE }

# Write to Custom Fields
Ninja-Property-Set monitorStatus $($monitorStatus)
Ninja-Property-Set protectionStatus $($protectionStatus)
Ninja-Property-Set agentLoadedStatus $($agentLoadedStatus)
Ninja-Property-Set mitigationPolicyName $($mitigationPolicyName)

# Write to Console
Write-Host "Monitor Status: $($monitorStatus)"
Write-Host "Protection Status: $($protectionStatus)"
Write-Host "Agent Loaded Status: $($agentLoadedStatus)"
Write-Host "Mitigation Policy: $($mitigationPolicyName)"

# If SentinelOne has an active threat, error result.
If (2 -eq $s1_agentActiveThreatsPresentStatusId) {
  Write-Host "There are active threats present. Please check the portal."
  $ngavHealth="Active Threats"
  Write-Host "NGAV Health: $($ngavHealth)"
  Ninja-Property-Set ngavHealth $($ngavHealth)
  Exit 2
}

# If SentinelOne is not installed, error result.
If (($s1_Serv -eq $FALSE) -and ($s1_Proc -eq $FALSE)) {
  Write-Host "SentinelOne is not installed. Needs to be installed."
  $ngavHealth="Not Installed"
  Write-Host "NGAV Health: $($ngavHealth)"
  Ninja-Property-Set ngavHealth $($ngavHealth)
  Exit 1
}

# If SentinelOne is installed and not running, error result.
If ((1 -ne $agentLoadedStatusId) -or (1 -ne $protectionStatusId)) {
  Write-Host "SentinelOne is installed but not running!"
  $ngavHealth="Unhealthy"
  Write-Host "NGAV Health: $($ngavHealth)"
  Ninja-Property-Set ngavHealth $($ngavHealth)
  Exit 1
}

# If SentinelOne is clearly installed and running, no further actions required.
If ((1 -eq $agentLoadedStatusId) -and (1 -eq $protectionStatusId)) {
  Write-Host "SentinelOne is installed and running!"
  $ngavHealth="Healthy"
  Write-Host "NGAV Health: $($ngavHealth)"
  Ninja-Property-Set ngavHealth $($ngavHealth)
  Exit 0
}