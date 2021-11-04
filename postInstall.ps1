
<#
    .DESCRIPTION
    
    .INPUTS
    None. You cannot pipe object.

    .OUTPUTS
    Console based and log file 

    .NOTES   
    Name       : 
    Authors    : Paul Caligari
    Version    : 1.09
    DateCreated: 2018-02-07
    DateUpdated: 2018-06-04

#>

#region FUNCTIONS
####################################################################################################
# Function declarations
####################################################################################################

#region Function Write-Log
# -------------------------------------- function Write-Log -------------------------------------- #

<#
    .SYNOPSIS
    This function Output's to screen and write to Log File
    .DESCRIPTION
    ...
#>

Function Write-Log
{
   
  [CmdletBinding()]
  Param(
    [PSObject]$InputObject,
    [String]$Severity='INFO',
    [String]$Color='Gray'
  ) # end Param

  If ($Logging)
  {
  
    $CallStack = Get-PSCallStack
    If (($CallStack | Measure-Object).Count -gt 1)
    {
      $functionName = $CallStack[1].Command
      $Location = $CallStack[1].Location
    } Else {
      $functionName = 'functionNameNotFound'
      $Location = 'LocationNotFound'
    } 

    $DateStamp = Get-Date -Format yyyyMMdd-HHmmss
    $OutputLogLine = "$($DateStamp)`t$($Severity)`t$($functionName)`t$($Location)`t$('    '*$Global:Indent)$($InputObject)"

    $OutputLogLine | Out-File -Append -FilePath $Global:LogFile -Whatif:$False
    $OutputLine = "`t$('    '*$Global:Indent)$($InputObject)"
    If ($Severity -ne 'VERBOSE') {
      $OutputLine = "$($Severity):`t $('    '*$Global:Indent)$($InputObject)"
    }
    Switch ($Severity)
    {
      'VERBOSE' { If ($ScriptInfoPreference) { Write-Verbose -Message $OutputLine } }
      'DEBUG' { If ($ScriptDebugPreference) { Write-Debug -Message $OutputLine } }
      'WARNING' { If ($ScriptWarningPreference) { Write-Warning -Message $OutputLine } }
      'ERROR' { If ($ScriptErrorPreference) { Write-Host -Object $OutputLine -ForegroundColor Red} }
      'INFO' { If ($ScriptErrorPreference) { Write-Host -Object $OutputLine -ForegroundColor $Color} }
      'THROW' { throw $OutputLine }
    }
  } # end if($Logging)
} # end function Write-Log
#
#endregion function Write-Log


####################################################################################################

#region Function Set-PowershellConsoleView
# ------------------------------ Function Set-PowershellConsoleView ------------------------------ #

<#
    .SYNOPSIS
    This function ....
    .DESCRIPTION
    ...
#>
Function Set-PowershellConsoleView
{
  Param (
  ) # End Param

  # Initialize console Settings and Output header

  # Set background color to Black
  $Host.UI.RawUI.BackgroundColor = 'Black'

  $newsize = $host.ui.RawUI.buffersize
  $newsize.width = 160
  $host.ui.RawUI.buffersize = $newsize
  $newsize = $host.ui.RawUI.windowsize
  $newsize.width = 160

  $host.ui.RawUI.windowsize = $newsize
  $Host.UI.RawUI.WindowTitle = "Windows Server 2019 - Post Deployment Tasks v$ScriptVersion"
  Clear-Host
} # End Function Set-PowershellConsoleView
#
#endregion Function Set-PowershellConsoleView 


####################################################################################################
Function Exit-Script
{
  Param (
  ) # End Param
   
  $CurrentVerbosePreference = $Global:VerbosePreference
  $Global:VerbosePreference = 'SilentlyContinue'

  <#
      if ($Error) {
      $Error | ForEach-Object {
      $CurrentError = $_
      $ErrorLine = "$($CurrentError.InvocationInfo.PositionMessage) - $($CurrentError.Exception.Message)".Replace("`r`n",'')
      Write-Log -Severity VERBOSE -InputObject "$ErrorLine"
      }
      }
  #>
  Exit

} # End Function Exit-Script
#
#endregion Function Exit-Script 

####################################################################################################

#endregion FUNCTIONS

#region VARIABLES
####################################################################################################
# Initialize Variables
####################################################################################################

#Exchange Server to be upgraded
$ComputerName = $env:computername

$Domain = $env:USERDOMAIN
$DomainDNS = $env:USERDNSDOMAIN

$Path = $env:temp

#Set Script version and logging

$ScriptFile = Get-Item -Path $MyInvocation.MyCommand.Path.ToString()
$ScriptName = $ScriptFile.BaseName

$TimeStampNow = Get-Date
$TimeStamp = Get-Date -Format yyyymmdd-HHMMss -Date $TimeStampNow

$LogFileName = $ScriptName + '_' + $TimeStamp + '.log'
$LogFolder = Join-Path -Path "$env:SystemRoot" -ChildPath 'Logs'

If (!(Test-Path -Path $LogFolder)) {
  New-Item -ItemType Directory -Path $LogFolder -Force
}

$Global:LogFile = Join-Path -Path $LogFolder -ChildPath $LogFileName

$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$Logging = $True
$ScriptInfoPreference = $True
$ScriptDebugPreference = $True
$ScriptWarningPreference = $True
$ScriptErrorPreference = $True
$ScriptVersion = "1.09"
$Global:Indent = 0

$LogFile = '\' + (Get-Date -Format 'yyyy-MM-dd-hh-mm-ss') + '-PostDeploymentTasks.log'
$LogFilePath = Join-Path -Path $LogFolder -ChildPath $LogFile
#endregion VARIABLES

#region MAIN SCRIPT
####################################################################################################
# Script
####################################################################################################

Write-Log -Severity INFO -InputObject 'Connecting to Azure FileShare' -Color White

Write-Log -Severity INFO -InputObject 'Copying PostDeployment Files' -Color White

# Configure Console to fit text
Set-PowershellConsoleView

####################################################################################################

#Clear-Host 
Write-Log -Severity INFO -InputObject 'Windows Server 2019 - Post OS Deployment Tasks' -Color White
$Global:Indent++
Write-Log -Severity INFO -InputObject "Target server: [$($ComputerName)]"

#Log File Paths
Write-Log -Severity INFO -InputObject "Script path: [$($Path)]"
Write-Log -Severity INFO -InputObject "Script version: [$($ScriptVersion)]"
Write-Log -Severity INFO -InputObject "Log file: [$($LogFilePath)]"

####################################################################################################

$Global:Indent--
Write-Log -Severity INFO -InputObject 'UPDATE REGION SETTINGS' -Color White
$Global:Indent++

Write-Log -Severity INFO -InputObject "Reading CSV file from $($Path)\CountryCodeLookup.csv"
$csv = import-csv -Path ".\CountryCodeLookup.csv"

# Get data
$CountryCode = ($env:COMPUTERNAME).Substring(0,2)
$GeoId = ($csv.Where({$_.CountryCode -eq $CountryCode})).GeoID
$Location = ($csv.Where({$_.CountryCode -eq $CountryCode})).Location
$TimeZone = ($csv.Where({$_.CountryCode -eq $CountryCode})).TimeZone

Write-Log -Severity INFO -InputObject "CountryCode is [$($CountryCode)]"
Write-Log -Severity INFO -InputObject "GeoID found from CSV is [$($GeoID)]"
Write-Log -Severity INFO -InputObject "Location found from CSV is [$($Location)]"
Write-Log -Severity INFO -InputObject "TimeZone found from CSV is [$($TimeZone)]"

$xml = @()
$xml = '<gs:GlobalizationServices xmlns:gs="urn:longhornGlobalizationUnattend">
 
  <!-- user list --> 
  <gs:UserList>
  <gs:User UserID="Current" CopySettingsToDefaultUserAcct="true" CopySettingsToSystemAcct="true"/> 
  </gs:UserList>
'

$xml += "
  <gs:LocationPreferences> 
  <gs:GeoID Value=$('"'+$GeoID+'"')/> 
  </gs:LocationPreferences>
"

$xml += '</gs:GlobalizationServices>'
Write-Log -Severity INFO -InputObject "Outputting MUI.xml to $($Path)\MUI.xml"
$xml | Out-File "$Path\MUI.xml"

$ErrorActionPreference = 'SilentlyContinue' 
Write-Log -Severity INFO -InputObject "Update server location to $Location"
$null = C:\Windows\System32\control.exe "intl.cpl,,/f:""$Path\MUI.xml"""

# Set Timezone
Write-Log -Severity INFO -InputObject "Update server time zone to $TimeZone"
Set-TimeZone $TimeZone

$Global:Indent--
Write-Log -Severity INFO -InputObject 'UPDATE ROLES AND FEATURES' -Color White
$Global:Indent++

<#
# Modify Roles and Features
Write-Log -Severity INFO -InputObject 'Modify Roles - Install AD-Domain-Services,RSAT-ADDS-Tools,RSAT-DNS-Server'
$null = Install-WindowsFeature AD-Domain-Services,RSAT-ADDS-Tools,RSAT-DNS-Server
Write-Log -Severity INFO -InputObject 'Modify Features - Remove FS-SMB1'
$null = Remove-WindowsFeature FS-SMB1
Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force
#>

# Enable Remote Desktop
Write-Log -Severity INFO -InputObject 'Enable remote desktop'
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0

# Hide PopUp at startup
Write-Log -Severity INFO -InputObject 'Hide PopUp at startup'
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\ServerManager' -Name 'DoNotPopWACConsoleAtSMLaunch' -Type Dword -Value 1


# Windows Firewall Rules
Write-Log -Severity INFO -InputObject 'Disable domain firewall'
Set-NetFirewallProfile -Profile 'Domain' -Enabled False

# Set Network security: LAN Manager authentication level
Write-Log -Severity INFO -InputObject 'Disable NTLMv1 support'
Set-ItemProperty -Path 'HKLM\System\CurrentControlSet\Control\Lsa' -Name 'LMCompatibilityLevel' -value 5


# Disable Link-Local Multicast Name Resolution (LLMNR) protocol
Write-Log -Severity INFO -InputObject  "Disable LLMNR"
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0

# Disable NetBIOS
Write-Log -Severity INFO -InputObject  "Disable NetBIOS"
Get-WmiObject win32_networkadapterconfiguration | foreach {$_.settcpipnetbios(2)}


$Global:Indent--
Write-Log -Severity INFO -InputObject 'PATCH OS VULNERABILITIES' -Color White
$Global:Indent++

# Spectre
Write-Log -Severity INFO -InputObject 'Enable Spectre Meltdown mitigation'
$null = New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverride -Value 0 -PropertyType DWORD
$null = New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverrideMask -Value 3 -PropertyType DWORD

Write-Log -Severity INFO -InputObject 'Apply registry fix for CVE-2017-8547'
$null = New-Item 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX' -Force
$null = New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX' -Name iexplore.exe -Value 1 -PropertyType DWORD

Write-Log -Severity INFO -InputObject 'Apply registry fix for CVE-2017-8547'
$null = New-Item 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX' -Force
$null = New-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX' -Name iexplore.exe -Value 1 -PropertyType DWORD


Exit-Script