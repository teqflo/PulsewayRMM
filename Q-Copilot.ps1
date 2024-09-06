<# TRIGGER EXAMPLES
#Disable all Copilot features system-wide
powershell -Command "& { . 'C:\Scripts\Q-Copilot.ps1'; Set-QCopilotComputer -WindowsCopilot Disable -CopilotPlusRecall Disable -EdgeCopilot Disable -BingCopilot Disable }"

#Disable Copilot taskbar button for the current user (and specific abbrevation on Windows 10)
powershell -Command "& { . 'C:\Scripts\Q-Copilot.ps1'; Set-QCopilotUser -WindowsCopilot Disable -CopilotTaskbarButton Disable }"

#Or within the same script just call either (as last line in script/scope)
Set-QCopilotComputer -WindowsCopilot Disable -CopilotPlusRecall Disable -EdgeCopilot Disable -BingCopilot Disable
#or
Set-QCopilotUser -WindowsCopilot Disable -CopilotTaskbarButton Disable
#>

# Helper function to set registry value only if it's different from the desired value
function SetRegistryValueIfDifferent {
    param(
        [string]$Path,
        [string]$ValueName,
        [int]$DesiredValue
    )

    # Check if the registry path exists before attempting to get or set its value
    if (-not (Test-Path $Path)) {
        Write-Verbose "Registry path '$Path' does not exist. Creating it..."
        New-Item -Path $Path -Force | Out-Null
    }

    $currentValue = Get-ItemProperty -Path $Path -Name $ValueName -ErrorAction SilentlyContinue
    if (($currentValue -and $currentValue.$ValueName -ne $DesiredValue) -or -not $currentValue) {
        New-ItemProperty -Path $Path -Name $ValueName -Value $DesiredValue -PropertyType DWORD -Force
        Write-Verbose "Set '$ValueName' in '$Path' to '$DesiredValue'"
    } else {
        Write-Verbose "'$ValueName' in '$Path' is already set to '$DesiredValue'"
    }
}

# Function to ensure a registry path exists, creating intermediate keys if necessary
function EnsureRegistryPath {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Verbose "Registry path '$Path' does not exist. Creating it..."
        New-Item -Path $Path -Force | Out-Null
    }
}

# Function to convert state to DWORD value
function ConvertToDword {
    param([string]$State)

    if ($State -eq "Enable") {
        return 0
    } elseif ($State -eq "Disable") {
        return 1
    } else {
        throw "Invalid state: $State"
    }
}

# Function to configure Copilot settings for the current user (HKCU)
function Set-QCopilotUser {
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("Enable", "Disable")]
        [string]$CopilotTaskbarButton,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Enable", "Disable")]
        [string]$WindowsCopilot # For Windows 10 specific settings
    )

    try {
        # Copilot Taskbar Button (All Windows versions)
        if ($CopilotTaskbarButton -ne $null) { 
            $copilotTaskbarButtonPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            $copilotTaskbarButtonValueName = "ShowCopilotButton"
            SetRegistryValueIfDifferent $copilotTaskbarButtonPath $copilotTaskbarButtonValueName (ConvertToDword $CopilotTaskbarButton)
        }

        # Windows 10 Copilot
        if ((Get-CimInstance -ClassName Win32_OperatingSystem).Caption -like "*Windows 10*" -and $WindowsCopilot -eq "Disable") {
            $win10CopilotPath = "HKCU:\Software\Microsoft\Windows\Shell\Copilot"
            EnsureRegistryPath $win10CopilotPath

            $win10CopilotDisabledReasonValueName = "CopilotDisabledReason"
            SetRegistryValueIfDifferent $win10CopilotPath $win10CopilotDisabledReasonValueName "IsEnabledForGeographicRegionFailed" 

            $win10CopilotIsAvailableValueName = "IsCopilotAvailable"
            SetRegistryValueIfDifferent $win10CopilotPath $win10CopilotIsAvailableValueName (ConvertToDword $WindowsCopilot)
        }
    } catch {
        Write-Error "An error occurred while configuring Copilot settings for the current user: $($_.Exception.Message)"
    }
}

# Function to configure Copilot settings for the computer (HKLM)
function Set-QCopilotComputer {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Enable", "Disable")]
        [string]$WindowsCopilot,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Enable", "Disable")]
        [string]$CopilotPlusRecall,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Enable", "Disable")]
        [string]$EdgeCopilot,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Enable", "Disable")]
        [string]$BingCopilot
    )

    try {
        # Windows Copilot
        $copilotPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsCopilot"
        $copilotValueName = "TurnOffWindowsCopilot"
        SetRegistryValueIfDifferent $copilotPath $copilotValueName (ConvertToDword $WindowsCopilot)

        # Copilot + Recall
        $copilotPlusRecallPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
        $copilotPlusRecallValueName = "DisableAIDataAnalysis"
        SetRegistryValueIfDifferent $copilotPlusRecallPath $copilotPlusRecallValueName (ConvertToDword $CopilotPlusRecall)

        # Microsoft Edge Copilot
        $edgeCopilotPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        $edgeCopilotValueName = "HubsSidebarEnabled"
        SetRegistryValueIfDifferent $edgeCopilotPath $edgeCopilotValueName (ConvertToDword $EdgeCopilot)

        # Bing and Search Services Copilot
        $bingCopilotPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        $bingCopilotValueName = "DisableSearchBoxSuggestions"
        SetRegistryValueIfDifferent $bingCopilotPath $bingCopilotValueName (ConvertToDword $BingCopilot)
    } catch {
        Write-Error "An error occurred while configuring Copilot settings for the computer: $($_.Exception.Message)"
    }
}
