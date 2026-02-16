# ================================
# Deep Freeze Cleanup Script    - WS 2/15/2026
# ================================

# Use at your own risk. I am not liable for any damages or losses
# This will remove Deep Freeze components but system must not be frozen



# --- Helper Functions ---

function Write-Log {
    param (
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    $current = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    Write-Host $Message
    $Host.UI.RawUI.ForegroundColor = $current
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "Removal Script must be run as Administrator." Red
    exit 1
}


function Stop-ServiceSafe {
    param([string]$Name)

    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        if ($svc.Status -ne "Stopped") {
            Stop-Service -Name $Name -Force -ErrorAction Stop
        }
        return 0
    }
    catch {
        return 1
    }
}

function Remove-RegistryKeySafe {
    param([string]$Path)

    try {
        if (Test-Path $Path) {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
        }
        return 0
    }
    catch {
        return 1
    }
}



if (-not ([System.Management.Automation.PSTypeName]'Win32.NativeMethods').Type) {

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace Win32 {
    public static class NativeMethods {

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool MoveFileEx(
            string lpExistingFileName,
            string lpNewFileName,
            int dwFlags
        );
    }
}
"@
}


function Remove-FileSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [switch]$WhatIf
    )

    # Constants
    $MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004

    # Normalize path
    try {
        $resolved = Resolve-Path -Path $Path -ErrorAction Stop
        $fullPath = $resolved.Path
    }
    catch {
        Write-Log "Path not found: $Path" Yellow
        return 2   # not found
    }

    if ($WhatIf) {
        Write-Log "WhatIf: would remove $fullPath" Cyan
        return 0
    }

    try {
        Remove-Item -LiteralPath $fullPath -Force -ErrorAction Stop
        Write-Log "$fullPath deleted." Green
        return 0
    }
    catch {
        # Attempt to schedule deletion at reboot
        $ok = [Win32.NativeMethods]::MoveFileEx($fullPath, $null, $MOVEFILE_DELAY_UNTIL_REBOOT)
        if ($ok) {
            Write-Log "$fullPath locked; scheduled for deletion on next reboot." Yellow
            return 1   # scheduled
        }
        else {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Log "Failed to delete or schedule $fullPath. Win32 error: $err" Red
            return 3   # failure
        }
    }
}





function Remove-FolderSafe {
    param([string]$Path)

    try {
        if (Test-Path $Path) {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
        }
        return 0
    }
    catch {
        return 1
    }
}

# --- Driver Removal ---

function Remove-DFDriver {
    param([string]$DriverName)

    Write-Log "Processing driver $DriverName..." Cyan

    # Stop driver service if present
    Stop-ServiceSafe $DriverName | Out-Null

    # Remove from Services registry
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$DriverName"
    if ((Remove-RegistryKeySafe $serviceKey) -eq 1) {
        Write-Log "Failed to remove service registry for $DriverName" Red
        return 1
    }

    # Delete driver file
    $driverFile = "$env:windir\System32\drivers\$DriverName.sys"
    $result = Remove-FileSafe $driverFile

    switch ($result) {
        0 { } # deleted
        1 { Write-Log "$DriverName.sys scheduled for deletion on reboot." Yellow }
        2 { Write-Log "$DriverName.sys not found (already removed)." Gray }
        3 {
            Write-Log "Failed to delete $DriverName.sys" Red
            return 2
        }
    }

    Write-Log "Driver $DriverName removed." Cyan
    return 0
}

# --- Remove DF Service (dfserv) ---

function Remove-DFService {

    Write-Log "Removing DFServ..." Cyan

    taskkill /im dfserv.exe /f 2>$null
    taskkill /im frzstate2k.exe /f 2>$null
    taskkill /im dflocker64.exe /f 2>$null
    taskkill /im dflocker.exe /f 2>$null

    Start-Sleep 1

    sc.exe stop dfserv | Out-Null
    Start-Sleep 1
    sc.exe delete dfserv | Out-Null
    Start-Sleep 1

    $dfPath = "${env:ProgramFiles}\Faronics\Deep Freeze\DFServ.exe"

    for ($i = 0; $i -lt 10; $i++) {
        if (Test-Path $dfPath) {
            Remove-FileSafe $dfPath | Out-Null
            Start-Sleep 1
        }
    }

    Write-Log "DFServ removal attempted." Cyan
    return 0
}

# --- Remove Deep Freeze Files ---

function Remove-DFFiles {

    Write-Log "Removing Deep Freeze files..." Cyan

    $base = "${env:ProgramFiles}\Faronics\Deep Freeze"

    for ($i = 0; $i -le 10; $i++) { # $Df is literal (single quote)-- text is not a variable!
        $folder1 = Join-Path $base ('Install C-{0}_$Df' -f $i)
        Remove-FolderSafe $folder1 | Out-Null

        $folder2 = Join-Path $base ("Install C-$i")
        Remove-FolderSafe $folder2 | Out-Null
    }

    Remove-FolderSafe $base | Out-Null

    Remove-FileSafe "$env:windir\System32\dfc.exe" | Out-Null
    Remove-FileSafe "$env:windir\SysWOW64\dfc.exe" | Out-Null

    return 0
}

# --- Remove Registry Entries ---

function Remove-DFRegistry {

    Write-Log "Cleaning registry..." Cyan

    $wow = ""
    if ([Environment]::Is64BitOperatingSystem) {
        $wow = "Wow6432Node\"
    }

    Remove-RegistryKeySafe "HKLM:\Software\${wow}Faronics\Deep Freeze 6" | Out-Null
    Remove-RegistryKeySafe "HKCR:\${wow}CLSID\{B5CC39B3-F5FA-4FAD-BF9D-3E1CB286C673}" | Out-Null

    return 0
}

# --- Remove WMI Class ---

function Remove-DFWMI {

    Write-Log "Checking for DeepFreeze WMI class..." Cyan

    try {
        # Check if class exists
        $class = Get-WmiObject -Namespace "root\faronics" -List -ErrorAction Stop |
                 Where-Object { $_.Name -eq "DeepFreeze" }

        if (-not $class) {
            Write-Log "DeepFreeze WMI class not found. Nothing to remove." Yellow
            return 0
        }

        Write-Log "Removing DeepFreeze WMI instances..." Cyan

        # Remove all instances
        Get-WmiObject -Namespace "root\faronics" -Class "DeepFreeze" -ErrorAction Stop |
            ForEach-Object {
                $_.Delete()
            }

        Write-Log "Removing DeepFreeze WMI class definition..." Cyan

        # Remove the class definition
        $class.Delete()

        Write-Log "WMI class removed successfully." Green
        return 0
    }
    catch {
        Write-Log ("Failed to remove WMI class. Error: {0}" -f $_.Exception.Message) Red
        return 1
    }
}





# --- Revert System Settings ---

function Revert-SystemSettings {

    Write-Log "Reverting system settings..." Cyan

    bcdedit /set '{current}' bootstatuspolicy displayallfailures | Out-Null

    sc.exe config wuauserv start= auto | Out-Null
    sc.exe config UsoSvc start= auto | Out-Null

    # Restore CrashControl
    Set-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" `
        -Name "LogEvent" `
        -Value 1 -ErrorAction SilentlyContinue

    # Restore page file default
    Set-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
        -Name "PagingFiles" `
        -Value "?:\pagefile.sys" -ErrorAction SilentlyContinue

    return 0
}



# --- Additional Cleanup Patch ---

function Invoke-AdditionalCleanup {

    Write-Log "Performing additional leftover cleanup..." Cyan

    # --- Extra Services ---
    $extraServices = @("DF5Serv","DF6Serv","FWASvc")

    foreach ($svc in $extraServices) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            sc.exe delete $svc | Out-Null
            Write-Log "Deleted leftover service $svc" Cyan
        }
    }

    # --- Extra Files / Folders ---
    $extraPaths = @(
        "$env:ProgramFiles\Faronics",
        "$env:ProgramFiles(x86)\Faronics",
        "C:\Persi0.sys"
    )

    foreach ($path in $extraPaths) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Removed leftover path $path" Cyan
        }
    }

    # --- Extra Registry Keys ---
    $extraRegistry = @(
        "HKLM:\SOFTWARE\Faronics",
        "HKLM:\SOFTWARE\Wow6432Node\Faronics",
        "HKLM:\SYSTEM\ControlSet001\Services\DFServ",
        "HKLM:\SYSTEM\ControlSet001\Services\DeepFrz",
        "HKLM:\SYSTEM\ControlSet001\Services\FWASvc"
    )

    foreach ($reg in $extraRegistry) {
        if (Test-Path $reg) {
            Remove-Item -Path $reg -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Removed leftover registry $reg" Cyan
        }
    }
}


# --- Master Removal Function ---

function Invoke-DeepFreezeRemoval {

    Write-Log "`nStarting Deep Freeze full removal..." Cyan

    $success = $true

    foreach ($drv in @("DeepFrz","DfDiskLo","FarDisk","DFFilter","DFRegMon")) {
        if ((Remove-DFDriver $drv) -ne 0) { $success = $false }
    }

    if ((Remove-DFService) -ne 0) { $success = $false }
    if ((Remove-DFFiles) -ne 0) { $success = $false }
    if ((Remove-DFRegistry) -ne 0) { $success = $false }
    if ((Remove-DFWMI) -ne 0) { $success = $false }
    if ((Revert-SystemSettings) -ne 0) { $success = $false }

    Invoke-AdditionalCleanup

    if ($success) {
        Write-Log "`nDeep Freeze removal completed successfully." Green
        return 0
    }
    else {
        Write-Log "`nDeep Freeze removal completed with errors." Yellow
        return -1
    }
}



# --- Execute ---

Invoke-DeepFreezeRemoval
