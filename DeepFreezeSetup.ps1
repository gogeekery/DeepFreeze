# ======================================================
# Deep freeze Lab Setup Script - WS 2/11/2026
# ======================================================

# If you include the removal script this will attempt to remove any existing Deep Freeze installation first
# If you do not include that script, please make sure Deep Freeze is fully removed from the computer first
# You can contact Faronics for an official Deep Freeze removal tool
# My included removal script may have issues and is not maintained so it may break


# >> Do not run this on a frozen computer!
# >> Use at your own risk.


if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Script must be run as Administrator." Red
    exit 1
}


# ==========================
# ======= Configuration =======
# ===============================

# Log file for silent/remote installs
$LogFile = Join-Path $env:windir "Temp\LabDFSetupScript.log"
$DFRemovalScriptName = "DeepFreezeRemoval.ps1"      # < If this script exists nearby and detects and old DF installed it will run to remove it
                                                    # Useful if we have an old Deep Freeze install that needs removed to install DF Cloud


function Log {                
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ConsoleColor]$ForegroundColor = "White"
    )
    
    $TimeStamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $FormattedMessage = "$TimeStamp - $Message"
    
    Write-Host $FormattedMessage -ForegroundColor $ForegroundColor
    $FormattedMessage | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

$IPAddress = (Get-NetIPAddress -AddressFamily IPv4 `
                               -PrefixOrigin Dhcp `
                               -ErrorAction SilentlyContinue |
              Where-Object { $_.IPAddress -notlike "169.*" } |      # DHCP not responding?
              Select-Object -First 1 -ExpandProperty IPAddress)

Log "Detected IP: $IPAddress"


# ==========================
# ======= Configuration =======
# ===============================


# Account details for the public user (can be blank password but GPO would need configured)
$UserName = "Student"
$Password = "pw"

$ProfileRoot = Join-Path $env:SystemDrive "Users"
$ProfilePath = Join-Path $ProfileRoot $UserName

$ShortcutDesktop = "$env:PUBLIC\Desktop"        # Path to put desktop shortcuts

# ----------

# TODO: Use your own wallpaper link
$WallpaperUrl  = "https://goodwillbigbend.org/LabConfig/Career Campus Desktop Wallpaper.png"
$WallpaperDir  = "$env:PUBLIC\Documents"
$WallpaperPath = Join-Path $WallpaperDir "Wallpaper.png"


$DeepFreezeURL = "" # TODO: Replace this with your Deep Freeze Cloud installer link
$DeepFreezePath = "$env:PUBLIC\Documents\DeepFreezeInstaller.exe"

$SecureBrowserURL = "https://media.prime.prometric.com/Files/prometric_ldb/PrometricSetup.msi"
$SecureBrowserPath = "$env:PUBLIC\Documents\SecureBrowser.msi"


# Desktop shortcuts for Students (centralized)
$AllShortcuts = @{
    "General" = @{
        "Goodwill Big Bend"   = "https://www.goodwillbigbend.org"
        "Career Campus"       = "https://www.gwcareercampus.com"
        "Virtual Campus"      = "https://www.gwvirtualcampus.org"
        "Essential ED GED"    = "https://app.essentialed.com/start/"
        "Northstar"           = "https://www.digitalliteracyassessment.org"
        "Typing.com"          = "https://typing.com"
        "Office 365 Login"    = "https://www.office.com"
        "Skills to Succeed"   = "https://s2sacademy.org/login"
        "Social Security"     = "https://www.ssa.gov"
        "Learn Free"          = "https://www.learnfree.org/"
        "GED"                 = "https://www.ged.com/"
    }

    "JobSearchSites" = @{
        "Indeed"           = "https://www.indeed.com"
        "Snagajob"         = "https://www.snagajob.com"
        "Goodwill Careers" = "https://www.goodwillbigbend.org/careers/"
        "Simply Hired"     = "https://www.simplyhired.com/"
        "Zip Recruiter"    = "https://www.ziprecruiter.com"
    }

    "Locations" = @{
        "Georgia" = @{
            "Access Benefits"  = "https://gateway.ga.gov/access/"
            "Unemployment"     = "https://dol.georgia.gov/individuals/unemployment-benefits"
            "Driver's License" = "https://dds.georgia.gov/"
        }
        "Florida" = @{
            "Access Benefits"  = "https://www.myflorida.com/accessflorida"
            "Unemployment"     = "https://floridajobs.org/Reemployment-Assistance-Service-Center/reemployment-assistance/claimants/apply-for-benefits"
            "Driver's License" = "https://www.flhsmv.gov/driver-licenses-id-cards/renew-or-replace-your-florida-driver-license-or-id-card"
            "Prometric - Secure Browser" = "https://tcnet.prometric.com/flcna/geelockdown/start.aspx"
            "JobSearchSites" = @{
                "Employ Florida" = "https://www.employflorida.com/vosnet/Default.aspx"
            }
        }
        "Springfield" = @{
            "JobSearchSites" = @{
                "Parker Job Openings"     = "http://www.cityofparker.com/about-us-employment.aspx"
                "Bay County Job Openings" = "https://www.baycountyfl.gov/491/Employment-Opportunities"
                "Callaway Job Openings"   = "https://www.cityofcallaway.com/jobs.aspx"
                "Lynn Haven Job Openings" = "https://www.cityoflynnhaven.com/Jobs.aspx"
                "Naf Job Openings"        = "https://www.nafjobs.org/viewjobs.aspx"
                "PC Job Openings"         = "https://www.pcgov.org/552/Job-Openings"
            }
        }
        "Thomasville" = @{
            "JobSearchSites" = @{
                "Walmart Careers" = "https://careers.walmart.com/us/en/home"
            }
        }
    }
}



# Determine Location based on IP
if ($IPAddress -like "192.168.202*") {
    $State = "Georgia-Thomasville"     # Georgia area
} elseif ($IPAddress -like "192.168.3*") {
    $State = "Florida-Springfield"     # Florida Springfield area
} else {
    $State = "Florida"                 # Default to Florida
}

Log "IP location determined as: $State"


# Start with general shortcuts
$Shortcuts = @{}
$Shortcuts += $AllShortcuts["General"]

# Merge state-level shortcuts
if ($State -like "Georgia*") {
    $Shortcuts += $AllShortcuts["Locations"]["Georgia"]
} elseif ($State -like "Florida*") {
    $Shortcuts += $AllShortcuts["Locations"]["Florida"]
}

# Merge city-specific job sites
if ($State -like "*Springfield") {
    $Shortcuts["JobSearchSites"] += $AllShortcuts["Locations"]["Springfield"]["JobSearchSites"]
} elseif ($State -like "*Thomasville") {
    $Shortcuts["JobSearchSites"] += $AllShortcuts["Locations"]["Thomasville"]["JobSearchSites"]
}




# ======================================
# Deep Freeze Install state check ===
# =================================

function Get-DeepFreezeState {

    $windir = $env:windir
    $dfcPath = $null

    # --- Locate DFC.exe (SysWOW64 first like C#) ---
    if (Test-Path "$windir\SysWOW64\DFC.exe") {
        $dfcPath = "$windir\SysWOW64\DFC.exe"
    }
    elseif (Test-Path "$windir\System32\DFC.exe") {
        $dfcPath = "$windir\System32\DFC.exe"
    }

    # --- Determine if installed ---
    $dfService = Get-Service -Name "dfserv" -ErrorAction SilentlyContinue
    $dfDriver  = Get-Service -Name "DeepFrz" -ErrorAction SilentlyContinue

    $installed = $dfService -or $dfDriver -or $dfcPath

    if (-not $installed) {
        return "NotInstalled"
    }

    # --- Check Registry Status ---
    $dfStatus = $null
    $regPaths = @(
        "HKLM:\SOFTWARE\Faronics\Deep Freeze",
        "HKLM:\SOFTWARE\Wow6432Node\Faronics\Deep Freeze"
    )

    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            try {
                $dfStatus = (Get-ItemProperty $path -ErrorAction Stop).Status
                break
            }
            catch {}
        }
    }

    $dfServRunning = $dfService -and $dfService.Status -eq "Running"
    $dfDriverRunning = $dfDriver -and $dfDriver.Status -eq "Running"

    # --- Condition 1: Registry frozen + DFServ running ---
    if ($dfStatus -eq "frozen" -and $dfServRunning) {
        return "Frozen"
    }

    # --- Condition 2: Use DFC.exe if available ---
    if ($dfcPath) {
        $process = Start-Process -FilePath $dfcPath `
                                 -ArgumentList "get /isfrozen" `
                                 -NoNewWindow `
                                 -Wait `
                                 -PassThru `
                                 -ErrorAction SilentlyContinue

        if ($process.ExitCode -eq 1) {
            return "Frozen"
        }
    }

    # --- Condition 3: Seed + Driver Running ---
    if ($dfStatus -eq "seed" -and $dfDriverRunning) {
        return "Frozen"
    }

    # -- Thawed, but is it and old version that needs replaced?
    $cloudService = Get-Service -Name "FWASvc" -ErrorAction SilentlyContinue
    if ($cloudService -ne $null -and $cloudService.Status -eq 'Running') {
        return "Thawed"        # Already running DF Cloud and thawed
    }

    # Not cloud version installed, so remove/install cloud
    return "Reinstall"

}


$dfState = Get-DeepFreezeState

switch ($dfState) {

    "Thawed" {
        Log "Deep Freeze Cloud installed but thawed, configuring install..." -ForegroundColor Green
    }

    "NotInstalled" {
        Log "Deep Freeze not installed. Continuing setup..." -ForegroundColor Green
    }

    "Reinstall" {
        Log "Bad Deep Freeze installed and THAWED. Checking for removal script..." -ForegroundColor Yellow

        # Initialize variables
        $ScriptDirectory = $null
        $removalScript   = $null

        # Only resolve directory if script file exists
        if ($PSCommandPath) {
            $ScriptDirectory = Split-Path -Parent (Resolve-Path $PSCommandPath)
            $removalScript   = Join-Path $ScriptDirectory $DFRemovalScriptName
        }

        # Check for removal script
        if ($removalScript -and (Test-Path $removalScript)) {
            Log "Removal script found at: $removalScript"
            Log "Running removal script..."
            & $removalScript
            Log "Removal script completed. Exiting..."
        }
        else {
            Log "Removal script not found next to the running script." -ForegroundColor Red
            Log ">> Run the removal script manually, then try install <<" -ForegroundColor Red
        }

        Start-Sleep -Seconds 10
        exit 1
    }

    "Frozen" {
        Log "Deep Freeze is FROZEN. Lab configuration cannot continue." -ForegroundColor Red
        Log "Please thaw the machine before running this script." -ForegroundColor Red
        Start-Sleep -Seconds 10
        exit 1
    }
}




# ---------------------------------------------
# Disable Smart App Control if enabled
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
$name = "VerifiedAndReputablePolicyState"
$value = 0

if (-NOT (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force


# ------------------------------------------------------------
# Disable Windows Privacy and OOBE prompt at first sign in
# ----------------------------------------------------------

# Official Windows OOBE Policy Bypass
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -Value 1 -PropertyType DWORD -Force | Out-Null

# Supplemental OOBE Suppression
# These target the underlying system status to trick Windows into thinking the process is complete.
$OobePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
if (-not (Test-Path $OobePath)) { New-Item -Path $OobePath -Force | Out-Null }

Set-ItemProperty -Path $OobePath -Name "PrivacyConsentStatus" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path $OobePath -Name "SkipMachineOOBE" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path $OobePath -Name "SkipUserOOBE" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path $OobePath -Name "ProtectYourPC" -Value 3 -Type DWORD -Force

# Disable First Sign-in Animation ("Hi" / "Getting things ready")
$WinlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $WinlogonPath -Name "EnableFirstLogonAnimation" -Value 0 -Type DWORD -Force




# Ensure the show last logged-on user registry keys are set
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnumerateLocalUsers" -Value 1 -Type DWord







$WScriptShell = New-Object -ComObject WScript.Shell

# Function to Create Website Shortcut
function New-WebsiteShortcut {
    param (
        [string]$Name,
        [string]$URL,
        [string]$Location
    )

    $ShortcutPath = Join-Path $Location "$Name.url"
    $Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = $URL
    $Shortcut.Save()
}

# -----------------------------
# Desktop Shortcuts
# -----------------------------

function New-ShortcutTree {
    param (
        [hashtable]$Tree,
        [string]$BasePath
    )

    foreach ($Key in $Tree.Keys) {
        $Value = $Tree[$Key]

        if ($Value -is [hashtable]) {
            $NewFolder = Join-Path $BasePath $Key
            if (!(Test-Path $NewFolder)) {
                New-Item -Path $NewFolder -ItemType Directory | Out-Null
            }

            New-ShortcutTree -Tree $Value -BasePath $NewFolder
        }
        else {
            New-WebsiteShortcut -Name $Key -URL $Value -Location $BasePath
        }
    }
}

New-ShortcutTree -Tree $Shortcuts -BasePath $ShortcutDesktop

Log "Shortcuts created"




# ---------------------------
# Force the User to appear as an option:

# $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"

# # Create the keys if they do not exist
# if (-not (Test-Path $regPath)) {
#     New-Item -Path $regPath -Force | Out-Null
# }

# # Create or update the DWORD value to hide the user (0 = hidden)
# New-ItemProperty -Path $regPath -Name $UserName -PropertyType DWORD -Value 0 -Force





# -----------------------------
# Handle existing account ------------
# ------------------------------------------

if (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue) {
    Log "Existing account '$UserName' found. Removing old account..." -ForegroundColor Yellow

    $UserSID = (Get-LocalUser -Name $UserName).SID.Value

    # Force logoff if needed
    quser | Select-Object -Skip 1 | ForEach-Object {
        $line = $_ -replace '^\>', ''  # remove leading >
        $columns = $line -split '\s+'

        $user = $columns[0]
        $sessionId = $columns[2]

        if ($user -eq $UserName) {
            logoff $sessionId
        }
    }

    # Wait a moment to release locks
    Start-Sleep -Seconds 5

    # Get the profile via SID
    $Profile = Get-CimInstance Win32_UserProfile | Where-Object {
        $_.SID -eq $UserSID
    }

    if ($Profile) {
        try {
            $Profile | Remove-CimInstance
            Log "Profile removed via Win32_UserProfile." -ForegroundColor Yellow
        }
        catch {
            Log "Failed to remove profile via CIM: $_" -ForegroundColor Red
        }
    }

    if (Test-Path $ProfilePath) {
        try {
            Remove-Item -Path $ProfilePath -Recurse -Force
            Log "Old User Folder at $ProfilePath removed." -ForegroundColor Yellow
        } catch {
            Log "Failed to remove old profile at $ProfilePath. You may need to delete it manually." -ForegroundColor Red
        }
    }

    # Remove the existing user account
    Remove-LocalUser -Name $UserName
    Log "Old account '$UserName' removed." -ForegroundColor Yellow
}


# -----------------------------
# Create local user

$ExistingUser = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if ($ExistingUser) {
    Log "User '$UserName' already exists. Updating password..." -ForegroundColor Yellow
    if (-not [string]::IsNullOrWhiteSpace($Password)) {
        $SecurePW = ConvertTo-SecureString $Password -AsPlainText -Force
        Set-LocalUser -Name $UserName -Password $SecurePW
    }
} else {
    if ([string]::IsNullOrWhiteSpace($Password)) {
        New-LocalUser -Name $UserName -NoPassword -Description "Public Lab Account"
    } else {
        $SecurePW = ConvertTo-SecureString $Password -AsPlainText -Force
        New-LocalUser -Name $UserName -Password $SecurePW -Description "Public Lab Account"
    }
}



# -----------------------------
# Prevent password from being changed or expiring
# -----------------------------

net user $UserName /passwordchg:no
net user $UserName /logonpasswordchg:no
net user $UserName /expires:never

Set-LocalUser -Name $UserName -PasswordNeverExpires $true

# Add to Users group
Add-LocalGroupMember -Group "Users" -Member $UserName




# ----------------------------------
# Update settings and preferences
# ----------------------------------------

# Disable OneDrive for the system
$OneDriveReg = "HKLM:\Software\Policies\Microsoft\Windows\OneDrive"
if (-not (Test-Path $OneDriveReg)) { New-Item -Path $OneDriveReg -Force | Out-Null }
Set-ItemProperty -Path $OneDriveReg -Name "DisableFileSyncNGSC" -Value 1 -Type DWord
Log "OneDrive disabled."

# Disable Edge first-run experience
$EdgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (-not (Test-Path $EdgePolicyPath)) { New-Item -Path $EdgePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $EdgePolicyPath -Name "HideFirstRunExperience" -Value 1 -Type DWord
Set-ItemProperty -Path $EdgePolicyPath -Name "BrowserSignin" -Value 0 -Type DWord
Log "Edge first-run experience disabled."

# Disable News (all users)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0


# Disable hibernate
powercfg.exe /hibernate off

# Set sleep timeout to 'Never' for both AC (Plugged In) and DC (Battery)
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 0

# Set 'unattended sleep' timeout to 0 (prevents sleep after wake-on-lan or updates)
powercfg /setacvalueindex SCHEME_CURRENT 238c9fa8-0aad-41ed-83f4-97be242c8f20 7bc4a2f9-d8fc-4469-b07b-33eb785aaca0 0
powercfg /setdcvalueindex SCHEME_CURRENT 238c9fa8-0aad-41ed-83f4-97be242c8f20 7bc4a2f9-d8fc-4469-b07b-33eb785aaca0 0

# Set monitor timeout to 30 minutes
powercfg /change monitor-timeout-ac 30
powercfg /change monitor-timeout-dc 30

# Apply the changes
powercfg /setactive SCHEME_CURRENT





# -----------------------------
# Lock wallpaper and login screen background
# -----------------------------

if (!(Test-Path $WallpaperDir)) {
    New-Item -Path $WallpaperDir -ItemType Directory -Force | Out-Null
}

try {
    Invoke-WebRequest -Uri $WallpaperUrl -OutFile $WallpaperPath -UseBasicParsing
}
catch {
    Log "Failed to download wallpaper from $WallpaperUrl"
    Start-Sleep -Seconds 10
    exit 1
}


# Local GPO Policy Path
$PolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"

if (!(Test-Path $PolicyPath)) {
    New-Item -Path $PolicyPath -Force | Out-Null
}


Set-ItemProperty -Path $PolicyPath -Name "DesktopImagePath" -Value $WallpaperPath -Type String
Set-ItemProperty -Path $PolicyPath -Name "LockScreenImagePath" -Value $WallpaperPath -Type String

Set-ItemProperty -Path $PolicyPath -Name "DesktopImageStatus" -Value 1 -Type DWord
Set-ItemProperty -Path $PolicyPath -Name "LockScreenImageStatus" -Value 1 -Type DWord


# ---------------------------------------
# Download and install Secure Browser

$SecureBrowserInstallPaths = @(
    "C:\Program Files (x86)\Respondus\LockDown Browser Lab OEM",
    "C:\Program Files (x86)\Prometric\ProSecureClientLauncher",
    "C:\Users\Public\Surpass\SecureClient"
)

$SBInstalled = $false

foreach ($Path in $SecureBrowserInstallPaths) {
    if (Test-Path $Path) {
        Write-Host "Found existing installation at: $Path" -ForegroundColor Green
        $SBInstalled = $true
        break
    }
}

if ($SBInstalled) {

    Log "Secure Browser already installed, skipping..." -ForegroundColor Cyan

} else {

    Log "Downloading and installing Prometric Secure Browser (this will take a while)."

    try {
        Invoke-WebRequest -Uri $SecureBrowserURL -OutFile $SecureBrowserPath -UseBasicParsing
    }
    catch {
        Log "Failed to download Prometric Secure Browser from $SecureBrowserURL"
        Start-Sleep -Seconds 10
        exit 1
    }

    Start-Process -FilePath $SecureBrowserPath -ArgumentList "/quiet /qn /norestart" -Wait

    $SBDesktopShortcut = "C:\Users\Public\Desktop\LockDown Browser Lab OEM.lnk"

    if (Test-Path $SBDesktopShortcut) {
        Remove-Item -Path $SBDesktopShortcut -Force
        Write-Host "Shortcut removed successfully." -ForegroundColor Green
    } else {
        Write-Host "Shortcut not found; nothing to delete." -ForegroundColor Yellow
    }


}




# ----------------------------
# Download Deep Freeze


# Already running DF Cloud and thawed, so no need to install it
If ($dfState -eq "Thawed") {
    exit 0
}

try {
    Invoke-WebRequest -Uri $DeepFreezeURL -OutFile $DeepFreezePath -UseBasicParsing
}
catch {
    Log "Failed to download DeepFreeze from $DeepFreezeURL"
    Start-Sleep -Seconds 10
    exit 1
}





# Now configure the user to auto sign in (bypass first setup) -- This is reverted later
$WinlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

Set-ItemProperty -Path $WinlogonPath -Name "AutoAdminLogon" -Value "1"
Set-ItemProperty -Path $WinlogonPath -Name "DefaultUserName" -Value $UserName
Set-ItemProperty -Path $WinlogonPath -Name "DefaultPassword" -Value $Password




# Scheduled task to install Deep Freeze after next login
$PostScript = "C:\Windows\Temp\DFInstall.ps1"

@"
# Remove scheduled task
Unregister-ScheduledTask -TaskName "DFInstallTask" -Confirm:$false

# -> Disable AutoLogon <-
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "0"
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -ErrorAction SilentlyContinue

# Install Deep Freeze silently
Start-Process -FilePath "${DeepFreezePath}" -ArgumentList "/install" -Wait

# Optional reboot after install
Restart-Computer -Force
"@ | Set-Content -Path $PostScript -Encoding UTF8




# Register the task in scheduler
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$PostScript`""
$Trigger = New-ScheduledTaskTrigger -AtStartup

# Create the Principal using the SYSTEM account
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Register the task
Register-ScheduledTask `
    -TaskName "DFInstallTask" `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Force



Log "Restarting computer to sign in Student then install Deep Freeze" -ForegroundColor Cyan
Start-Sleep -Seconds 10
Restart-Computer -Force
