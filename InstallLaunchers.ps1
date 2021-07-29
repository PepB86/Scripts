$serverurl = "https://pbiwvdle.eastus.cloudapp.azure.com"
$LeRemoteFile = "https://pbiwvdstorage.blob.core.windows.net/files/launcher_win10_x64.zip?sp=r&st=2021-07-15T16:01:50Z&se=2022-05-31T00:01:50Z&spr=https&sv=2020-08-04&sr=b&sig=CL08FnN4EXUmXSUDtH46F5NvnptMAEDoNX2HvkRSxMg%3D"
$uname = "admin.pb"
$pw = "Jemoeder1Lgn1"
$domainWINS = "WORKGROUP"
$Secret = 'EDFEADA9E3C6C3CE0E5B12C1A74FA0991434659E'

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Set variables and start logging
$TempFolder = Join-Path $Env:TEMP "LoginEnterprise"

# Create necessary folders and cleanup existing folders if present
if (!([System.IO.Directory]::Exists($TempFolder))) {
    New-Item -ItemType Directory -Force $TempFolder
}

$LeFolder = (Get-Item -Path $TempFolder).FullName
$LeZip = Join-Path $LeFolder "Logon.zip"
$LauncherInstall = Join-Path $LeFolder "Setup.msi"

if ([System.IO.Directory]::Exists($LeFolder)) {
    Remove-Item -Recurse -Force $LeFolder
}
New-Item -ItemType Directory -Force $LeFolder

if ([System.IO.File]::Exists($LeZip)) {
    Remove-Item -Recurse -Force $LeZip
}

# Download, unzip and start engine
$attemptsCount = 0
$maxAttemptsCount = 30
$succeeded = $false
$retryInterval = 2 #seconds

Write-Output "Downloading Launcher Installation from '$LeRemoteFile'..."
while (!$succeeded) {
    try {
        $attemptsCount++

        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile($LeRemoteFile, $LeZip)
        (new-object -com shell.application).namespace($LeFolder).CopyHere((new-object -com shell.application).namespace($LeZip).Items(), 0x14);
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

        $succeeded = $true
        Write-Output "Engine downloaded succesfully"
    }
    catch {
        if ($attemptsCount -lt $maxAttemptsCount) {
            Write-Output "Attempt $attemptsCount failed. Reason: $_"
            Write-Output "Waiting for $retryInterval seconds and will try again"
            start-sleep -seconds $retryInterval
        }
        else {
            Write-Output "All attempts failed."
            break
        }
    }
}


if ((Test-Path "C:\Program Files\Login VSI\Login PI 3 Launcher\LoginPI.Launcher.exe" ) -eq $false) {

    $MSIArguments = @(
        "/i"
        $LauncherInstall
        "/qb!"
        "Serverurl=$Serverurl"
        "Secret=$Secret"
    )
    Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait
}


# Check if launcher is already autorunning, if it isn't set it to autorun
If ($null -eq (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name "LoginEnterpriseLauncher" -ea silent)) {
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name "LoginEnterpriseLauncher" -Value "C:\Program Files\Login VSI\Login PI 3 Launcher\Console\LoginPI.Launcher.Console.exe" -Force
    #Restart-Computer -Force
}

# Set the launcher machine to autologon with admin account
Set-ItemProperty -Path "HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 1 -Force
Set-ItemProperty -Path "HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value $uname -Force
Set-ItemProperty -Path "HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value $pw -Force		
Set-ItemProperty -Path "HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultDomainName" -Value $domainWINS -Force
Set-ItemProperty -Path "HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoLogonCount" -Value 999 -Force
Remove-ItemProperty -Path "HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoLogonSID" -Force -Erroraction silentlycontinue


# Run the MSFT VDI optimizer
if (-not (Test-Path "C:\VDIOptimizer")) {
    Invoke-WebRequest -OutFile "C:\VDIOptimizer.zip" -Uri "https://github.com/blairparkhill/WVDConnect/raw/master/Virtual-Desktop-Optimization-Tool-master.zip"
    Expand-Archive -Path "C:\VDIOptimizer.zip" -DestinationPath "C:\VDIOptimizer\"
    Start-Process -FilePath C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe '-ExecutionPolicy RemoteSigned -File "C:\VDIOptimizer\Virtual-Desktop-Optimization-Tool-master\Win10_VirtualDesktop_Optimize.ps1" -WindowsVersion 2004 -Verbose' -Wait
}


#REBOOT THE MACHINE
shutdown /r /t 0 /f