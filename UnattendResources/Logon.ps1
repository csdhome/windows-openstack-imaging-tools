$ErrorActionPreference = "Stop"
$resourcesDir = "$ENV:SystemDrive\UnattendResources"
$configIniPath = "$resourcesDir\config.ini"


function LogErrors() {
    $date = Get-Date -uformat "%H:%M:%S"
    if ($error.Count -gt 0) {
        foreach ($err in $error) {
            "[$date][E] $err"
        }
        $error.Clear()
    }
}

function Set-PersistDrivers {
    Param(
    [parameter(Mandatory=$true)]
    [string]$Path,
    [switch]$Persist=$true
    )
    if (!(Test-Path $Path)){
        return $false
    }
    try {
        $xml = [xml](Get-Content $Path)
    }catch{
        Write-Error "Failed to load $Path"
        return $false
    }
    if (!$xml.unattend.settings){
        return $false
    }
    foreach ($i in $xml.unattend.settings) {
        if ($i.pass -eq "generalize"){
            $index = [array]::IndexOf($xml.unattend.settings, $i)
            if ($xml.unattend.settings[$index].component -and $xml.unattend.settings[$index].component.PersistAllDeviceInstalls -ne $Persist.ToString()){
                $xml.unattend.settings[$index].component.PersistAllDeviceInstalls = $Persist.ToString()
            }
        }
    }
    $xml.Save($Path)
}

function Clean-UpdateResources {
    $HOST.UI.RawUI.WindowTitle = "Running update resources cleanup"
    # We're done, disable AutoLogon
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name Unattend*
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoLogonCount

    # Cleanup
    Remove-Item -Recurse -Force $resourcesDir
    Remove-Item -Force "$ENV:SystemDrive\Unattend.xml"

}

function Clean-WindowsUpdates {
    $HOST.UI.RawUI.WindowTitle = "Running Dism cleanup..."
    if (([System.Environment]::OSVersion.Version.Major -gt 6) -or ([System.Environment]::OSVersion.Version.Minor -ge 2))
    {
        Dism.exe /Online /Cleanup-Image /StartComponentCleanup
        if ($LASTEXITCODE)
        {
            throw "Dism.exe clean failed"
        }
    }
}

function Run-Defragment {
    $HOST.UI.RawUI.WindowTitle = "Running Defrag..."
    #Defragmenting all drives at normal priority
    defrag.exe /C /H /V
    if ($LASTEXITCODE)
    {
        throw "Defrag.exe failed"
    }
}

function Release-IP {
    $HOST.UI.RawUI.WindowTitle = "Releasing IP..."
    ipconfig.exe /release
    if ($LASTEXITCODE)
        {
            throw "IPconfig release failed"
        }
}

function Install-Base-Dev-Languages {

    $Host.UI.RawUI.WindowTitle = "Set Execution Policy to Unrestricted"
    Set-ExecutionPolicy Unrestricted -Force

    $Host.UI.RawUI.WindowTitle =  "Disable UAC"
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value "0"


    $Host.UI.RawUI.WindowTitle =  "Installing PowerShell 4.0 (Requires .Net 4.0)"
    CMD /C START /WAIT wusa $resourcesDir\Windows6.1-KB2819745-x64-MultiPkg.msu /quiet /norestart
    Start-Sleep -Seconds 5
    $Host.UI.RawUI.WindowTitle =  "Finished Installing PowerShell 4.0"

}

function Set-PageFile-Size {
    $Host.UI.RawUI.WindowTitle =  "Set the pagefile size to 2 - 4 GB"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "C:\pagefile.sys 2048 4096"
    
}

function Configure-Firewall {
    $Host.UI.RawUI.WindowTitle =  "Set Firewall Rules"
    netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes
	netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv4-In)" new enable=yes
	netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv6-In)" new enable=yes
}

function Disable-NLA {
    $Host.UI.RawUI.WindowTitle = "Install Password Reset Utility"
    (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)
    LogErrors
}

function Run-Cleanup-Routines {
    $Host.UI.RawUI.WindowTitle = "Remove Temporary files"
    Remove-Item "C:\bootsect.bak" -Force | Log
    LogErrors

    $Host.UI.RawUI.WindowTitle = "Empty Recycle bin"
    $shell = New-Object -ComObject Shell.Application
    $rb = $shell.NameSpace(0xA)
    $rb.Items() | %{Remove-Item $_.Path -force}
    LogErrors
    
    $Host.UI.RawUI.WindowTitle = "Clear all event logs"
    wevtutil el | foreach { wevtutil cl "$_" }
    LogErrors
    
    Run-Defragment

    Clean-UpdateResources

    Release-IP
}

try
{
    Import-Module "$resourcesDir\ini.psm1"
    $installUpdates = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "InstallUpdates" -Default $false -AsBoolean
    $persistDrivers = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "PersistDriverInstall" -Default $true -AsBoolean

    if($installUpdates)
    {
        if (!(Test-Path "$resourcesDir\PSWindowsUpdate"))
        {
            #Fixes Windows Server 2008 R2 inexistent Unblock-File command Bug
            if ($(Get-Host).version.major -eq 2)
            {
                $psWindowsUpdatePath = "$resourcesDir\PSWindowsUpdate_1.4.5.zip"
            }
            else
            {
                $psWindowsUpdatePath = "$resourcesDir\PSWindowsUpdate.zip"
            }

            & "$resourcesDir\7za.exe" x $psWindowsUpdatePath $("-o" + $resourcesDir)
            if($LASTEXITCODE) { throw "7za.exe failed to extract PSWindowsUpdate" }
        }

        $Host.UI.RawUI.WindowTitle = "Installing updates..."

        Import-Module "$resourcesDir\PSWindowsUpdate"

        Get-WUInstall -AcceptAll -IgnoreReboot -IgnoreUserInput -NotCategory "Language packs"
        if (Get-WURebootStatus -Silent)
        {
            $Host.UI.RawUI.WindowTitle = "Updates installation finished. Rebooting."
            shutdown /r /t 0
            exit 0
        }
    }
    
    Clean-WindowsUpdates

    Install-Base-Dev-Languages

    $Host.UI.RawUI.WindowTitle = "Installing Cloudbase-Init..."
    
    $programFilesDir = $ENV:ProgramFiles

    $CloudbaseInitMsiPath = "$resourcesDir\CloudbaseInit.msi"
    $CloudbaseInitMsiLog = "$resourcesDir\CloudbaseInit.log"

    $serialPortName = @(Get-WmiObject Win32_SerialPort)[0].DeviceId

    $p = Start-Process -Wait -PassThru -FilePath msiexec -ArgumentList "/i $CloudbaseInitMsiPath /qn /l*v $CloudbaseInitMsiLog LOGGINGSERIALPORTNAME=$serialPortName"
    if ($p.ExitCode -ne 0)
    {
        throw "Installing $CloudbaseInitMsiPath failed. Log: $CloudbaseInitMsiLog"
    }
    
    $Host.UI.RawUI.WindowTitle = "Running SetSetupComplete..."
    & "$programFilesDir\Cloudbase Solutions\Cloudbase-Init\bin\SetSetupComplete.cmd"
    
    Set-PageFile-Size

    Disable-NLA

    Configure-Firewall

    Run-Cleanup-Routines

    $Host.UI.RawUI.WindowTitle = "Running Sysprep..."
    $unattendedXmlPath = "$programFilesDir\Cloudbase Solutions\Cloudbase-Init\conf\Unattend.xml"
    Set-PersistDrivers -Path $unattendedXmlPath -Persist:$persistDrivers
    & "$ENV:SystemRoot\System32\Sysprep\Sysprep.exe" `/generalize `/oobe `/shutdown `/unattend:"$unattendedXmlPath"
}
catch
{
    $host.ui.WriteErrorLine($_.Exception.ToString())
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    throw
}
