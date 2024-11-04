param (
    [Parameter(Mandatory=$false)][string]$command
 )

$SupportAssistType = $null
$SupportAssistTypeProgramData = $null
$SupportAssistService = $null
$SystemDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive
$winID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$winPrincipal=new-object System.Security.Principal.WindowsPrincipal($winID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
$DesktopPathSA = [System.Environment]::GetFolderPath("Desktop")
$DestinationPathSA = Join-Path $DesktopPathSA "SupportAssistLogs"

#region Common Funtions
function EnableDisableSADebugLog([string]$Status)
{
    $FilePath = "$SystemDrive\Program Files\Dell\$SupportAssistType\bin\SupportAssistAgent.exe.config" 
    $xml = [xml](Get-Content $FilePath)
    $nodes = ($xml.configuration.log4net.appender.filter.param)
    $debug = $null
    if($Status -eq "debugenable")
    {
        $debug = "Debug"
    }
    elseif($Status -eq "debugdisable")
    {
        $debug = "Info"
    }

    foreach ($node in $nodes)
    {
        if($node.name -eq 'LevelMin')
        {
            $node.value = $debug
            $xml.Save($FilePath)
        }
    }
}

function CheckForErrors()
{
    $ZipfilePath = Join-Path $DesktopPathSA -ChildPath "SupportAssistLogs.zip"
    if(-Not(Test-Path (Join-Path $DesktopPathSA "SupportAssistLogs")))
    {
        New-Item -Path $DesktopPathSA -Name "SupportAssistLogs" -ItemType "directory" | Out-Null
    }
    if(Test-Path -Path "$DestinationPathSA\Error.txt")
    {
        Remove-Item -Path "$DestinationPathSA\Error.txt" -Force
    }
    switch($SupportAssistType)
    {
        'SupportAssistAgent'
        { 
            if(Test-Path -Path "HKLM:SOFTWARE\DELL\SupportAssistBusinessClient")
            {
                "Support Assist Business Client edition found in registry" | Out-File "$DestinationPathSA\Error.txt" -Append
            }
            if(Test-Path -Path "HKLM:SOFTWARE\DELL\SupportAssist ProManage")
            {
                "Support Assist Promanage edition found in registry" | Out-File "$DestinationPathSA\Error.txt" -Append
            }
        }
        'SupportAssistBusinessClient'
        {
           if(Test-Path -Path "HKLM:SOFTWARE\DELL\SupportAssistAgent")
           {
                "Support Assist Consumer edition found in registry" | Out-File "$DestinationPathSA\Error.txt" -Append
           }
           if(Test-Path -Path "HKLM:SOFTWARE\DELL\SupportAssist ProManage")
           {
                "Support Assist Promanage edition found in registry" | Out-File "$DestinationPathSA\Error.txt" -Append
           } 
        }
        'SupportAssist ProManage'
        {
            if(Test-Path -Path "HKLM:SOFTWARE\DELL\SupportAssistBusinessClient")
            {
                "Support Assist Business Client edition found in registry" | Out-File "$DestinationPathSA\Error.txt" -Append
            }
            if(Test-Path -Path "HKLM:SOFTWARE\DELL\SupportAssistAgent")
            {
                "Support Assist Consumer edition found in registry" | Out-File "$DestinationPathSA\Error.txt" -Append
            }
        }
        default
        {
            if(Test-Path -Path "HKLM:SOFTWARE\DELL\SupportAssistBusinessClient")
            {
                "Support Assist Business Client edition found in registry" | Out-File "$DestinationPathSA\Error.txt" -Append
            }
            if(Test-Path -Path "HKLM:SOFTWARE\DELL\SupportAssistAgent")
            {
                "Support Assist Consumer edition found in registry" | Out-File "$DestinationPathSA\Error.txt" -Append
            }
            if(Test-Path -Path "HKLM:SOFTWARE\DELL\SupportAssist ProManage")
            {
                "Support Assist Promanage edition found in registry" | Out-File "$DestinationPathSA\Error.txt" -Append
            }
        }

    }
    Add-Type -AssemblyName "System.IO.Compression.Filesystem"
    [IO.Compression.Zipfile]::CreateFromDirectory($DestinationPathSA, $ZipfilePath)
    Remove-Item -Path "$DestinationPathSA" -Recurse -Force
}
#endregion

if((Test-Path -Path "HKLM:SOFTWARE\DELL\SupportAssistAgent") -and (Get-Service "SupportAssistAgent" -ErrorAction SilentlyContinue))
{
    $SupportAssistType = "SupportAssistAgent"
    $SupportAssistTypeProgramData = "SupportAssist"
    $SupportAssistService = "SupportAssistAgent"
}
elseif((Test-Path -Path "HKLM:SOFTWARE\DELL\SupportAssistBusinessClient") -and (Get-Service "SupportAssistSvc" -ErrorAction SilentlyContinue))
{
    $SupportAssistType = "SupportAssistBusinessClient"
    $SupportAssistTypeProgramData = "SupportAssistBusinessClient"
    $SupportAssistService = "SupportAssistSvc"

}
elseif((Test-Path -Path "HKLM:SOFTWARE\DELL\SupportAssist ProManage") -and (Get-Service "SupportAssistSvc" -ErrorAction SilentlyContinue))
{
    $SupportAssistType = "SupportAssist ProManage"
    $SupportAssistTypeProgramData = "SupportAssist ProManage"
    $SupportAssistService = "SupportAssistSvc"
}
else
{
    Write-Host "Exiting the script as Support Assist information is not found in registry" -ForegroundColor Red
    CheckForErrors
    Exit
}


#region Function related to command CollectInfo
function GetBasicInformation()
{
    #SupportAssistLogs is the folder in dektop which collects all the logs and finally will be zipped.
    #If folder does not exists create one. 
    if(-Not(Test-Path (Join-Path $DesktopPathSA "SupportAssistLogs")))
    {
        New-Item -Path $DesktopPathSA -Name "SupportAssistLogs" -ItemType "directory" | Out-Null
    }

    #OS_BIOS_Info is the text file which has OS and BIOS information. If the file exists delete it and create it once agian.
    if(Test-Path -Path "$DestinationPathSA\OS_BIOS_Info.txt")
    {
        Remove-Item -Path "$DestinationPathSA\OS_BIOS_Info.txt" -Force
    }
    
    #Create the file and write the details to the console.
    $BasicOSInfo = Get-CimInstance Win32_OperatingSystem | select Caption, Version, OSArchitecture, CSName | Tee-Object -FilePath "$DestinationPathSA\OS_BIOS_Info.txt" -Append
    $BIOSInfo = Get-CimInstance Win32_BIOS | select SMBIOSBIOSVersion, ReleaseDate, SerialNumber | Tee-Object -FilePath "$DestinationPathSA\OS_BIOS_Info.txt" -Append
    $CompInfo = Get-CimInstance Win32_ComputerSystem | select Model,Manufacturer | Tee-Object -FilePath "$DestinationPathSA\OS_BIOS_Info.txt" -Append
    $CurrentUser = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
    $IsUserAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    "User : $CurrentUser" | Out-File "$DestinationPathSA\OS_BIOS_Info.txt" -Append
    "IsAdmin : $IsUserAdmin" | Out-File "$DestinationPathSA\OS_BIOS_Info.txt" -Append
    
    "`r`nInternet Connection Check" | Out-File "$DestinationPathSA\OS_BIOS_Info.txt" -Append
    Test-NetConnection -Port 80 -InformationLevel Detailed| Out-File "$DestinationPathSA\OS_BIOS_Info.txt" -Append
}
#endregion

#region Function related to command CheckStatus
function GetServiceStatus([string]$ServiceName, [string]$ServiceDisplayName)
{
    if(Get-Service $ServiceName -ErrorAction SilentlyContinue)
    {
        $status = (Get-Service $ServiceName).Status
        return $status
    }
    else
    {
        return "Unable to get the status of '$ServiceDisplayName' service. Service does not exists"
    }
}

function GetExecutableVersions([string]$ExeName,[string]$ExePath)
{
    $SAExePath = "$SystemDrive\Program Files\Dell\$SupportAssistType\bin\SupportAssistAgent.exe"
    $SAInstallerExePath = "$SystemDrive\Program Files\Dell\$SupportAssistType\bin\SupportAssistInstaller.exe"
    $PcDrFolderName = (Get-ChildItem -Path "$SystemDrive\Program Files\Dell\$SupportAssistType\PCDr\SupportAssist" -Directory).Name
    $PcDrExePath = "$SystemDrive\Program Files\Dell\$SupportAssistType\PCDr\SupportAssist\$PcDrFolderName\DSAPI.exe"
    $SREExePath = "$SystemDrive\Program Files\Dell\$SupportAssistType\SRE\SRE.exe"
    $DDVCollectorExePath = "$SystemDrive\Program Files\Dell\DellDataVault\DDVDataCollector.exe"
    $DDVProcessorExePath = "$SystemDrive\Program Files\Dell\DellDataVault\DDVRulesProcessor.exe"
    $DDVServiceAPiExecPath ="$SystemDrive\Program Files\Dell\DellDataVault\DDVCollectorSvcApi.exe"
    $BradburyExePath = "$SystemDrive\Program Files (x86)\Dell\UpdateService\ServiceShell.exe"

    $table = New-Object system.Data.DataTable “SAExecutables”
    #Define Columns
    $col1 = New-Object system.Data.DataColumn ExecutableName,([string])
    $col2 = New-Object system.Data.DataColumn Version,([string])
    $col3 = New-Object system.Data.DataColumn Signature,([string])
    $col4 = New-Object system.Data.DataColumn SignatureStatus,([string])
    #Add the Columns
    $table.columns.add($col1)
    $table.columns.add($col2)
    $table.columns.add($col3)
    $table.columns.add($col4)

    
    #Create hash with Executables names and their respective paths
    $ExeNamePathHash = @{
        'SupportAssistAgent' = $SAExePath
        'SupportAssist Installer' = $SAInstallerExePath
        'PcDr' = $PcDrExePath
        'SRE' = $SREExePath
        'DDV DataCollector' = $DDVCollectorExePath
        'DDV RulesProcessor' = $DDVProcessorExePath
        'DDV CollectorSvcApi' = $DDVServiceAPiExecPath
        'Dell Update' = $BradburyExePath
    }

    foreach($key in $ExeNamePathHash.keys)
    {
        $row = $table.NewRow()
        $row.ExecutableName = $key
        if(Test-Path -Path $ExeNamePathHash[$key])
        {
            $row.Version = (Get-Item $ExeNamePathHash[$key]).VersionInfo.ProductVersion
            $row.Signature = ((Get-AuthenticodeSignature $ExeNamePathHash[$key]).signercertificate.subject -split ',*..=')[1]
            $row.SignatureStatus = (Get-AuthenticodeSignature $ExeNamePathHash[$key]).status
        }
        else
        {
            $row.Version = "Not Found"
        }
        
        $table.Rows.Add($row)
    }

    #Display the table
    $table | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append
}

function SupportAssistBasicCheck()
{

    #SupportAssistLogs is the folder in dektop which collects all the logs and finally will be zipped.
    #If folder does not exists create one. 
    if(-Not(Test-Path (Join-Path $DesktopPathSA "SupportAssistLogs")))
    {
        New-Item -Path $DesktopPathSA -Name "SupportAssistLogs" -ItemType "directory" | Out-Null
    }

    #Service_Executable_Status is the text file which has Services and Executables information. If the file exists delete it and create it once agian.
    if(Test-Path -Path "$DestinationPathSA\Service_Executable_Status.txt")
    {
        Remove-Item -Path "$DestinationPathSA\Service_Executable_Status.txt" -Force
    }
   

    #region Get SA related services status and write to console and log

    "Support Assist related services...." | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append
    "----------------------------------------------------------" | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append  
    
    
    $sa = GetServiceStatus "$SupportAssistService" "Dell SupportAssist"
    $dh = GetServiceStatus "Dell Hardware Support" "Dell Hardware Support"
    $ddvd = GetServiceStatus "DDVDataCollector" "Dell Data Valut Collector"
    $ddvr = GetServiceStatus "DDVRulesProcessor" "Dell Data Vault Processor"
    $ddvc = GetServiceStatus "DDVCollectorSvcApi" "Dell Data Vault Service API"
    $du = GetServiceStatus "DellClientManagementService" "Dell Update"

    #Write Services status to text file
    "SupportAssistAgent : $sa`r`nDell Hardware Support : $dh`r`nDell Data Valut Collector : $ddvd`r`nDell Data Vault Processor : $ddvr`r`nDell Data Vault Service API : $ddvc`r`nDell Update : $du" | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append
    
    #endregion
    
    #region Get the version of all the executables and write to console and log
    
    #Write to file
    "`r`n----------------------------------------------------------" | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append
    "Executables Version Information" | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append
    "----------------------------------------------------------"  | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append

    #Function call to get the versions of exes - SA, SA Installer, PCDr, SRE, Dell Update etc
    GetExecutableVersions

    #endregion
    
    #region Get the Appx information and write to console and log

    "----------------------------------------------------------" | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append
    "Appx Information" | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append
    "----------------------------------------------------------" | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append
   
    $AppxPackageName = "DellInc.DellSupportAssistforPCs_htrsf667h5kn2"
    $GetAppxDetails = Get-AppxPackage -AllUsers | Where-Object {$_.packagefamilyname -eq $AppxPackageName} | select PackageFullName, PackageUserInformation, Dependencies
    $GetProvisionedPackage = Get-AppxProvisionedpackage -online | Where-Object {$_.PackageName -eq $GetAppxDetails.PackageFullName}

    if($GetAppxDetails -eq $null)
    {
        Write-Host "$AppxPackageName is not installed" -ForegroundColor Red
        "Appx Status : $AppxPackageName is not installed" | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append
    } 
    else 
    {
        foreach($appx in $GetAppxDetails)
        {
            $Dependencies = ($appx.Dependencies | Select Name, PackageFullName, Version | Format-Table | Out-String)
            $AppxUser = ($appx).PackageUserInformation
        }
        $AppxOutput = "Name : " + $GetProvisionedPackage.DisplayName + "`r`nVersion : " + $GetProvisionedPackage.Version + "`r`nPublisher Id :" + $GetProvisionedPackage.PublisherId | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append
        "Appx User Install Status : $AppxUser" | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append
        "Dependencies : $Dependencies" | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append
    }
    #endregion    

    $SAProgramFilePath = "$SystemDrive\Program Files\Dell\$SupportAssistType"
    $AgentPath = "$SystemDrive\ProgramData\$SupportAssistTypeProgramData\Client\Agent"
    $dbPath = "$SystemDrive\ProgramData\$SupportAssistTypeProgramData\Client\Agent\db\SupportAssist.db"
    if(Test-Path -Path $dbPath)
    {
        "Support Assist database exists in the location - True" | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append
    }
    else
    {
        "Support Assist database exists in the location - False" | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append
    }
    
    if(Get-ItemProperty "HKLM:SOFTWARE\DELL\$SupportAssistType" -ErrorAction SilentlyContinue)
    {
        if((Get-Item "HKLM:SOFTWARE\DELL\$SupportAssistType").GetValue("key") -eq $null){ "The 'Key' value is empty in registry" | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append} else {"The 'Key' value is present in registry" | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append}
        
    }
    else
    {
        "Registry does not exists" | Out-File "$DestinationPathSA\Service_Executable_Status.txt" -Append
    }
    
}
#endregion

#region Function related to command EnableDebug
function EnableDebugLog()
{
    $foldername = (Get-ChildItem -Path "$SystemDrive\Program Files\Dell\$SupportAssistType\PCDr\SupportAssist" -Directory).Name
    #Loggrabber.exe path
    $LoggrabberPath = "$SystemDrive\Program Files\Dell\$SupportAssistType\PCDr\SupportAssist\$foldername\LogGrabber.exe"
    
    #Stop services to allow Loggrabber to clear error logs
	if(Get-Service $SupportAssistService -ErrorAction SilentlyContinue)
    {
        Stop-Service -Name $SupportAssistService -ErrorAction SilentlyContinue
        if(Test-Path -Path "$SystemDrive\Program Files\Dell\$SupportAssistType\PCDr\SupportAssist\$foldername\LogGrabber.exe")
	    {
            if(Get-Service "Dell Hardware Support" -ErrorAction SilentlyContinue)
            {
			    Stop-Service "Dell Hardware Support" -ErrorAction SilentlyContinue
		    }
		    else
		    {
			    Write-Host "Dell Hardware Support service does not exist"
		    }
            #Execute the loggrabber exe. This will clear the old logs and change the log level to Debug mode for PCDr
			Start-Process -FilePath $LoggrabberPath -ArgumentList "--adjust-loglevel-wick Debug --adjust-loglevel-native Debug --no-collect --clear-logs" -NoNewWindow -Wait
            #Restart PCDr service
			Start-Service -Name "Dell Hardware Support" -ErrorAction SilentlyContinue
		}
        else
	    {
		    Write-Host "Loggrabber.exe does not exist."
	    }	
			
		Start-Sleep -s 10
		   
		#Modify SAA config file for debug logging
		EnableDisableSADebugLog("debugenable")
			
		#Restart SAA Service
		Start-Service -Name $SupportAssistService -ErrorAction SilentlyContinue	
		Start-Sleep -s 10			
	}
    else
    {
        Write-Host "SupportAssist service does not exist"
    }
    
}
#endregion

#region Functions related to command CollectLogs

function CollectInformationAndLogs()
{
    #Call this function to show the basic information - OS, OS version, Service Tag etc..
    Write-Host "Collecting Support Assist information and writing the logs to $DestinationPathSA" 
    GetBasicInformation
    #Calls this function to show the Support Assist related basic checks -  Services status of SA, Bradbury, Dell Hardware etc
    SupportAssistBasicCheck
    Write-Host "Completed"
    #Collects all the logs - SA, PCDr, SRE, TTK, Bradbury, Clickfeed, Regitry etc.. Also collects the eventlog information
    Write-Host "Collecting Support Assist related logs and writing it to $DestinationPathSA"
    CollectAllLogs
    Write-Host "Completed"

    $ZipfilePath = Join-Path $DesktopPathSA -ChildPath "SupportAssistLogs.zip"
    if(Test-Path -Path $ZipfilePath)
    {
        Remove-Item -Path "$ZipfilePath" -Recurse -Force
    }

    CheckForErrors
    Write-Host "$ZipfilePath  is created" -ForegroundColor Green
}


function CollectAllLogs()
{
    if(-Not(Test-Path ($DestinationPathSA)))
    {
        New-Item -Path ($DestinationPathSA) -ItemType "directory" | Out-Null
    }

    CollectLogFiles
    CollectEventLogs
}

function CollectLogFiles()
{

    $SALogSource = "$SystemDrive\ProgramData\$SupportAssistTypeProgramData\Client\Agent\logs\ApplicationLogs"
    $PcDrLogSource = "$SystemDrive\ProgramData\PCDr"
    $PcDrInstallerLogSource = "$SystemDrive\ProgramData\PCDr\Installer\Logs"
    $BradburyLogSource = "$SystemDrive\ProgramData\Dell\UpdateService\Log"
    $BradburyIC = "$SystemDrive\ProgramData\dell\InventoryCollector\Log\ICDebugLog.txt"
    $SRELogSource = "$SystemDrive\ProgramData\$SupportAssistTypeProgramData\Client\SRE"
    $DDVLogSource = "$SystemDrive\ProgramData\Dell\DellDataVault\Archive"
    $DDVSource = "$SystemDrive\ProgramData\Dell\DellDataVault\Log"
    $SRETTKLogSource = "$SystemDrive\ProgramData\$SupportAssistTypeProgramData\Client\TechnicianToolkit\Library"
    $SADBSource = "$SystemDrive\ProgramData\$SupportAssistTypeProgramData\Client\Agent\db"
    $ClickStreamLogSource = "$SystemDrive\ProgramData\$SupportAssistTypeProgramData\Client\Agent\ClickFeed"
    $RegistryPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\DELL\$SupportAssistType"
    $AppxPackageName = "DellInc.DellSupportAssistforPCs_htrsf667h5kn2" 
    $AppxLogSource =  "$env:USERPROFILE\AppData\Local\Packages\$AppxPackageName\LocalState"
    $WPFUILog = "$SystemDrive\Windows\Temp\SupportAssistAgent\UILogs"
    $CDMLogs = "$SystemDrive\ProgramData\$SupportAssistTypeProgramData\Client\CDM"
    $ExcaliburLogs = "$SystemDrive\ProgramData\Dell\saremediation\log"
    

    $DesktopPath = [System.Environment]::GetFolderPath("Desktop")
    $SALogDestination = Join-Path $DesktopPath "SupportAssistLogs\SALogs"
    $PcDrLogDestination = Join-Path $DesktopPath "SupportAssistLogs\PcDrLogs"
    $PCDrInstallerLogDestination = Join-Path -Path $PcDrLogDestination -ChildPath "PcDrInstallerLogs"
    $BradburyLogDestination = Join-Path $DesktopPath "SupportAssistLogs\DellUpdateLogs"
    $SRELogDestination = Join-Path $DesktopPath "SupportAssistLogs\SRELogs"
    $DDVLogDestination = Join-Path $DesktopPath "SupportAssistLogs\DDVLogs"
    $SRETTKLogDestination = Join-Path $DesktopPath "SupportAssistLogs\SRETTKLogs"
    $SADBDestination = Join-Path $DesktopPath "SupportAssistLogs\Db"
    $ClickStreamDestination = Join-Path $DesktopPath "SupportAssistLogs\ClickFeed"
    $AppxLogDestination = Join-Path $DesktopPath "SupportAssistLogs\AppxLogs"
    $WPFUILogDestination = Join-Path $DesktopPath "SupportAssistLogs\WPFUILogs"
    $CDMLogDestination = Join-Path $DesktopPath "SupportAssistLogs\CDMLogs"
    $ExcaliburLogDestination = Join-Path $DesktopPath "SupportAssistLogs\ExcaliburLogs"

    $DestinationPath = Join-Path $DesktopPath "SupportAssistLogs"
    $ZipFilePath = [System.Environment]::GetFolderPath("Desktop")

    if(Test-Path $ExcaliburLogs)
    {
        #Collecting Excalibur log files
        Write-Host "Collecting Excalibur log files..."
        Copy-Item $ExcaliburLogs -Destination $ExcaliburLogDestination -Recurse -Force
    }
    
    if(Test-Path $CDMLogs)
    {
        #Collecting CDM log files
        Write-Host "Collecting CDM log files..."
        Copy-Item $CDMLogs -Destination $CDMLogDestination -Recurse -Force
    }


    if(Test-Path $WPFUILog)
    {
        #Collecting WPF UI log files
        Write-Host "Collecting WPF UI log files..."
        Copy-Item $WPFUILog -Destination $WPFUILogDestination -Recurse -Force
    }

    if(Test-Path $AppxLogSource)
    {
        #Collecting Appx log files
        Write-Host "Collecting Appx log files..."
        Copy-Item $AppxLogSource -Destination $AppxLogDestination -Recurse -Force
    }

    if(Test-Path $SALogSource)
    {
        #Collect SupportAssist log files and Db
        Write-Host "Collecting SupportAssist log files..."
        Copy-Item $SALogSource -Destination $SALogDestination -Recurse -Force 
    }

    $foldername = (Get-ChildItem -Path "$SystemDrive\Program Files\Dell\$SupportAssistType\PCDr\SupportAssist" -Directory).Name
    #Loggrabber.exe path
    $LoggrabberPath = "$SystemDrive\Program Files\Dell\$SupportAssistType\PCDr\SupportAssist\$foldername\LogGrabber.exe"
	if (-not (Test-Path $PCDrLogDestination))
	{
		try 
		{
			New-Item -Path $PCDrLogDestination -ItemType Directory -ErrorAction Stop | Out-Null #-Force
		}
		catch 
		{
			Write-Error -Message "Unable to create directory '$PCDrLogDestination'. Error was: $_" -ErrorAction Stop
		}
		#Write-Host "Successfully created directory '$PCDrLogDestination'."
	}
	

	if((Test-Path $PCDrLogDestination) -And (Test-Path -Path $LoggrabberPath))
	{
		#Collect PCDr log files
		Write-Host "Collecting PCDr log files..."
		#Execute the loggrabber exe. This will clear the old logs and change the log level to Debug mode for PCDr
		Start-Process -FilePath $LoggrabberPath -ArgumentList "--collect-outputzip-filename $PCDrLogDestination\PCDR_LOGS.zip" -NoNewWindow -Wait
	}
	else
	{
        #Collect PCDr log files
		Write-Host "Using fallback method to collect PCDr log files..."
        if(Test-Path $PcDrLogSource)
        {
            #Collect PCDr log files
            Write-Host "Collecting PcDr log files..."
            $foldername = 0
            $dirs = Get-ChildItem $PcDrLogSource -Directory
            foreach($dir in $dirs)
            {
               if($dir.Name -match '^\d+$' -and $foldername -lt $dir.Name)
               {
                    $foldername = $dir.Name
               }
            }
            $PcDrFolderName = Join-Path -Path $PcDrLogSource -ChildPath "$foldername\Logs"
            Copy-Item $PcDrFolderName -Destination $PcDrLogDestination -Recurse -Force

        }
    }


    if(Test-Path $PcDrInstallerLogSource)
    {
        $installerLog = Join-Path -Path $PcDrInstallerLogSource -ChildPath "installer.log"
        if(Test-Path $installerLog)
        {
           Copy-Item $PcDrInstallerLogSource -Destination $PCDrInstallerLogDestination -Recurse -Force
        }
    }

     
    if(Test-Path $BradburyLogSource)
    {
        #Collect DellUpdate log files
        
        Write-Host "Collecting DellUpdate log files..."
        Copy-Item $BradburyLogSource -Destination $BradburyLogDestination  -Recurse -Force
        Copy-Item $BradburyIC -Destination $BradburyLogDestination
        $BradburyInventoryCollector =  "$SystemDrive\Program Files (x86)\Dell\UpdateService\Service\InvColPC.exe"
        $StaticFile = Join-Path $BradburyLogDestination "StaticIC.xml"
        Start-Process -FilePath $BradburyInventoryCollector -ArgumentList "-sic -outc=$StaticFile" -NoNewWindow -Wait
    }
    if(Test-Path $SRELogSource)
    {
        #Collect SRE log files
        Write-Host "Collecting SRE log files..."
        Copy-Item $SRELogSource -Destination $SRELogDestination  -Recurse -Force
        #Remove Localdb folder from collection
        $sredeletefolder = Join-Path "$SRELogDestination" -ChildPath "LocalDB"
        if(Test-Path $sredeletefolder)
        {
            Remove-Item $sredeletefolder -Recurse -Force
        }
    }
    if(Test-Path $DDVLogSource)
    {
       #Collect DDV log files
       Write-Host "Collecting DDV log files..."
       $DDVFileExtn = "*.xml"
       $DDVFileName = Join-Path -Path $DDVLogSource -ChildPath $DDVFileExtn
       if(-Not(Test-Path -Path "$DDVLogDestination"))
       {
            New-Item -Path $DDVLogDestination -ItemType Directory | Out-Null
       }
       Get-ChildItem $DDVFileName -File | Sort-Object -Property CreationTime -Descending | Select-Object -First 2 | Copy-Item -Destination $DDVLogDestination  -Recurse -Force
       Copy-Item $DDVSource -Destination $DDVLogDestination -Recurse -Force
    }
    if(Test-Path $SRETTKLogSource)
    {
        #Collect SRE TTK log files
        Write-Host "Collecting TTK log files..."
        Copy-Item $SRETTKLogSource -Destination $SRETTKLogDestination  -Recurse -Force
        #Remove Images folder from collection
        $ttkdeletefolder = Join-Path $SRETTKLogDestination -ChildPath "Images"
        if(Test-Path $ttkdeletefolder)
        {
            Remove-Item $ttkdeletefolder -Recurse -Force
        }
    }
    if(Test-Path $SADBSource)
    {
        Write-Host "Collecting SupportAssist Db files..."
        Copy-Item $SADBSource -Destination $SADBDestination -Recurse -Force
    }
    if(Test-Path $ClickStreamLogSource)
    {
        #Collect ClickFeed log files
        Write-Host "Collecting ClickFeed log files..."
        $ClickfeedFileExtn = "*.zip"
        $ClickFileName = Join-Path -Path $ClickStreamLogSource -ChildPath $ClickfeedFileExtn
        
        if(Test-Path $ClickFileName)
        {
            if(-Not(Test-Path -Path "$ClickStreamDestination"))
            {
                New-Item -Path $ClickStreamDestination -ItemType Directory | Out-Null
            }
            Get-ChildItem $ClickFileName -File | Sort-Object -Property CreationTime -Descending | Select-Object -First 1 | Copy-Item -Destination $ClickStreamDestination -Recurse -Force
        }
    }

    #Collect SupportAssist Registry
    Write-Host "Collecting SupportAssist registry - $RegistryPath"
    if(-Not(Test-Path -Path "$DestinationPath\RegistryEntry"))
    {
         New-Item -Path (Join-Path $DestinationPath "RegistryEntry") -ItemType Directory | Out-Null
    }
    
    $RegFileName = "RegistryEntry\SARegistry.txt"
    $RegistryPathDestination = Join-Path -Path $DestinationPath -ChildPath $RegFileName

    if(Get-ItemProperty -Path $RegistryPath -ErrorAction SilentlyContinue)
    {
        $reg = Get-ItemProperty -Path $RegistryPath
        $regoutput = $reg.PSObject.Properties | ForEach-Object{
        if($_.name -like "key" -or $_.name -like "PSPath" -or $_.name -like "PSParentPath" -or $_.name -like "PSChildName" -or $_.name -like "PSProvider")
        {        }
        else
        {
            Write-Output ($_.Name + "  =  " + $_.Value)
        }
    }

        $Regoutput | Out-File -FilePath $RegistryPathDestination
    }
    else
    {
        Write-Host "Registry does not exists"   
    }
}

function EventLogs([Object] $EventLogSource)
{
    $output = foreach($log in $EventLogSource)
    {
        Write-Output ("RecordId : " + $log.RecordId)
        Write-Output ("Time Created : " + $log.TimeCreated.DateTime)
        Write-Output ("EventId : " + $log.Id)
        Write-Output ("Level : " + $log.LevelDisplayName)
        Write-Output ("Log Name : " + $log.LogName)
        Write-Output ("ProcessId : " + $log.ProcessId)
        Write-Output ("ThreadId : " + $log.ThreadId)
        Write-Output ("Message : " + $log.Message)
        Write-Output "---------------------------------------------------------------------------------------------------------"
    }
    return $output
}

function CollectEventLogs()
{
    $EventLogName = $null
    $EventLogProvider = $null
    $LogOutput = $null
    $Extn = ".txt"
    $ApplicationName = "Supportassist"
    $DesktopPath = [System.Environment]::GetFolderPath("Desktop")
    $DestinationPath = Join-Path $DesktopPath "SupportAssistLogs\EventLogs"

    if(-not(Test-Path -Path $DestinationPath))
    {
        New-Item -Path $DestinationPath -ItemType Directory | Out-Null
    }

    #Collect SupportAssist Eventlogs
    Write-Host "Collecting SupportAssist event logs..." 
    $EventLogName = "SupportAssist"
    $EventLogProvider = Get-WinEvent -FilterHashtable @{ProviderName='*' + $EventLogName + '*'}
    $LogOutput = EventLogs($EventLogProvider)
    $filename = $EventLogName + $Extn
    $LogOutput | Out-File (Join-Path -Path $DestinationPath -ChildPath $filename)

    #Collect MSIInstaller Eventlogs
    Write-Host "Collecting SupportAssist installer event logs..."
    $EventLogName = "MsiInstaller"
    $EventLogProvider = Get-WinEvent -FilterHashtable @{ProviderName='*' + $EventLogName + '*'} | Where-Object -Property Message -Match $ApplicationName
    $LogOutput = EventLogs($EventLogProvider)
    $filename = $EventLogName + $Extn
    $LogOutput | Out-File (Join-Path -Path $DestinationPath -ChildPath $filename)


    #Collect DellUpdate Eventlogs
    Write-Host "Collecting DellUpdate event logs..."
    $EventLogName = "DellClientManagementService"
    $EventLogProvider = Get-WinEvent -FilterHashtable @{ProviderName='*' + $EventLogName + '*'}
    $LogOutput = EventLogs($EventLogProvider)
    $filename = $EventLogName + $Extn
    $LogOutput | Out-File (Join-Path -Path $DestinationPath -ChildPath $filename)

    #Collect Microsoft-Windows-AppModel-Runtime Eventlogs
    Write-Host "Collecting SupportAssist event logs from Microsoft-Windows-AppModel-Runtime..."
    $EventLogName = "Microsoft-Windows-AppModel-Runtime"
    $EventLogProvider = Get-WinEvent -FilterHashtable @{ProviderName='*' + $EventLogName + '*'} | Where-Object -Property Message -Match $ApplicationName
    $LogOutput = EventLogs($EventLogProvider)
    $filename = $EventLogName + $Extn
    $LogOutput | Out-File (Join-Path -Path $DestinationPath -ChildPath $filename)
    
    #Collect Microsoft-Windows-AppXDeployment Eventlogs
    Write-Host "Collecting SupportAssist event logs from Microsoft-Windows-AppXDeployment..."
    $EventLogName = "Microsoft-Windows-AppXDeployment"
    $EventLogProvider = Get-WinEvent -FilterHashtable @{ProviderName='*' + $EventLogName + '*'} | Where-Object -Property Message -Match $ApplicationName
    $LogOutput = EventLogs($EventLogProvider)
    $filename = $EventLogName + $Extn
    $LogOutput | Out-File (Join-Path -Path $DestinationPath -ChildPath $filename)

    #Collect Microsoft-Windows-AppReadiness Eventlogs
    Write-Host "Collecting SupportAssist event logs from Microsoft-Windows-AppReadiness..."
    $EventLogName = "Microsoft-Windows-AppReadiness"
    $EventLogProvider = Get-WinEvent -FilterHashtable @{ProviderName='*' + $EventLogName + '*'} | Where-Object -Property Message -Match $ApplicationName
    $LogOutput = EventLogs($EventLogProvider)
    $filename = $EventLogName + $Extn
    $LogOutput | Out-File (Join-Path -Path $DestinationPath -ChildPath $filename) 

    #Collect Microsoft-Windows-AppxPackagingOM Eventlogs
    Write-Host "Collecting SupportAssist event logs from Microsoft-Windows-AppxPackagingOM..."
    $EventLogName = "Microsoft-Windows-AppxPackagingOM"
    $EventLogProvider = Get-WinEvent -FilterHashtable @{ProviderName='*' + $EventLogName + '*'} | Where-Object -Property Message -Match $ApplicationName
    $LogOutput = EventLogs($EventLogProvider)
    $filename = $EventLogName + $Extn
    $LogOutput | Out-File (Join-Path -Path $DestinationPath -ChildPath $filename)

    #Collect Microsoft-Windows-PushNotifications-Platform Eventlogs
    Write-Host "Collecting SupportAssist event logs from Microsoft-Windows-PushNotifications-Platform..."
    $EventLogName = "Microsoft-Windows-PushNotifications-Platform"
    $EventLogProvider = Get-WinEvent -FilterHashtable @{ProviderName='*' + $EventLogName + '*'} | Where-Object -Property Message -Match $ApplicationName
    $LogOutput = EventLogs($EventLogProvider)
    $filename = $EventLogName + $Extn
    $LogOutput | Out-File (Join-Path -Path $DestinationPath -ChildPath $filename)

    #Collect Microsoft-Windows-Taskscheduler Eventlogs
    Write-Host "Collecting SupportAssist event logs from Microsoft-Windows-Taskscheduler..."
    $EventLogName = "Microsoft-Windows-Taskscheduler"
    $EventLogProvider = Get-WinEvent -FilterHashtable @{ProviderName='*' + $EventLogName + '*'; StartTime=(Get-Date).AddDays(-10); EndTime=Get-Date} | Where-Object -Property Message -Match $ApplicationName
    $LogOutput = EventLogs($EventLogProvider)
    $filename = $EventLogName + $Extn
    $LogOutput | Out-File (Join-Path -Path $DestinationPath -ChildPath $filename)
       
}

#endregion

#region Function related to command DisableDebug...
function DisableDebugLog()
{
    
    $foldername = (Get-ChildItem -Path "$SystemDrive\Program Files\Dell\$SupportAssistType\PCDr\SupportAssist" -Directory).Name
    $LoggrabberPath = "$SystemDrive\Program Files\Dell\$SupportAssistType\PCDr\SupportAssist\$foldername\LogGrabber.exe"
    #Stop services before executing loggrabber
    if(Get-Service $SupportAssistService -ErrorAction SilentlyContinue)
	{
		Stop-Service -Name $SupportAssistService -ErrorAction SilentlyContinue
		    
        if(Test-Path -Path "$SystemDrive\Program Files\Dell\$SupportAssistType\PCDr\SupportAssist\$foldername\LogGrabber.exe")
	    {
            if(Get-Service "Dell Hardware Support" -ErrorAction SilentlyContinue)
		    {
			    Stop-Service "Dell Hardware Support" -ErrorAction SilentlyContinue
		    }
		    else
		    {
			    Write-Host "Dell Hardware Support service does not exist"
		    }
            #Execute the loggrabber exe. This will clear the old logs and change the log level to Debug mode for PCDr
			Start-Process -FilePath $LoggrabberPath -ArgumentList "--adjust-loglevel-wick Info --adjust-loglevel-native Info --no-collect --clear-logs" -NoNewWindow -Wait
            #Restart PCDr service
			Start-Service -Name "Dell Hardware Support" -ErrorAction SilentlyContinue
		}
        else
	    {
	        Write-Host "Loggrabber.exe does not exist."
	    }
			
		Start-Sleep -s 10
		    
        #Modify SAA config file for debug logging
		EnableDisableSADebugLog("debugdisable")
		
		#Restart SAA Service
		Start-Service -Name $SupportAssistService -ErrorAction SilentlyContinue
		Start-Sleep -s 10	
	}
	else
	{
		Write-Host "SupportAssist service does not exist"
	}
    
}
#endregion

function ShowHelp()
{
    
    Write-Host @"
    Please use the following commands to get results
    -------------------------------------------------
    EnableDebug  --- To enable debug logs for PcDr and SupportAssist
    CollectLogs  --- To collect all the support assist logs, event logs, registry etc
    DisableDebug --- To disable debug logs for PcDr, SupportAssist and get the zip file
    -------------------------------------------------
"@
}

#Elevate the powershell to administrator
if($winPrincipal.IsInRole($adminRole))
{
    $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
}
else
{
    $workingdir = "set-location $PWD"
    # Indicate that the process should be elevated
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}"' -f ($myinvocation.MyCommand.Definition))
    # Exit from the current, unelevated, process
    exit
}
if($command -eq "CollectInfo")
        {
            #Call this function to show the basic information - OS, OS version, Service Tag etc..
            Write-Host "Collecting Support Assist information and writing the logs to $DestinationPathSA" 
            GetBasicInformation
            #Calls this function to show the Support Assist related basic checks -  Services status of SA, Bradbury, Dell Hardware etc
            SupportAssistBasicCheck
            Write-Host "Completed"
        }
        elseif($command -eq "EnableDebug")
        {
            #Calls the loggrabber.exe to enable debug logs for PcDr and Enables the debug logs for SA in the config file
            Write-Host "Enabling debug logs"
            EnableDebugLog
            Write-Host "Completed"
        }
        elseif($command -eq "CollectLogs")
        {
            CollectInformationAndLogs
        }
        elseif($command -eq "DisableDebug")
        {
            #Calls the loggrabber.exe to disable debug logs for PcDr and disables the debug logs for SA in the config file.
            #Zips the logs folder and places it Desktop
            Write-Host "Disabling debug logs"
            DisableDebugLog
            Write-Host "Completed"
        }
        elseif($command -eq "help")
        {
            ShowHelp
        }
        else
        {
            CollectInformationAndLogs
        }
    


