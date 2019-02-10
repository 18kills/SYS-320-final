#This function is used for outputs that are used multiple times for the functions below
function outputs
{
    #Gets paramiters 
    param([int]$num,[string]$path)
    #Determines which options was choosen
    switch($num)
    {
        1{
            Clear-Host
            Write-Host -ForegroundColor Magenta 'File has been saved to '$path'.cvs'
            Read-Host 'Press ENTER to continue...'
            System-Admin
        }
        2{
            Clear-Host
            Write-Host -ForegroundColor Red 'ERROR: File did not save. Please try again'
            Read-Host 'Press ENTER to continue...'
            List-Processes
        }
        3{
            Clear-Host
            Write-Host -ForegroundColor Red 'ERROR: The path that you entered does not exists. Please try again'
            Read-Host 'Press ENTER to continue...'
            List-Processes
        }
        4{
            Clear-Host
            Write-Host -ForegroundColor Yellow 'Enter the filename and loction to save the file'
            Write-Host -ForegroundColor Yellow 'Leave blank to not save the output'
            Write-Host -ForegroundColor Yellow 'EX: C:\Users\Username\Documents\filename'
            $path=Read-Host 'Filename and location'
            return $path
        }
    }
}
#This function is used to get user responses and then output running processes based on the users responses
function List-Processes
{
    Clear-Host
    Write-Host -ForegroundColor Green 'Enter the name of the process'
    Write-Host -ForegroundColor Green 'Leave blank if you want to see all running processes'
    $processName=Read-Host 'Enter Process name'
    if(!$processName)
    {
        $path=outputs -num 4
        if(!$path)
        {
            Clear-Host
            #Outputs the running processes 
            Get-Process
            Read-Host 'Press ENTER to return to the System Admin Menu'
            System-Admin
        }else{
            #this checks if the path exists
            $path=$path.replace('/','\')
            $PathExists=Test-Path $path.Substring(0,$path.LastIndexOf('\'))
            if($PathExists -eq $True)
            {
                #outputs running processes to a file
                Get-Process | Out-File $path'.cvs'
                $fileExists=test-path $path'.cvs'
                if($fileExists -eq $True)
                {
                    outputs -num 1 -path $path
                }else{
                    outputs -num 2
                }
            }else{
                outputs -num 3
            }
        }
    }else{
        #Checks if the process that the user specified is running
        $processActive=Get-Process $processName -ErrorAction SilentlyContinue
        if(!$processActive)
        {
            #Tells the user that the process that was specified is not running
            Clear-Host
            Write-Host -ForegroundColor Red 'ERROR: Process '$processName' is not running'
            Read-Host 'Press ENTER to return to the System Admin Menu'
            System-Admin
        }else{
            #gets the path to save the file from the user
            $path=outputs -num 4
            if(!$path)
            {
                Clear-Host
                #outputs a specific process
                Get-Process $processName
                Read-Host 'Press ENTER to continue...'
                System-Admin
            }else{
                $path=$path.replace('/','\')
                $PathExists=Test-Path $path.Substring(0,$path.LastIndexOf('\'))
                if($PathExists -eq $True)
                {
                    #outputs a specific process to a file
                    Get-Process $processName | Out-File $path'.cvs'
                    $fileExists=test-path $path'.cvs'
                    if($fileExists -eq $True)
                    {
                        outputs -num 1 -path $path
                    }else{
                        outputs -num 2
                    }
                }else{
                    outputs -num 3
                }
            }
        }
    }
}
#This function is used to list services
function List-Services
{
    Clear-Host
    #Prompts the user for the name of a service
    Write-Host -ForegroundColor Green 'Enter the name of the service'
    Write-Host -ForegroundColor Green 'Leave blank if you want to see all running services'
    $serviceName=Read-Host 'Enter service name'
    if(!$serviceName)
    {
        #gets a path for a file to output results to
        $path=outputs -num 4
        if(!$path)
        {
            #outputs results of all running services to the screen
            Clear-Host
            Get-Service | Where-Object {$_.Status -eq "Running"}
            Read-Host 'Press Enter to return to the Systen Admin Menu'
            System-Admin
        }else{
            #checks if the path exists
            $path=$path.replace('/','\')
            $PathExists=Test-Path $path.Substring(0,$path.LastIndexOf('\'))
            if($PathExists -eq $True)
            {
                #sends the output of all running services to the user specified file
                Get-Service | Where-Object {$_.Status -eq "Running"} | out-file $path'.cvs'
                $fileExists=test-path $path'.cvs'
                if($fileExists -eq $True)
                {
                    outputs -num 1 -path $path
                }else{
                    outputs -num 2
                }
            }else{
                outputs -num 3
            }
        }
    }else{
        #checks to see if the service specified by the user is running
        $serviceActive=Get-Service -Name $serviceName -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq "Running"}
        if(!$serviceActive)
        {
            #Tells the user the service that was specified is not running
            Clear-Host
            Write-Host -ForegroundColor Red 'ERROR: Service '$serviceName' is not running'
            Read-Host 'Press ENTER to return to the System Admin Menu'
            System-Admin
        }else{
            $path=outputs -num 4
            if(!$path)
            {
                #outputs the running service info to the screen
                Clear-Host
                Get-Service -Name $servieName | Where-Object {$_.Status -eq "Running"}
                Read-Host 'Press ENTER to continue...'
                System-Admin
            }else{
                $path=$path.replace('/','\')
                $PathExists=Test-Path $path.Substring(0,$path.LastIndexOf('\'))
                if($PathExists -eq $True)
                {
                    #outputs the service info to a file
                    Get-Service -Name $serviceName | Out-File $path'.cvs'
                    $fileExists=test-path $path'.cvs'
                    if($fileExists -eq $True)
                    {
                        outputs -num 1 -path $path
                    }else{
                        outputs -num 2
                    }
                }else{
                    outputs -num 3
                }
            }
        }
    }
}
#This function is used to list packages that are installed on the computer
function List-Packages
{
    #Asks the user for the name of a package
    Clear-Host
    Write-Host -ForegroundColor Green 'Enter the name of the package'
    Write-Host -ForegroundColor Green 'Leave blank if you want to see all installed packages'
    $packageName=Read-Host 'Enter Package name'
    if(!$packageName)
    {
        #gets a path for the save file from the user
        $path=outputs -num 4
        if(!$path)
        {
            #outputs all installed packages to the screen
            Clear-Host
            Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate, DisplayVersion | Format-Table –AutoSize 
            Read-Host 'Press ENTER to return to the System Admin Menu'
            System-Admin
        }else{
            #checks if the path exists
            $path=$path.replace('/','\')
            $PathExists=Test-Path $path.Substring(0,$path.LastIndexOf('\'))
            if($PathExists -eq $True)
            {
                #Sends a list of all installed packages to the file
                Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate, DisplayVersion | Format-Table –AutoSize | Out-File $path'.cvs'
                $fileExists=test-path $path'.cvs'
                if($fileExists -eq $True)
                {
                    outputs -num 1 -path $path
                }else{
                    outputs -num 2
                }
            }else{
                outputs -num 3
            }
        }
    }else{
        #checks if the package that the user specificed is installed
        $packageActive=Get-Package -Name $packageName -ErrorAction SilentlyContinue
        if(!$packageActive)
        {
            #tells the user the specified package is not installed
            Clear-Host
            Write-Host -ForegroundColor Red 'ERROR: Package '$packageName' is not installed'
            Read-Host 'Press ENTER to return to the System Admin Menu'
            System-Admin
        }else{
            $path=outputs -num 4
            if(!$path)
            {
                #OUtputs the info on the specified package to the screen
                Clear-Host
                Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate, DisplayVersion | Where-object {$_.DisplayName -eq $packageName} | Format-Table –AutoSize
                Read-Host 'Press ENTER to continue...'
                System-Admin
            }else{
                $path=$path.replace('/','\')
                $PathExists=Test-Path $path.Substring(0,$path.LastIndexOf('\'))
                if($PathExists -eq $True)
                {
                    #sends the info for the specified package to the file
                    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate, DisplayVersion | Where-object {$_.DisplayName -eq $packageName} | Format-Table –AutoSize | Out-File $path'.cvs'
                    $fileExists=test-path $path'.cvs'
                    if($fileExists -eq $True)
                    {
                        outputs -num 1 -path $path
                    }else{
                        outputs -num 2
                    }
                }else{
                    outputs -num 3
                }
            }
        }
    }
}
# this function get the systems information
function List-SysInfo
{
    Clear-Host
    #Gets a path for file to send info
    $path=outputs -num 4
    if(!$path)
    {
        #Prints info about the computer to the screen
        Clear-Host
        Get-PSDrive -PSProvider "FileSystem" | select Name,MaxCapacity,Used,Free,Root
        Get-WmiObject -class "Win32_PhysicalMemoryArray" | select Name,MaxCapacity
        Get-WMIObject win32_Processor | select name
        read-host 'Press ENTER to return to the System Admin Menu'
        System-Admin
    }else{
        #checks if the path exists
        $path=$path.replace('/','\')
        $PathExists=Test-Path $path.Substring(0,$path.LastIndexOf('\'))
        if($PathExists -eq $True)
        {
            #sends the info about the computer to the file
            $disk=Get-PSDrive -PSProvider "FileSystem" | select Name,MaxCapacity,Used,Free,Root
            $ram=Get-WmiObject -class "Win32_PhysicalMemoryArray" | select Name,MaxCapacity
            $cpu=Get-WMIObject win32_Processor | select name
            $disk,$ram,$cpu | out-file $path'.cvs'
            $fileExists=test-path $path'.cvs'
            if($fileExists -eq $True)
            {
                outputs -num 1 -path $path
            }else{
                outputs -num 2
            }
        }else{
            outputs -num 3
        }
    }
}
#this function is used with list-eventlogs
function CheckLogName
{
    #this checks if thye log name that the user entered exists
	clear-host
	$logName=Read-Host 'Enter the name of log'
	$CheckIfExists=Get-EventLog -logname $logName -ErrorAction SilentlyContinue
	if(!$CheckIfExists)
	{
        #tells the user the log doesnt exist
		Clear-host
		Write-host -foregroundcolor red 'The log Name you entered does not exist. Please try again'
		Read-Host 'Press ENTER to continue'
		CheckLogName
	}else{
        #returns the name og the log the user specified if the log was found
	    return $logName
    }
}
#this function gets logs based on the parameters that the user enters
function List-EventLogs
{
	$keyword=''
	$timeAfter=''
	$timeBefore=''
	Clear-Host
	$logName=CheckLogName
	Clear-Host
    #gets the user to choose an option
	$numEvents=Read-Host 'Enter the number of events to display'
	Clear-Host
	Write-host 'Pick an option by entering the number of the option that you want'
	Write-host '1. Keyword search'
	Write-Host '2. timeframe search'
	$option=read-host 'Pick an option'
    #figures out what option the user picked
	switch($option)
	{
		1{
			Clear-Host
			$keyword=read-host 'Enter a keyword'
		}
		2{
			Clear-Host
			Write-host 'Ex: 1/17/2019'
			$time=Read-Host 'Enter a date to look at events after that date'
		}
	}
	$path=outputs -num 4
	if(!$path)
	{
		if(!$keyword)
		{
            #Checks to see if there are any events based on the users inputs and then outputs the events based on the user input
			$checkError=Get-EventLog -logname $logName -Newest $numEvents -After $time -ErrorAction SilentlyContinue
			if($checkError -eq $True)
			{
				Clear-host
				$checkError
				Read-Host 'Press ENTER to return to System Admin Menu'
				System-Admin
			}else{
				Clear-host
				Write-host -ForegroundColor Red 'ERROR the paramaters you entered do not return any results'
				read-host 'Press ENTER to return to System Admin Menu'
				System-Admin
			}
		}elseif(!$timeAfter)
		{
            #Checks to see if there are any events based on the users inputs and then outputs the events based on the user input
			$CheckError=Get-EventLog -logname $logName -Newest $numEvents -Message $Keyword
			if($checkError -eq $True)
			{
				Clear-host
				$checkError
				Read-Host 'Press ENTER to return to System Admin Menu'
				System-Admin
			}else{
				Clear-host
				Write-host -ForegroundColor Red 'ERROR the paramaters you entered do not return any results'
				read-host 'Press ENTER to return to System Admin Menu'
				System-Admin
			}
		}
	}else{
        #checks if the path that the user entered exists
        $path=$path.replace('/','\')
		$PathExists=Test-Path $path.Substring(0,$path.LastIndexOf('\'))
		if($PathExists -eq $True)
		{
			if(!$keyword)
			{
                #Checks to see if there are any events based on the users inputs and then outputs the events based on the user input
				$checkError=Get-EventLog -logname $logName -Newest $numEvents -After $time -ErrorAction SilentlyContinue
				if($checkError -eq $True)
				{
					$checkError | out-file $path'.cvs'
				}else{
					Clear-host
					Write-host -ForegroundColor -Red 'ERROR the paramaters you entered do not return any results'
					read-host 'Press ENTER to return to System Admin Menu'
					System-Admin
				}
			}elseif(!$timeAfter)
			{
                #Checks to see if there are any events based on the users inputs and then outputs the events based on the user input
				$CheckError=Get-EventLog -logname $logName -Newest $numEvents -Message $Keyword
				if($checkError -eq $True)
				{
					$checkError | out-file $path'.cvs'
				}else{
					Clear-host
					Write-host -ForegroundColor -Red 'ERROR the paramaters you entered do not return any results'
					read-host 'Press ENTER to return to System Admin Menu'
					System-Admin
				}
			}
			$fileExists=test-path $path'.cvs'
			if($fileExists -eq $True)
			{
				outputs -num 1 -path $path
			}else{
				outputs -num 2
			}
		}else{
			outputs -num 3
		}
	}
}
#System Admin menu
function System-Admin
{
    Clear-Host
    Write-Host -ForegroundColor Yellow '==================== System Admin ===================='
    Write-Host -ForegroundColor Green '   To select an option enter the options number    '
    Write-Host -ForegroundColor Green '1: List all running processes'
    Write-Host -ForegroundColor Green '2: List all running services'
    Write-Host -ForegroundColor Green '3: List all installed packages'
    Write-Host -ForegroundColor Green '4: List the processor, amount of RAM, mounted disks, disk space available, and disk space used'
    Write-Host -ForegroundColor Green '5: List the available Windows Event Logs'
    Write-Host -ForegroundColor Green '6: Return to the Main Menu'
    Write-Host -ForegroundColor Green '7: Exit'
    $selection=Read-Host 'Make a selection'
    switch($selection)
    {
        '1' {List-Processes} 
        '2' {List-Services}
        '3' {List-Packages}
        '4' {List-SysInfo}
        '5' {List-EventLogs}
        '6' {MainMenu}
        '7' {return}
    }
}
#this function is used to send the email with the cve that the user wants to send
function email
{
    param($searchOutput)
    clear-host
    $answer=read-host 'Do you want to email the results (Y/N)'
    if($answer -eq 'y' -or $answer -eq 'Y')
    {
        Clear-host
        $numOutputs=$searchOutput | measure
        $numOutputs=$numOutputs.Count
        if($numOutputs -gt 1)
        {
            clear-host
            $searchOutput
            $num=read-host "How many CVE's do you want to send"
            write-host 'Example: CVE-1999-0001'
            $names=New-Object System.Collections.ArrayList
            For($x=0;$x -lt $num;$x++ )
            {
                $cveName=read-host 'Enter name of CVE'
                $names.add($cveName)
            }
            $output=$searchOutput | where {$names -eq $_.Name}
        }else{
            $output=$searchOutput
        }
        clear-host
        $output=$output | select "Name","Status","Description","References","Phase"
        $output=$output -replace ";","`n"
        $output=$output -replace "@{",""
        $output=$output -replace "}",""
        $from=read-host 'Enter your email'
        $to=read-host 'Enter email to send to'
        $subject=read-host 'Enter the subject of the email'
        $body=read-host 'Enter the message for the email'
        $smtpserver=read-host 'Enter the smtp server address'
        $smtpport=read-host 'Enter the smtp server port'
        Send-MailMessage -From $from -to $to -Subject $subject -Body $body"`n$output" -SmtpServer $smtpserver -port $smtpport -UseSsl -Credential (Get-Credential) 
        clear-host
        write-host -ForegroundColor green 'The email was sent'
        read-host 'Press ENTER to return to the main menu'
        MainMenu
    }else{
        Clear-host
        MainMenu
    }
}
#this function is used to search the cve file for cve's based on the users input
function Search-Vulnerabilities
{
	Clear-Host
    $downFile=Read-host 'Download the Security vulnerabilites file(Y/N)'
	Clear-Host
    Write-Host -ForegroundColor Yellow 'To select an option enter the options number'
    write-host -ForegroundColor Green '1. Search file for CVE name'
    write-host -ForegroundColor Green '2. Search file for CVE description'
    $selection=Read-host 'Make a selection'
    #this gets input from the user on what to do
    switch($selection)
    {
    	1{
			clear-host
            write-host 'Example: CVE-1999-0001'
            $cveName=read-host 'Enter CVE name'
		}
		2{
			clear-host
			Write-Host -ForegroundColor Yellow 'To select an option enter the options number'
			Write-host -ForegroundColor Green '1. Search for software package name'
			Write-host -ForegroundColor Green '2. Search for package name and version'
			$selection=read-host 'Make a selection'
			switch($selection)
			{
				1{
					clear-host
                    Write-host 'Example: BIND'
					$SoftPackName=read-host 'Enter a Software Package Name'
				}
				2{
					clear-host
                    Write-host 'Example: BIND 4.9'
					$packAndVersion=read-host 'Enter a Package Name and Version'
				}
			}
		}
    }
    if($downFile -eq 'y' -or $downFile -eq 'Y')
    {
       #This downloads the cve file
       $url='https://cve.mitre.org/data/downloads/allitems.csv'
       $mydocuments = [environment]::getfolderpath("mydocuments")
       $mydocuments+='\SecVuln.csv'
       $destination=$mydocuments
       Import-Module BitsTransfer
       Start-BitsTransfer -Source $url -Destination $destination
       $csv=Import-Csv $destination -header "Name","Status","Description","References","Phase","Votes","Comments"
       #this gets more user input
       if($cveName)
       {
            $searchOutput=$csv | where { $_.Name -match $cveName }
            $searchOutput
            if($searchOutput)
            {
                read-host 'Press ENTER to continue'
                email -searchOutput $searchOutput
            }else{
                write-host -foregroundColor red 'You search came back with nothing'
                read-host 'Press ENTER to return to main menu'
                MainMenu
            }
       }elseif($SoftPackName){
            $searchOutput=$csv | where { $_.Description -match $SoftPackName }
            $searchOutput
            if($searchOutput)
            {
                read-host 'Press ENTER to continue'
                email -searchOutput $searchOutput
            }else{
                write-host -foregroundColor red 'You search came back with nothing'
                read-host 'Press ENTER to return to main menu'
                MainMenu
            }
       }elseif($packAndVersion){
            $searchOutput=$csv | where { $_.Description -match $packAndVersion }
            $searchOutput
            if($searchOutput)
            {
                read-host 'Press ENTER to continue'
                email -searchOutput $searchOutput
            }else{
                write-host -foregroundColor red 'You search came back with nothing'
                read-host 'Press ENTER to return to main menu'
                MainMenu
            }
       }
       
    }elseif($downFile -eq 'n' -or $downFile -eq 'N'){
        Write-host 'The file has to be downloaded in order to search it'
        read-host 'Press ENTER to return the Main Menu'
        MainMenu
    }
}
#Security admin menu
function Security-Admin
{
    Clear-Host
    Write-Host -ForegroundColor Yellow '==================== Security Admin ===================='
    Write-Host -ForegroundColor Green '   To select an option enter the options number    '
    Write-Host -ForegroundColor Green '1: Search for recent security vulnerabilities identified by the NVD project'
    Write-Host -ForegroundColor Green '2: Return the main menu'
    Write-Host -ForegroundColor Green '3: Exit'
    $selection=Read-Host 'Make a selection'
    switch($selection)
    {
        '1' {Search-Vulnerabilities} 
        '2' {MainMenu}
        '3' {return}
    }
}
#the main menu
function MainMenu
{
    Clear-Host
    Write-Host -ForegroundColor Yellow '==================== Main Menu ===================='
    Write-Host -ForegroundColor Green '   To select an option enter the options number    '
    Write-Host -ForegroundColor Green '1: System Admin'
    Write-Host -ForegroundColor Green '2: Security Admin'
    Write-Host -ForegroundColor Green '3: Exit'
    $selection=Read-Host 'Make a selection'
    switch($selection)
    {
        '1' {System-Admin} 
        '2' {Security-Admin}
        '3' {return}
    }
}
MainMenu
