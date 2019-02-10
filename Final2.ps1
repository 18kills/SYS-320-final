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
        return
    }else{
        Clear-host
        return
    }
}
#This function is used to get input from the user to figure out what they want to see
function userInput
{
    param($csv)
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
    if($cveName)
    {
        $searchOutput=$csv | where { $_.Name -match $cveName }
        if($searchOutput)
        {
            $searchOutput
            read-host 'Press ENTER to continue'
            Clear
            $saveFile=Read-host 'Do you want to save the output(Y/N)'
            if($saveFile -eq 'y' -or $saveFile -eq 'Y')
            {
                clear-host
                Write-host 'Enter the path to save the file'
                write-host 'Exmaple: C:\Users\Username\Documents\filename.csv'
                $path=read-host 'file path'
                #this checks if the path exists
                $path=$path.replace('/','\')
                $PathExists=Test-Path $path.Substring(0,$path.LastIndexOf('\'))
                if($PathExists -eq $True)
                {
                    $searchOutput | out-file $path
                    email -searchOutput $searchOutput
                }else{
                    Clear-host
                    write-host -ForegroundColor Red 'The path you entered does not exist'
                    read-host 'Press ENTER to exit'
                    return
                }
            }
        }else{
            write-host -foregroundColor red 'You search came back with nothing'
            read-host 'Press ENTER to exit'
            return
        }
    }elseif($SoftPackName){
        $searchOutput=$csv | where { $_.Description -match $SoftPackName }
        if($searchOutput)
        {
            $searchOutput
            read-host 'Press ENTER to continue'
            Clear
            $saveFile=Read-host 'Do you want to save the output(Y/N)'
            if($saveFile -eq 'y' -or $saveFile -eq 'Y')
            {
                clear-host
                Write-host 'Enter the path to save the file'
                write-host 'Exmaple: C:\Users\Username\Documents\filename.csv'
                $path=read-host 'file path'
                #this checks if the path exists
                $path=$path.replace('/','\')
                $PathExists=Test-Path $path.Substring(0,$path.LastIndexOf('\'))
                if($PathExists -eq $True)
                {
                    $searchOutput | out-file $path
                    email -searchOutput $searchOutput
                }else{
                    Clear-host
                    write-host -ForegroundColor Red 'The path you entered does not exist'
                    read-host 'Press ENTER to exit'
                    return
                }
            }
        }else{
            write-host -foregroundColor red 'You search came back with nothing'
            read-host 'Press ENTER to exit'
            return
        }
    }elseif($packAndVersion){
        $searchOutput=$csv | where { $_.Description -match $packAndVersion }
        if($searchOutput)
        {
            $searchOutput
            read-host 'Press ENTER to continue'
            Clear
            $saveFile=Read-host 'Do you want to save the output(Y/N)'
            if($saveFile -eq 'y' -or $saveFile -eq 'Y')
            {
                clear-host
                Write-host 'Enter the path to save the file'
                write-host 'Exmaple: C:\Users\Username\Documents\filename.csv'
                $path=read-host 'file path'
                #this checks if the path exists
                $path=$path.replace('/','\')
                $PathExists=Test-Path $path.Substring(0,$path.LastIndexOf('\'))
                if($PathExists -eq $True)
                {
                    $searchOutput | out-file $path
                    email -searchOutput $searchOutput
                }else{
                    Clear-host
                    write-host -ForegroundColor Red 'The path you entered does not exist'
                    read-host 'Press ENTER to exit'
                    return
                }
            }
        }else{
            write-host -foregroundColor red 'You search came back with nothing'
            read-host 'Press ENTER to exit'
            return
        }
    }
}
#this function is used to search the cve file for cve's based on the users input
function Search-Vulnerabilities
{
	Clear-Host
    $downFile=Read-host 'Download the Security vulnerabilites file(Y/N)'
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
       userInput -csv $csv
    }elseif($downFile -eq 'n' -or $downFile -eq 'N'){
        Write-host 'Enter the path the the CVE file'
        write-host 'Exmaple: C:\Users\Username\Documents\filename.csv'
        $path=read-host 'file path'
        #this checks if the path exists
        $path=$path.replace('/','\')
        $PathExists=Test-Path $path.Substring(0,$path.LastIndexOf('\'))
        if($PathExists -eq $True)
        {
           $csv=Import-Csv $path -header "Name","Status","Description","References","Phase","Votes","Comments" 
           userInput -csv $csv
        }else{
            Clear-host
            write-host -ForegroundColor Red 'The path you entered does not exist'
            read-host 'Press ENTER to exit'
            return
        }
    }
}
Search-Vulnerabilities
