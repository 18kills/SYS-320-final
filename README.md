# SYS-320-final

The two powershell programs here were written by me for my Automation and Scripting class final project. 
These programs are to be run on windows 10 computer on powershell.
By: Richard T Swierk
Date: 2/28/2019

#### The following is what the powershell program named finalProject.ps1 does.

Main Menu -
	This program will start by showing the user the Main Menu. In this menu the user has three options to choose
	from. Those options are to go to the System Admin menu, go to the Security Admin menu, or exit the program.
	
System Admin Menu -
	In the System Admin menu the user will have seven options that can be choosen from. From this menu the user can 
	now pick what system info they want to see. All of the options given on the System Admin menu will have options after 
	them to further clearify what the user wants to see and do. Options numbers one through five will all allow the user to 
	save the output they recieve to a file. Option one will allow the user to see processes that are running on the current
	system. Option two will show the user running services on the current system. Option three will show the user packages 
	that are currently installed on the users system. Option four shows the users systems hardware info. Option five will let 
	the user see windows event logs on there system. Option six will take the user back to the main menu. Option seven will 
	exit the program. 

Security Admin Menu -
	In the Security Admin menu there are three options that the user can choose from. The first option is to 
	search recent security vulnerabilities identified by the NVD project. More info about this option can be found below in the, 
	Search Security Vulnerabilities function, section. The second option is to return to the main menu and the third option
	is to exit the program.
	
Search Vulnerabilities function -
	The basic function of this function is to allow the user to find Secuirty Vulnerabilities that have been idenifide by the 
	NVD project. In this function it asks the user if they want to download the CVE file. Before it asks the user if they want to
	download the file it tells the user that if this file is not on the current users system then this function can not be used. 
	If the user already has the file downloaded then they can choose not to the download the file. If they choose to not download
	the file they will prompted to enter the path the file. If the path that the user gave does not exist then this function calls 
	the function outputs with the parameter -num 3 which gives and error message saying that the file does not exist and then brings
	the user back to the main menu. If the user either downloads the file or gives a valid path to the file then this function calls
	the function CVEoptions with the parameter -csv $csv. The variable $csv that is entered as a parameter for the function is where 
	the imported csv file content held.
	
CVEoptions function -
	This function is only used by the Search Vulnerabilities function. This function contains all of the options that the user
	can enter. The user can search the through the file three different ways. The user can either search for a CVE by it name, or 
	search for a CVE by software package name, or search for a CVE by software package name and software package version. After the 
	user has choosen how to search for the CVE the program then outputs what was found in the file based on the users input. If 
	nothing was found with the input that the user gave then the program tells the user that nothing was found and sends the user 
	back to the main menu. If something was found based on the user input then it writes what was found to the screen and then calls 
	the function email with the parameter -searchOutput $searchOutput. The variable $searchOutput contains what was found in the CVE 
	file based on the users input.
	
email function - 
	This function is used to email the result of the search of the CVE file based on the users input. The user is asked if they want
	to email the results of the CVE file search. If the user chooses not to email the results then the user is sent back to the main
	menu. If the user chooses to email the result then the user is given more options. If there was more then one CVE found that matched
	the users input from the CVEoptions function the user is asked how many of the CVE's they want to send in the email. All of the 
	CVE's found are printed to the screen and the user enters the number of CVE's they want to send and then the name of each CVE they
	want to send. After the user is asked for information to send the email. The user is prompted for there email address, the email address
	to send the email to, the subject of the email, the body of the email, the address of the smtp server they use, the port of the 
	smtp server they use, and then there credentials for there email account. After this the user is sent back to the main menu.
	

#### The following is what the powershell program named finalProject2.ps1 does.

Search Vulnerabilites function - 
	The basic function of this function is to allow the user to find Secuirty Vulnerabilities that have been idenifide by the 
	NVD project. In this function it asks the user if they want to download the CVE file. Before it asks the user if they want to
	download the file it tells the user that if this file is not on the current users system then this function can not be used. 
	If the user already has the file downloaded then they can choose not to the download the file. If they choose to not download
	the file they will prompted to enter the path the file. If the path that the user gave does not exist then an error message is printed 
	to the screen saying that the file does not exist and then brings the user back to the main menu. If the user either downloads 
	the file or gives a valid path to the file then this function calls the function userInput -csv with the parameter -csv $csv. 
	The variable $csv that is entered as a parameter for the function is where the imported csv file content held.
	
userInput function -
	This function is only used by the Search Vulnerabilities function. This function contains all of the options that the user
	can enter. The user can search the through the file three different ways. The user can either search for a CVE by it name, or 
	search for a CVE by software package name, or search for a CVE by software package name and software package version. After the 
	user has choosen how to search for the CVE the program then outputs the results and then asks the user if they want to save the results
	to a file. If nothing was found with the input that the user gave then the program tells the user that nothing was found and sends the user 
	back to the main menu. If something was found based on the user input then it writes what was found to the screen and then calls 
	the function email with the parameter -searchOutput $searchOutput. The variable $searchOutput contains what was found in the CVE 
	file based on the users input.
	
email function - 
	This function is used to email the result of the search of the CVE file based on the users input. The user is asked if they want
	to email the results of the CVE file search. If the user chooses not to email the results then the user is sent back to the main
	menu. If the user chooses to email the result then the user is given more options. If there was more then one CVE found that matched
	the users input from the userInput function the user is asked how many of the CVE's they want to send in the email. All of the 
	CVE's found are printed to the screen and the user enters the number of CVE's they want to send and then the name of each CVE they
	want to send. After the user is asked for information to send the email. The user is prompted for there email address, the email address
	to send the email to, the subject of the email, the body of the email, the address of the smtp server they use, the port of the 
	smtp server they use, and then there credentials for there email account. After this the user is sent back to the main menu.

