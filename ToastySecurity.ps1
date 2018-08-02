<# 
                          ____
              .----------'    '-.
             /  .      '     .  \\
            /        '    .     / |
           /     TOASTY SEC!!!  \ /
          /  ' .       .     .  |||
         /.___________    '    / //
         |._          '------'| / |
         '.............______.-' /  
         |-.                  | /
         `"""""""""""""-.....-'

 		Authors:
			Adam "C4RnaG3" Morris
			Kelvin "grepnoir" Ashton

		Purpose:
			This tool kit is built for security/system administrators
			who are lazy and want a shortcut to doing their everyday
			tasks.
		
		Note:
		We are NOT professional PowerShell developers, this was built for SIP311 at UAT.
		THIS IS A STUDENT PROJECT SO THERE ARE PROBABLY GOING TO BE PROGRAMMING
		ERRORS!
#>

#Tools

#User tools

function Add-User #Function that adds users
{
    param (
    [string]$uTitle = 'Welcome to User Addition' #Greeting message
    )
    cls
    Write-Host "==============$uTitle=============="
	''
    $fname = Read-Host "What is the FIRST NAME? " #gets the users FIRST name from the user
    
    $lname = Read-Host "What is the LAST NAME? " #gets the users LAST name from the user
    
    $uname = Read-Host "What will be the USER NAME? " #creates the new users username
    
    $pass = Read-Host -AsSecureString "What is the DEFAULT PASSWORD? " #Sets the default password
    
    $ou = Read-Host "What is the OU it goes too?" #Gets the OU that the new user needs to be added too
    
    $group = Read-Host "What Group are they in?"
    
    Try
    {
    New-ADUser -Name "$fname $lname" -GivenName $fname -Surname $lname ` #creates the account then enables it
    -SamAccountName $uname -AccountPassword $pass `
    -PassThru -ChangePasswordAtLogon $True -Path "OU=$ou" | Enable-ADAccount 
    Add-ADMember -Identity $group -Members $uname
    }
    Catch
    {
    $ErrorMessage = $_.Exception.Message #throws error message if the user already exists
    }
}

function DR-User #function for removing/disabling users
{
    param (
    [string]$drTitle = 'Welcome to User Removal'
    )
    cls
    Write-Host "==============$drTitle=============="
	''
	Write-Host "1: Disable all inactive accounts" #disables accounts
	Write-Host "2: Delete all inactive accounts (NOT RECOMMENDED)" #deletes accounts
	Write-Host "99: QUIT" #back to main menu
	''
	$ur = Read-Host "What do?(1/2)"
	switch($ur) #waits for user input
	{
		'1' 
            {
				$days = Read-Host "How long inactive (in days)?" #gets how far back to go for inactive accounts
				$dayz = get-date.adddays(-"$days") #Tells the script to go back so many days
				''
				Write-Host "Begining the Purge" #witty remark
				''
				Get-ADuser -properties * -filter {(lastlogondate -notlike "*" -OR lastlogondate -le $dayz) -AND (passwordlastset -le $dayz) `
				-AND (passwordneverexpires -eq $false)} | Disable-ADAccount #disables all user accounts that meet the requirements
				''
				Write-Host "Purge complete"		
		}
		
		'2' 
            {
				$days = Read-Host "How long inactive (in days)?"
				$dayz = get-date.adddays(-"$days")
				''
				Write-Host "Time to go Ol' Yeller" #witty remark
				''
				Get-ADuser -properties * -filter {(lastlogondate -notlike "*" -OR lastlogondate -le $dayz) -AND (passwordlastset -le $dayz) `
				-AND (passwordneverexpires -eq $false) | Remove-ADObject #deletes all user accounts that meet the requirements
				''
				Write-Host "They Dead" #they dead
		
		}
		
		'99' 
            {
				Write-Host "K Thx Bye" #goes back to the main menu
		}
    }
  }
}

function Chng-Psswd
{
    param (
    [string]$chpsTitle = 'Welcome to Password Changing'
    )
    cls
    Write-Host "==============$chpsTitle=============="
    ''
    $uname = Read-Host "What user will have their password changed?" #gets the user that is affected
    $npass = Read-Host -AsSecureString "Enter the new password" #Gets the new password securly
    ''
    net user $uname $npass # changes the password
}

function Group-Perms
{
    param (
    [string]$gpTitle = 'Welcome to Group Permissions'
    )
    cls
    Write-Host "==============$gpTitle=============="

}

#Security tools

function sPort-Scan
{
    param (
    [string]$portsscTitle = 'Welcome to Single-Port/Single-Host Scanning'
    )
    cls
    Write-Host "==============$portsscTitle=============="

    $ErrorActionPreference = 'SilentlyContinue' #Makes errors not display

    $port = Read-Host "What port do you want to scan for?" #Gets target port

    $ip = Read-Host "What IP address" #Gets target IP address

    $time = Read-Host "How long (in SECONDS), between each test" #Gets sleep time

    $count = '1'

    do
    {

        Test-Connection -BufferSize 32 -Count 1 -Quiet -ComputerName $ip #Sees if target system is up

        $ssocket = new-object System.Net.Sockets.TcpClient($ip, $port) #Builds the socket

            IF($ssocket.Connected) #Tests for socket connection
                {
                    Write-Host "$ip listening on port $port"
                    $ssocket.Close()
                }
            ELSE
                {
                    Write-Host "$ip not listening on port $port!!"
                    $ssocket.Close()
                }
        Start-Sleep -s $time #Time before testing again
    }
    While (++$count -le '2')

}

function  fPort-Scan
{
    <#Credit to Ed Wilson, msft
      For the original script. 
      Modified for the purposes
      of this script
      Link to original:
      https://blogs.technet.microsoft.com/heyscriptingguy/2014/03/19/creating-a-port-scanner-with-windows-powershell/#>
       
     param (
     [string]$fportscTitle = 'Welcome to Multi-Port/Multi-Host Scanning'
     )
    cls
    Write-Host "==============$fportscTitle=============="

    $ErrorActionPreference = 'SilentlyContinue' #Makes errors not display
                                                    
    $hostn = Read-Host "Enter the first THREE OCTECTS (X.X.X)"
    $sport = Read-Host "What port do you want to START at"
    $fport = Read-Host "What port do you want to END with"
    
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++"

    $iprange = 1..254 #range of hosts
    
    $ping = Test-Connection -BufferSize 32 -Count 1 -Quiet -ComputerName $ip #Sees if target system is up

    $port = $sport..$fport #range of ports

    $fsocket =  new-object System.Net.Sockets.TcpClient($iprange, $port) #building out the socket

    foreach ( $h in $iprange )
        {
            $ip = "{0}.{1}" -F $host,$h
            IF($ping)
                {
                    $fsocket
                        
                        IF($fsocket.Connected)
                            {
                                Write-Host "$ip Listening on $port!"
                                $fsocket.Close()
             }
                                                                              
        }

    }
}



function Fire-Wall
{
    param (
    [string]$fwTitle = 'Welcome to Firewall Configuration'
    )
    cls
    Write-Host "==============$fwTitle=============="
}

function GP-UPDATE
{
    param (
    [string]$gpuTitle = 'Welcome to Group Policy Updating'
    )
    cls
    Write-Host "==============$gpuTitle=============="
    ''
    Write-Host "1: Start the update"
    Write-Host "2: BACK"
    ''
    $gp = "what do? "
    switch($gp)
        {
            '1' {

                $domain = Read-Host "What is the domain? "

                $computers = Get-ADComputer -filt *
                $creds = GetCredential $domain\Administrator
                $session = New-PSSession -cn $computers.name -cred $creds
                icm -Session $session -ScriptBlock {gpupdate/force}
                
                }

            '2' {
                    return
                }
        }
}

#Software tools

function Tsk-Schd
{
    param (
    [string]$tskTitle = 'Welcome to Scheduled Tasks'
    )
    cls
    Write-Host "==============$tskTitle=============="
    ''
    Write-Host "1: Create a scheduled task"
    Write-Host "2: Delete a scheduled task"
    Write-Host "3: Modify a scheduled task"
    Write-Host "4: QUIT"
    ''
    $sch = Read-Host "What would you like to do?"

    IF($sch -eq 'c')
        {
            cls
            $file = Read-Host "What is the FULL PATH to the file you want to run"
            ''
            Write-Host "==========Triggers==========="
            ''
            Write-Host "Daily"
            Write-Host ""    
           
           
           
           
            $trigger = Read-Host "When do you want this to trigger?"
            
}
}

function Uninst-Soft
{
    param (
    [string]$uniTitle = 'Welcome to Uninstalling Software'
    )
    cls
    Write-Host "==============$uniTitle=============="
}

function Inst-Soft
{
    param (
    [string]$instTitle = 'Welcome to Software Installation'
    )
    cls
    Write-Host "==============$instTitle=============="
}

function Hash-stuff
{
    param (
    [string]$hashTitle = 'Welcome to File Hashing'
    )
    cls
    Write-Host "==============$hashTitle=============="
	#Various hashing algorithms
    Write-Host "1:SHA1"
    Write-Host "2:SHA256"
    Write-Host "3:SHA384"
    Write-Host "4:SHA512"
    Write-Host "5:MACTripleDES"
    Write-Host "6:MD5"
    Write-Host "7:RIPEMD160"
    Write-Host "8:QUIT"


do
{

$hash = Read-Host "Which Hashing Algorithm?" #Determines hashing algorithm to use
$dir = Read-Host "Which Directory?" #Gets certain directory to hash
switch ($hash)
<# Hashes EVERYTHING in the specified directory,
   including hidden files and sub-directories#>
 {
  '1'{
      dir -force $dir * -Recurse | Get-FileHash -Algorithm SHA1 | Format-List | Out-File C:\SHA1.txt
  } '2' {
      dir -force $dir * -Recurse | Get-FileHash -Algorithm SHA256 | Format-List | Out-File C:\SHA256.txt
  } '3' {
      dir -force $dir * -Recurse | Get-FileHash -Algorithm SHA384 | Format-List | Out-File C:\SHA384.txt
  } '4' {
      dir -force $dir * -Recurse | Get-FileHash -Algorithm SHA512 | Format-List | Out-File C:\SHA512.txt
  } '5' {
      dir -force $dir * -Recurse | Get-FileHash -Algorithm MACTripleDES | Format-List | Out-File C:\MAC3DES.txt
  } '6' {
      dir -force $dir * -Recurse | Get-FileHash -Algorithm MD5 | Format-List | Out-File C:\MD5.txt
  } '7' {
      dir -force $dir * -Recurse | Get-FileHash -Algorithm RIPEMD160 | Format-List | Out-File C:\RIPE.txt
  }
 }
}
until ($hash -eq '8') #Keeps loop going until user hits the 8 key

}

#Local tools

function Hardware-Info
{
    param (
    [string]$hdwTitle = 'Welcome to Hardware Information'
    )
    cls
    Write-Host "==============$hdwTitle=============="
    ''
    Write-Host "1: CPU information"
    Write-Host "2: Hard drive info"
    Write-Host "3: Remote Device info"
    Write-Host "4: BIOS information"
    Write-Host "5: ALL"
    Write-Host "6: QUIT"

    $hardwares = Read-Host "Which option?" #Determines which information to obtain
    switch ($hardwares)
    
 {
  '1'{
      Get-WmiObject -Class Win32_Processor | ft systemname,Name,DeviceID,NumberOfCores,NumberOfLogicalProcessors, AddressWidth #Finds processor information
  } '2' { 
      cls
      Write-Host "Which Option do you want?" #Asks for what kind of drive information the user wants
      Write-Host "1:Physical Disk Drives"
      Write-Host "2:Network Disk Drives"
      Write-Host "3:All Drives"

      $meluckydrives = Read-Host "Which option?" #Determines which drive information to obtain
      switch ($meluckydrives)
         {
          '1'{
              Get-WmiObject -Class Win32_logicaldisk -Filter "DriveType = '3'"
          } '2' {
              Get-WmiObject -Class Win32_logicaldisk -Filter "DriveType = '4'"
          } '3' {
              Get-WmiObject -Class Win32_logicaldisk              
        } 
     }

  }'3' {
      
  } '4' {
      Get-WmiObject Win32_Bios
  } '5' {
      Write-Host "---------Hard Drives---------"
      Get-WmiObject -Class Win32_logicaldisk
      Write-Host "------BIOS Information-------"
      Get-WmiObject Win32_Bios
      Write-Host "-------CPU Information-------"
      Get-WmiObject -Class Win32_Processor | ft systemname,Name,DeviceID,NumberOfCores,NumberOfLogicalProcessors, AddressWidth
  } '6' {
      return
      }
   }
}
until ($hardwares -eq '6') #Keeps loop going until user hits the 6 key

function Drive-Part
{
    param (
    [string]$partTitle = 'Welcome to Partitioning'
    )
    cls
    Write-Host "==============$partTitle=============="
}

function Local-Account
{
    param (
    [string]$locaccTitle = 'Welcome to Local Account Management'
    )
    cls
    Write-Host "==============$locaccTitle=============="
}

function Group-Policy
{
    param (
    [string]$gppyTitle = 'Welcome to Group Policy'
    )
    cls
    Write-Host "==============$gppyTitle=============="
}

function Trble-Shoot
{
    param (
    [string]$trbsTitle = 'Welcome to Troubleshooting'
    )
    cls
    Write-Host "==============$trbsTitle=============="
}

function DNS-Mgmt
{
    param (
    [string]$dnsmTitle = 'Welcome to DNS Management'
    )
    cls
    Write-Host "==============$dnsmTitle=============="
    ''
    Write-Host "1: Add new record"
    Write-Host "2: Delete record"
    Write-Host "3: Full backup"
    Wirte-Host "99: QUIT"
    ''
   do
   {
    $din = Read-Host "Wat we doin? "
    switch ($din)
    {
        '1' 
            {
                
                $name = Read-Host "What is the name of the box? "
                $zone = Read-Host "What is the name of the Zone? "
                $addr = Read-Host "What is the IPv4 address of the target? "

                Add-DnsServerResourceRecordA -Name $name -ZoneName $zone -IPv4Address $addr
            
            }
        '2' 
            {
                
                $zone = Read-Host "What is the name of the Zone? "   
                $name = Read-Host "What is the name of the box? "

                Remove-DnsServerResourceRecord -ZoneName $zone -RRType "A" -Name $name

            }
        '3' 
            {

                $zone = Read-Host "What is the name of the DNS server? "
                $fname = Read-Host "what is the name of the file to save to? "
                
                Export-DnsServerZone -Name $zone -FileName $fname

            }
        '99'
            {
            return
            }
        }
    }
    until ($din -eq '99')
}



function Rst-Pnt #function for restore points
{
    param (
    [string]$rstTitle = 'Welcome to Restore Point Management' #title
    )
    cls
    Write-Host "==============$rstTitle=============="

    $pin = Read-Host "Do you want to Create or Revert (c/r) "
    switch ($pin)
    {
        'c' {
            cls
            $desc = Read-Host "What is the point description? " #describes the restore point
			''
            Write-Host "==========Types========="
            ''
			#Various restore point types that are used
			Write-Host "1:Application_Install"
			Write-Host "2:Application_Uninstall"
			Write-Host "3:Device_Driver_Install"
			Write-Host "4:Modify_Settings"
			Write-Host "5:Cancelled_Operation"
			''
            $type = Read-Host "What is the type of restore point?"
            
            switch($type)
            {
                '1'
                    { 
                        Checkpoint-Computer -Description "$desc" -RestorePointType "Application_Install" -Verbose #creates the restore point
                	}		
                '2'
                    {
                        Checkpoint-Computer -Description "$desc" -RestorePointType "Application_Uninstall" -Verbose #creates the restore point
                    }
                '3'
                    {
                        Checkpoint-Computer -Description "$desc" -RestorePointType "Device_Driver_Install" -Verbose #creates the restore point
                    }
                '4'
                    {
                        Checkpoint-Computer -Description "$desc" -RestorePointType "Modify_Settings" -Verbose #creates the restore point
                    }
                '5'
                    {
                        Checkpoint-Computer -Description "$desc" -RestorePointType "Cancelled_Operation" -Verbose #creates the restore point
                    }
        } 'r' 
            {
            cls
            $rest = Read-Host "Go back to previously created restore point (y/n): "
            IF ($rest -eq 'y')
                {
                    Restore-Computer -RestorePoint (Get-ComputerRestorePoint)[-1].sequencenumber #automatically go back to the previous restore point
                }
            ELSEIF ($rest -eq 'n')
                {
			    #Dumps a list of all restore points and lets the user go back to the desired one
                Get-ComputerRestorePoint | Format-List
                $seq = Read-Host "What is the SEQUENCE number? "
                Restore-Computer -RestorePoint "$seq" #goes back to the chosen restore point
        
                }

        }
    }
  }
}

#End of Tools

#Menu Functions

function Main-Menu #Function Building the main menu
{
	param (
		[string]$Title = 'Welcome to Toasty Security Maintenance Kit' #Creates the title of the maintenance kit
	)
	cls #Clears the terminal screen so the menu is the only thing displayed
	Write-Host "++++++++++++++++++++++++++++++++++++++++++++++++++++++" #Full menu
	Write-Host "++++++$Title++++++"
	
	Write-Host "1: Manage Users and Groups" #Option for choosing to maipulate users and computers
	Write-Host "2: Security Options" #Tools for security
	Write-Host "3: Manage Software" #Tools for managing software on local and remote systems
	Write-Host "4: Local Options"
	Write-Host "99: Quit"
}

function User-Menu #Function for User interaction
{
	param (
		[string]$uTitle = 'User Menu' #Creates the title of the user menu
	)
	cls #Clears the terminal screen so the menu is the only thing displayed
	Write-Host "++++++++++++++++++++++++++++++++++++++++++++++++++++++" #Full menu
	Write-Host "++++++++++++++++++++$uTitle+++++++++++++++++++++++++"
	
	Write-Host "1: Add Users" #Lets the Admin create users on the domain
	Write-Host "2: Disable / Remove Users" #Lets the Admin delete or disable user accounts
	Write-Host "3: Change passwords" #Lets the admin quickly change user passwords
	Write-Host "4: Modify Groups and Permissions" #Edits groups
	Write-Host "5: Main Menu" #Return to the main menu
	
	do #Starts the User menu
{
	$uin = Read-Host "Who we gonna mess with? " #Prompts for user input
	switch ($uin) #Tells the script to start reading for input
	{
		'1'{ #Launches the user configuration tools
			cls
			Add-User
		} '2' { #Launches the disabling/deleting tools
			cls
			DR-User
		} '3' { #Launches the password changing menu
			cls
			Chng-Psswd
		} '4' { #Launches the groups and permissions menu
			cls
			Group-Perms
		} '99' { #Saves the value to tell the loop to move on and break
			return
		}
	}
	pause #Tells the script to wait for input
}
until ($in -eq '99') #Breaks the loop
}

function Sec-Menu #Function for security options
{
	param (
		[string]$sTitle = 'Security Menu' #Creates the title of the security menu
	)
	cls #Clears the terminal screen so the menu is the only thing displayed
	Write-Host "++++++++++++++++++++++++++++++++++++++++++++++++++++++" #Full menu
	Write-Host "+++++++++++++++++++++$sTitle++++++++++++++++++++"
	
	Write-Host "1: Port scan" #Fires off a customized port scan
	Write-Host "2: Firewall Configuration" #Configuration options for the firewall
	Write-Host "3: Group Policy Update" #Forces a remote update of the group policy
	Write-Host "4: Main Menu" #Return to the main menu

do #Starts the security menu
{
	$sin = Read-Host "Batton down the hatches! " #Prompts for user input
	switch ($sin) #Tells the script to start reading for input
	{
		'1'{ #Launches the port scan tools
			cls
			
            $scan = Read-Host "Full network scan or single host (f/s) "
            switch($scan)
                {
                    'f' {

                        cls
                        fPort-Scan

                    } 's' {

                        cls
                        sPort-Scan
                    
                    }
                }
            
		} '2' { #Launches the firewall tools
			cls
			Fire-Wall
		} '3' { #Launches the GPUPDATE tools
			cls
			GP-UPDATE
		} '4' { #Saves the value to tell the loop to move on and break
			return
		}
	}
	pause #Tells the script to wait for input
}
until ($in -eq '4') #Breaks the loop

}

function Software-Menu #Function for software options
{
	param (
		[string]$swTitle = 'Software Menu' #Creates the title of the software menu
	)
	cls #Clears the terminal screen so the menu is the only thing displayed
	Write-Host "++++++++++++++++++++++++++++++++++++++++++++++++++++++" #Full menu
	Write-Host "++++++++++++++++++++$swTitle+++++++++++++++++++++"
	
	Write-Host "1: Schedule Tasks" #Modify local scheduled tasks
	Write-Host "2: Remove Software" #Lets the admin remotely uninstall software
	Write-Host "3: Install Software" #Lets the admin remotely install software
	Write-Host "4: Hashing" #Lets the admin hash files for integrity check
	Write-Host "5: Main Menu" #Return to the main menu

do #Starts the Software menu
{
	$swin = Read-Host "Did you mean to install that?: " #Prompts for user input
	switch ($swin) #Tells the script to start reading for input
	{
		'1'{ #Launches task scheduler
			cls
			Tsk-Schd
		} '2' { #Launches the remote removal tools
			cls
			Uninst-Soft
		} '3' { #Launches the remote install tools
			cls
			Inst-Soft
		} '4' { #Launches hashing tools
			cls
			Hash-stuff
		} '5' { #Saves the value to tell the loop to move on and break
			return
		}
	}
	pause #Tells the script to wait for input
}
until ($in -eq '5') #Breaks the loop

}

function Local-Menu #Function for local configurations
{
	param (
		[string]$lTitle = 'Local Menu' #Creates the title of the local menu
	)
	cls #Clears the terminal screen so the menu is the only thing displayed
	Write-Host "++++++++++++++++++++++++++++++++++++++++++++++++++++++" #Full menu
	Write-Host "++++++++++++++++++++++$lTitle++++++++++++++++++++++"
	
	Write-Host "1: Hardware Information" #retrieves hardware information
	Write-Host "2: Hard Drive Partitioning" #Lets the admin partition the hard drive
	Write-Host "3: Local Account Management" #Lets the admin manage the local account
	Write-Host "4: Group Policy Management" #Manage GPOs
	Write-Host "5: Troubleshooting tools" #Used to troubleshoot the system
	Write-Host "6: DNS Management" #Allows for DNS configuration and modification
    Write-Host "7: Restore Points" #Allows the admin to make restore points
	Write-Host "8: Main Menu" #Return to the main menu

do #Starts the local menu
{
	$lin = Read-Host "Home sweet home: " #Prompts for user input
	switch ($lin) #Tells the script to start reading for input
	{
		'1'{ #Launches the hardware triage tools
			cls
			Hardware-Info
		} '2' { #Launches the partitioning tools
			cls
			Drive-Part
		} '3' { #Launches the local account management tools
			cls
			Local-Account
		} '4' { #Launches the group policy tools
			cls
			Group-Policy
		} '5' { #Launches the troubleshooting tools
			cls
			Trble-Shoot
		} '6' { #Launches the DNS tools
			cls
			DNS-Mgmt
        } '7' {
            cls
            Rst-Pnt
		} '8' { #Saves the value to tell the loop to move on and break
			return
		}
	}
	pause #Tells the script to wait for input
}
until ($in -eq '7') #Breaks the loop

}


#End of Menus


do #Starts the main script
{
	Main-Menu #Calls the Main-Menu function
	$in = Read-Host "What is thy bidding?: " #Prompts for user input
	switch ($in) #Tells the script to start reading for input
	{
		'1'{ #Launches the user configuration tools
			cls
			User-Menu
		} '2' { #Launches the security configuration tools
			cls
			Sec-Menu
		} '3' { #Launches the software configuration tools
			cls
			Software-Menu
		} '4' { #Launches the local configuration tools
			cls
			Local-Menu
		} '5' { #Saves the value to tell the loop to move on and break
			return
		}
	}
	pause #Tells the script to wait for input
}
until ($in -eq '5') #Breaks the loop
[Environment]::Exit(1) #Kills the script and Tells the OS to kill the process
