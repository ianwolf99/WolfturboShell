Write-Output "______________________"
Write-Output "*********************"
Write-Output "@Ianwolf99"
Write-Output "POWERSHELL OFFSYSTEM"
Write-Output "**********************"
Write-Output "https://github.com/ianwolf99/WolfturboShell.git"       


$user = whoami
$currenthost = hostname 
$networkinfo = (Get-NetIPAddress).IPAddress

$env:computername
$env:userdomain

Write-Output "_________________________________"
Write-Output "User: $user"
Write-Output "Hostname: $currenthost"
Write-Output "___________________________________"
Write-Output "Network IP/s:"
$networkinfo
Write-Output "___________________________________"
Write-Output "Getting details on $user......"

whoami /all


Write-Output "___________________________________"
Write-Output "-------------------------------"
Write-Output "___________________________________"
Write-Output "LOCAL ADMIN INFORMATION"
Write-Output "-----------------------"
Write-Output "___________________________________"

net localgroup Administrators


Write-Output ""
Write-Output "-------------------------------"
Write-Output "_______________________________"
Write-Output "LOCAL USERS INFORMATION"
Write-Output "-----------------------"
Write-Output "______________________________"

net users

Write-Output "___________________________________"
Write-Output "-------------------------------"
Write-Output "___________________________________"
Write-Output "CURRENT LOGGED IN USERS"
Write-Output "-----------------------"
Write-Output "___________________________________"


query user /server:$SERVER


Write-Output "___________________________________"
Write-Output "-------------------------------"
Write-Output "___________________________________"
Write-Output "PROGRAM INFORMATION"
Write-Output "-------------------"
Write-Output "____________________________________"

$programs = (dir "c:\program files").Name
$programs32 = (dir "c:\Program Files (x86)").Name
$allprogs = @($programs,$programs32)

$allprogs

Write-Output "________________________________"
Write-Output "-------------------------------"
Write-Output "________________________________"
Write-Output "SMBSHARE INFORMATION"
Write-Output "-------------------"
Write-Output "_________________________________"

 Get-SmbShare


Write-Output "_________________________________"
Write-Output "-------------------------------"
Write-Output "_________________________________"
Write-Output "INTERNET ACCESS TEST"
Write-Output "-------------------"
Write-Output "__________________________________"


$Publicip = (curl http://ipinfo.io/ip -UseBasicParsing).content
$internetcheckgoogle = (Test-NetConnection google.com -Port 443).TcpTestSucceeded
$internetcheckhackernews = (Test-NetConnection hackernews.com -Port 443).TcpTestSucceeded
$internetcheckMicro = (Test-NetConnection Microsoft.com -Port 443).TcpTestSucceeded

Write-Output "Public IP: $Publicip"
Write-Output "_________________________________"
Write-Output "Can I Reach Google: $internetcheckgoogle"
Write-Output "Can I Reach Hacker news: $internetcheckhackernews"
Write-Output "Can I Reach Microsoft: $internetcheckMicro"


Write-Output "_______________________________"
Write-Output "-------------------------------"
Write-Output "________________________________"
Write-Output "FIREWALL INFORMATION (Blocks)"
Write-Output "-------------------"
Write-Output "________________________________"

#$firewall = New-Object -com HNetCf.FwMgr
#$private = $firewall.localpolicy.getprofilebytetype(0)
#$private | fl
Get-netfirewallrule

Write-Output "_______________________"
Write-Output "*********************"
Write-Output "________________________"
Write-Output "BIOS information"
Write-Output "**********************"
Write-Output "_________________________"

Get-wmiobject -Class win32_BIOS | ft

Write-Output "______________________"
Write-Output "*********************"
Write-Output "______________________"
Write-Output "Processor information"
Write-Output "**********************"
Write-Output ""

Get-wmiobject -Class win32_processor | fl

Write-Output "___________________________"
Write-Output "*********************"
Write-Output "___________________________"
Write-Output "Manufacturer and model information"
Write-Output "**********************"
Write-Output "_______________________________"

Get-wmiobject -Class win32_computersystem | ft

Write-Output "_______________________"
Write-Output "*********************"
Write-Output "_______________________"
Write-Output "Hotfix information"
Write-Output "**********************"
Write-Output "__________________________"

Get-wmiobject -Class win32_QuickFixEngineering | ft

Write-Output "___________________________________"
Write-Output "*********************"
Write-Output "__________________________________"
Write-Output "OS information"
Write-Output "**********************"
Write-OutPut "_____________________________________"

Get-wmiobject -Class win32_OperatingSystem

Write-Output "________________________"
Write-Output "*********************"
Write-Output "________________________"
Write-Output "DISK information"
Write-Output "**********************"
Write-Output "_________________________"

get-disk | fl

#last option to persist
#Write-OutPut"_________________________________"
#Write-OutPut "*********************"
#Write-OutPut""
#Write-OutPut"ShutDown machine and wait reboot for malware to load. "
#Write-OutPut"**********************"
#Write-OutPut"________________________________"

#(Get-wmiobject -Class win32_OperatingSystem -ComputerName.).Win32Shutdown(2)

Write-Output "___________________________"
Write-Output "*********************"
Write-Output "__________________________"
Write-Output "Process information"
Write-Output "**********************"
Write-OutPut "____________________________"

Get-Process | ft

Write-Output "___________________________"
Write-Output "*********************"
Write-Output "______________________"
Write-Output "Services information"
Write-Output "**********************"
Write-Output "________________________"

Get-Service | ft

Write-Output "__________________________"
Write-Output "*********************"
Write-Output "__________________________"
Write-Output "Network Adapter information"
Write-Output "**********************"
Write-Output "______________________________"

Get-NetAdapter | fl

Write-Output "__________________________"
Write-Output "*********************"
Write-Output "______________________________"
Write-Output "DISK information"
Write-Output "**********************"
Write-Output "_____________________________"

get-disk | fl

Write-Output "__________________________"
Write-Output "*********************"
Write-Output "______________________________"
Write-Output "Active Connections"
Write-Output "**********************"
Write-Output "_____________________________"

$net = Netstat
$net

Write-Output "__________________________"
Write-Output "*********************"
Write-Output "______________________________"
Write-Output "TCP Connections"
Write-Output "**********************"
Write-Output "_____________________________"

$conns = netsh interface ipv4 show tcpconnections
$conns

Write-Output "__________________________"
Write-Output "*********************"
Write-Output "______________________________"
Write-Output "Enviroment variables"
Write-Output "**********************"
Write-Output "_____________________________"

Get-ChildItem env:

Write-Output "__________________________"
Write-Output "*********************"
Write-Output "______________________________"
Write-Output "List Groups"
Write-Output "**********************"
Write-Output "_____________________________"

Get-wmiobject -Class win32_Group

Write-Output "__________________________"
Write-Output "*********************"
Write-Output "______________________________"
Write-Output "Physical memory"
Write-Output "**********************"
Write-Output "_____________________________"

Get-wmiobject -Class win32_PhysicalMemory

Write-Output "__________________________"
Write-Output "*********************"
Write-Output "______________________________"
Write-Output "Disk Partions"
Write-Output "**********************"
Write-Output "_____________________________"

Get-wmiobject -Class win32_diskpartition

Write-Output "__________________________"
Write-Output "*********************"
Write-Output "______________________________"
Write-Output "Logical Disk"
Write-Output "**********************"
Write-Output "_____________________________"

Get-wmiobject -Class win32_logicaldisk

Write-Output "__________________________"
Write-Output "*********************"
Write-Output "______________________________"
Write-Output "System Drivers"
Write-Output "******************"
Write-Output "_____________________________"

Get-wmiobject -Class win32_systemdriver

Write-Output "__________________________"
Write-Output "*********************"
Write-Output "______________________________"
Write-Output "PS Drive"
Write-Output "**********************"
Write-Output "_____________________________"

get-psdrive

Write-Output "__________________________"
Write-Output "*********************"
Write-Output "______________________________"
Write-Output "printers"
Write-Output "**********************"
Write-Output "_____________________________"

Get-wmiobject -Class win32_printer

Write-Output "__________________________"
Write-Output "*********************"
Write-Output "______________________________"
Write-Output "startups"
Write-Output "**********************"
Write-Output "_____________________________"

Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl;

Write-Output "__________________________"
Write-Output "*********************"
Write-Output "______________________________"
Write-Output "Software in Registry"
Write-Output "**********************"
Write-Output "_____________________________"

Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name;

