Write-Output "______________________"
Write-Output "*********************"
Write-Output "@Ianwolf99"
Write-Output "POWERSHELL OFFSYSTEM"
Write-Output "**********************"
Write-Output ""       


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


Write-Output ""
Write-Output "-------------------------------"
Write-Output ""
Write-Output "LOCAL ADMIN INFORMATION"
Write-Output "-----------------------"
Write-Output ""

net localgroup Administrators


Write-Output ""
Write-Output "-------------------------------"
Write-Output ""
Write-Output "LOCAL USERS INFORMATION"
Write-Output "-----------------------"
Write-Output ""

net users

Write-Output ""
Write-Output "-------------------------------"
Write-Output ""
Write-Output "CURRENT LOGGED IN USERS"
Write-Output "-----------------------"
Write-Output ""


query user /server:$SERVER


Write-Output ""
Write-Output "-------------------------------"
Write-Output ""
Write-Output "PROGRAM INFORMATION"
Write-Output "-------------------"
Write-Output ""

$progs = (dir "c:\program files").Name
$progs32 = (dir "c:\Program Files (x86)").Name
$allprogs = @($progs,$progs32)

$allprogs

Write-Output ""
Write-Output "-------------------------------"
Write-Output ""
Write-Output "SMBSHARE INFORMATION"
Write-Output "-------------------"
Write-Output ""

 Get-SmbShare


Write-Output ""
Write-Output "-------------------------------"
Write-Output ""
Write-Output "INTERNET ACCESS TEST"
Write-Output "-------------------"
Write-Output ""


$Publicip = (curl http://ipinfo.io/ip -UseBasicParsing).content
$internetcheckgoogle = (Test-NetConnection google.com -Port 443).TcpTestSucceeded
$internetcheckhackernews = (Test-NetConnection hackernews.com -Port 443).TcpTestSucceeded
$internetcheckMicro = (Test-NetConnection Microsoft.com -Port 443).TcpTestSucceeded

Write-Output "Public IP: $Publicip"
Write-Output ""
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
#Write-OutPut""
#Write-OutPut "*********************"
#Write-OutPut""
#Write-OutPut"ShutDown machine and wait reboot "
#Write-OutPut"**********************"
#Write-OutPut""

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

cmd /c wmic startup