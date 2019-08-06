$cred  =Get-Credential
$Computers = get-content "c:\Results\serverlist.txt"
$path = "C:\Results"   
foreach ($Computer in $Computers)  
{ 
$cim = New-CimSession -ComputerName $Computer -Credential $cred 
Get-SmbShare -CimSession $cim | export-csv $path\SMBShare_Report.csv -NoTypeInformation -UseCulture


$admins = Get-WmiObject win32_groupuser –computer $Computer  
$admins = $admins |? {$_.groupcomponent –like '*"Administrators"'}  
  
$admins |% {  
$_.partcomponent –match “.+Domain\=(.+)\,Name\=(.+)$” > $nul  
$matches[1].trim('"') + “\” + $matches[2].trim('"')  }  | out-file -append $path\Admins_Report.csv 


Get-WmiObject Win32_ComputerSystem -ComputerName $Computer -Credential $cred | select name,Domain | Out-File -Append $path\Domain_Report.csv 

Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $Computer -Credential $cred | Format-List @{ Label="Computer Name"; Expression= { $_.__SERVER }}, IPEnabled, Description, MACAddress, IPAddress, IPSubnet, DefaultIPGateway, DHCPEnabled, DHCPServer, @{ Label="DHCP Lease Expires"; Expression= { [dateTime]$_.DHCPLeaseExpires }}, @{ Label="DHCP Lease Obtained"; Expression= { [dateTime]$_.DHCPLeaseObtained }} | Out-File -Append $path\IP_Report.csv
 
Get-NetRoute -CimSession $cim| Export-Csv $path\RouteTable_Report.csv -NoTypeInformation -UseCulture

Get-Service -ComputerName $computer  | select PSComputerName,DisplayName,Name,Status  | Export-Csv $path\Services_Report.csv -NoTypeInformation -UseCulture
Get-WmiObject Win32_Processor -ComputerName $computer | select PSComputerName,Name,Caption,DeviceID | Export-csv $path\CPUINFO_Report.csv -NoTypeInformation -UseCulture
if (test-Connection -ComputerName $computer  -Count 4 ) { Write-Output "$computer is up" | Out-File -Append $path\pinginfo_report.csv } else {Write-Output "$computer is down" | Out-File -Append $path\pinginfo_report.csv}

$Disks = Get-wmiobject  Win32_LogicalDisk -computername $Computer -ErrorAction SilentlyContinue -filter "DriveType= 3" -Credential $cred 
$Servername = (Get-wmiobject  CIM_ComputerSystem -ComputerName $computer).Name 
foreach ($objdisk in $Disks)  
{  
        $out=New-Object PSObject 
    $total=“{0:N0}” -f ($objDisk.Size/1GB)  
    $free=($objDisk.FreeSpace/1GB)  
    $freePercent=“{0:P0}” -f ([double]$objDisk.FreeSpace/[double]$objDisk.Size)  
        $out | Add-Member -MemberType NoteProperty -Name "Servername" -Value $Servername 
        $out | Add-Member -MemberType NoteProperty -Name "Drive" -Value $objDisk.DeviceID  
        $out | Add-Member -MemberType NoteProperty -Name "Total size (GB)" -Value $total 
        $out | Add-Member -MemberType NoteProperty -Name “Free Space (GB)” -Value $free 
        $out | Add-Member -MemberType NoteProperty -Name “Free Space (%)” -Value $freePercent 
        $out | Add-Member -MemberType NoteProperty -Name "Name " -Value $objdisk.volumename 
        $out | Add-Member -MemberType NoteProperty -Name "DriveType" -Value $objdisk.DriveType 
        $out | export-csv $path\Diskspace_Report.csv -NoTypeInformation -Append   
} 
 
$computer | Out-File -Append $path\KMS_Report.csv 
Write-Output "==============================================================================================" | Out-File -Append $path\KMS_Report.csv
Invoke-Command -ComputerName $computer -Credential $cred { 
cd c:\Windows\System32 
cscript slmgr.vbs /dli all } | Out-File -Append $path\KMS_Report.csv 
Write-Output "==============================================================================================" | Out-File -Append $path\KMS_Report.csv 
Write-Output "==============================================================================================" | Out-File -Append $path\KMS_Report.csv 
Write-Output "==============================================================================================" | Out-File -Append $path\KMS_Report.csv

$computer | Out-File -Append $path\CHKDISK_Report.csv
Write-Output "==============================================================================================" | Out-File -Append $path\CHKDISK_Report.csv
Invoke-Command -ComputerName $computer -Credential $cred {
chkdsk } | Out-File -Append $path\CHKDISK_Report.csv
Write-Output "==============================================================================================" | Out-File -Append $path\CHKDISK_Report.csv
Write-Output "==============================================================================================" | Out-File -Append $path\CHKDISK_Report.csv
Write-Output "==============================================================================================" | Out-File -Append $path\CHKDISK_Report.csv

Write-Output "==============================================================================================" | Out-File -Append $path\Systeminfo_Report.csv
$computer | Out-File -Append $path\Systeminfo_Report.csv
Invoke-Command -ComputerName $computer  -Credential $cred {
systeminfo.exe } | Out-File -Append $path\Systeminfo_Report.csv

Write-Output "==============================================================================================" | Out-File -Append c:\Results\Systeminfo_Report.csv
Write-Output "==============================================================================================" | Out-File -Append c:\Results\Systeminfo_Report.csv
Write-Output "==============================================================================================" | Out-File -Append c:\Results\Systeminfo_Report.csv

$Net = Invoke-Command -ComputerName $computer -Credential $cred { Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' | Get-ItemProperty -Name Version | select version -ExpandProperty Version } 
$Object = New-Object PSObject
$Object | add-member Noteproperty CompName $computer
$Object | add-member Noteproperty .NetVersion $Net
$Object| Export-Csv -Append c:\Results\Net_Report.csv -UseCulture -NoTypeInformation

Get-WmiObject win32_product -ComputerName $computer -Credential $cred  | select PSComputerName,Name,Version,Vendor | Export-Csv -Append $path\Software_Report.csv -UseCulture -NoTypeInformation

Get-HotFix -ComputerName $computer -Credential $cred  | export-csv $path\Patch_Report.csv -UseCulture -NoTypeInformation

}
