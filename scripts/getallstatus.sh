#!/bin/sh


# Description: This file/script displays the status of the Firewall
# Tag: Get Windows Defender Status  
sshpass -p 'Student12345@' ssh student@172.16.2.223 -o ConnectTimeout=5 "powershell -command \"Get-MpComputerStatus | select Antivirusenabled\" "

# # Description: This file/script displays the status of services on the Windows Host Machine
# # Tag: Get KepServer Service Status   
sshpass -p 'Student12345@' ssh student@172.16.2.223 -o ConnectTimeout=5 "powershell -command \"Get-Service KEPServerEXV6 | Select-Object -Property Status\" "

# Description: This file/script displays the status of the Firewall
# Tag: Get Firewall Windows Firewall Status
sshpass -p 'Student12345@' ssh student@172.16.2.223 -o ConnectTimeout=5 "netsh advfirewall show allprofiles state"

#student@192.168.62.3 , student@172.16.2.223