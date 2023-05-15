#!/bin/sh

# Description: This file/script would revert the firewall status of the affected Smart Meter PC
# Tag: Re-enable Windows Firewall    
sshpass -p 'Student12345@' ssh student@172.16.2.223 -o ConnectTimeout=5 "C:\Windows\Temp\SmartMetertest\AttackScript.exe 11 1"
