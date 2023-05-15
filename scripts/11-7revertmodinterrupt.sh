#!/bin/sh

# Description: This file/script would stop the Mod Bus Interrupt polling DoS Attack on the Smart Meter PC 
# Tag: Stop Mod Bus Interrupt Attack 
sshpass -p 'Student12345@' ssh -o ConnectTimeout=5 student@172.16.2.223 "C:\Windows\Temp\SmartMetertest\AttackScript.exe 11 7"
