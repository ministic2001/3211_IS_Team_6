#!/bin/sh

# Description: This file/script would be responsible for re-enabling the comport on the Smart Meter PC
# Tag: Re-enable Com Port    
sshpass -p 'Student12345@' ssh student@172.16.2.223 -o ConnectTimeout=5 "C:\Windows\Temp\SmartMetertest\AttackScript.exe 11 4"
