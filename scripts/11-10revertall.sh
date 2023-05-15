#!/bin/sh

# Description: This file/script would revert all changes made to the Smart Meter PC
# Tag: Revert all changes to system    
sshpass -p 'Student12345@' ssh -t -o ConnectTimeout=5 student@172.16.2.223 "cd \"C:\Windows\Temp\SmartMetertest\" && Attackscript.exe 11 10"
