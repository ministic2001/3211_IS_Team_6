#!/bin/sh

# Description: This file/script demostrates the creation of a directory C:\Windows\Temp\SmartMetertest on the Smart Meter PC
# Tag: Create Directory    
sshpass -p 'Student12345@' ssh -t -o ConnectTimeout=5 student@172.16.2.223 "mkdir C:\Windows\Temp\SmartMetertest" && echo "Directory Created."  