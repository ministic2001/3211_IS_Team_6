#!/bin/sh

# Description: This file/script's purpose is to get relavant infomation on the Smart Meter PC
# Tag: Get Smart Meter PC Info   
sshpass -p 'Student12345@' ssh -o ConnectTimeout=5 student@172.16.2.223 "C:\Windows\Temp\SmartMetertest\ReconScript.exe"
