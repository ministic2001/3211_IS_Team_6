#!/bin/sh

# Description: This file/script would decrypt the files encrypted by the ransomware
# Tag: Decrypt Files  
sshpass -p 'Student12345@' ssh student@172.16.2.223 -o ConnectTimeout=5 "C:\Windows\Temp\SmartMetertest\AttackScript.exe 11 5"
