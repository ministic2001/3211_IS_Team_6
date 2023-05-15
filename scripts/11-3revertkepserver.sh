#!/bin/sh

# Description: This file/script is responsible for reverting the status of Kepserver from stopped to running
# Tag: Re-enable Kepserver Service    
sshpass -p 'Student12345@' ssh student@172.16.2.223 -o ConnectTimeout=5 "C:\Windows\Temp\SmartMetertest\AttackScript.exe 11 3"
