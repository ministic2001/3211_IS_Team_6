#!/bin/sh

# Description: This file/script demostrates the Change of Meter25 Id back to 25 from 26   
# Tag: Change Meter25 Id back to 25 from 26      
sshpass -p 'Student12345@' ssh student@172.16.2.223 -o ConnectTimeout=5 "cd \"C:\Windows\Temp\SmartMetertest\" && Attackscript.exe 11 6"
