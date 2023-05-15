#!/bin/sh

# Description: This file/script would change the baudrate via modpolling
# Tag: Baudrate  
sshpass -p 'Student12345@' ssh student@172.16.2.223 -o ConnectTimeout=5 "C:\Windows\Temp\SmartMetertest\AttackScript.exe 13"
