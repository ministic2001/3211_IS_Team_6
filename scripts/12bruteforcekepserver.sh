#!/bin/sh

# Description: This file/script would attempt to execute a Password Bruteforce attack to get the login password for the KepServer Software
# Tag: Bruteforce KepServer Login Password
sshpass -p 'Student12345@' ssh -o ConnectTimeout=5 student@172.16.2.223 "cd \"C:\Windows\Temp\SmartMetertest\" && AttackScript.exe 12"
