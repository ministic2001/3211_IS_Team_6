# Does not work on Windows with PowerShell 5.1 on cmd on PowerShell 7.3

import csv
import subprocess
import os

def getPowershellPath():
    """
    Helper function to get the path to the PowerShell executable. If it doesn't exist, stop the whole program.
    Returns:
        string: The path to the PowerShell executable.
    """

    # Detect OS for PowerShell executable path
    ps_executable = None
    # Check Linux
    if os.name == "posix":
        # Check if PowerShell is installed
        if os.path.exists("/usr/bin/powershell"):
            ps_executable = "/usr/bin/powershell"
        else:
            print("PowerShell is not installed on this system.")
            exit()
    # Check Windows
    elif os.name == "nt":
        # Check if PowerShell is installed
        if os.path.exists("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"):
            ps_executable = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        else:
            print("PowerShell is not installed on this system.")
            exit()
    # Check macOS
    elif os.name == "darwin":
        # Check if PowerShell is installed
        if os.path.exists("/usr/local/bin/powershell"):
            ps_executable = "/usr/local/bin/powershell"
        else:
            print("PowerShell is not installed on this system.")
            exit()
    # Else, we don't know what OS this is
    else:
        print("Unknown OS. Cannot determine path to PowerShell executable.")
        exit()
    
    return ps_executable

def callPowerShell(ip, command, outFile=None):
    """
    Calls a PowerShell command and prints the output to the console.
    If outFile is not None, then the output of the command will be written to the file specified by outFile.
    Inputs:
        command: The PowerShell command to run.
        outFile: The path to the file to write the output of the command to.
    """

    ps_executable = getPowershellPath()

    # Import a CSV file with credentials
    with open("Powershell\credentials.csv", "r") as csv_file:
        # Read the first line of the CSV
            csv_reader = csv.DictReader(csv_file)
            for credRow in csv_reader:
                break  # Read only the first data row

    # Define username and password
    username = credRow["Username"]
    password = credRow["Password"]
    # Create the PSSession (Broken on Windows with PS 5.1 on cmd on PS 7.3)
    subprocess.call("{} New-PSSession -ComputerName {} -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList {}, (ConvertTo-SecureString {} -AsPlainText -Force))".format(ps_executable, ip, username, password), shell=True)

    # If outFile is not None, then we want to write the output of the command to a file
    if outFile:
        # Open the file for writing
        with open(outFile, "w") as f:
            # Run the command and write the output to the file
            subprocess.call("{} {}".format(ps_executable, command), shell=True, stdout=f)
    # Else, just run and print the output of the command
    else:
        subprocess.call("{} {}".format(ps_executable, command), shell=True)

    # Exit the PSSession
    subprocess.call("{} Exit-PSSession".format(ps_executable), shell=True)

callPowerShell("172.16.2.77", "Get-Service")
