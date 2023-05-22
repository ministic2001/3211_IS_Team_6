# Does not work on Windows with PowerShell 5.1 on cmd on PowerShell 7.3

import csv
import subprocess
import os
import platform

def getPowershellPath():
    """
    Helper function to get the path to the PowerShell executable. If it doesn't exist, stop the whole program.
    
    Returns:
        string: The path to the PowerShell executable.
    """

    # Detect OS for PowerShell executable path (assumption, not final)
    ps_executable = None
    # Check Linux
    if platform.system() == "Posix":
        # Check if PowerShell is installed
        if os.path.exists("/usr/bin/pwsh"):
            ps_executable = "/usr/bin/pwsh"
        else:
            print("PowerShell is not installed on this system.")
            exit()
    # Check Windows
    elif platform.system() == "Windows":
        # Check if PowerShell is installed
        if os.path.exists("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"):
            ps_executable = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        else:
            print("PowerShell is not installed on this system.")
            exit()
    # Check macOS
    elif platform.system() == "Darwin":
        # Check if PowerShell is installed
        if os.path.exists("/usr/local/bin/pwsh"):
            ps_executable = "/usr/local/bin/pwsh"
        else:
            print("PowerShell is not installed on this system.")
            exit()
    # Else, we don't know what OS this is
    else:
        print("Unknown OS. Cannot determine path to PowerShell executable.")
        exit()
    
    return ps_executable


def convertToCommand(command, filePath=None, parameters=None):
    """
    Helper function to convert a command and optional filePaths and parameters into a properly formatted PowerShell command.
    
    Inputs:
        command: The command to run. Required.
        filePath: The path to the file to run the command on. Optional.
        parameters: The parameters to the command. Optional.
    
    Returns:
        string: The command (and optional parameters) as a single string.
    """

    # If filePath is None, then we don't have a file to run the command on
    if filePath is None:
        # If parameters is None, then we don't have any parameters to the command
        if parameters is None:
            # Return just the command
            return command
        # Else, we have parameters to the command
        else:
            # Return the command and parameters
            return "{} -ArgumentList \'{}\'".format(command, parameters)
    # Else, we have a file to run the command on
    else:
        # If parameters is None, then we don't have any parameters to the command
        if parameters is None:
            # Return the command and file path
            return "{} -FilePath \'{}\'".format(command, filePath)
        # Else, we have parameters to the command
        else:
            # Return the command, file path, and parameters
            return "{} -FilePath \'{}\' -ArgumentList \'{}\'".format(command, filePath, parameters)


def startPowershellSession(ip, command, outFile=None):
    """
    Starts a Powershell session, calls the specified command (with parameters if any), and prints the output to the console.
    If outFile is specified, then the output of the command will be written to the file specified by outFile.
    
    Inputs:
        ip: The IP address of the machine to run the command on. Required.
        command: The PowerShell command to run. Call convertToCommand to get the Powershell command string. Required.
        outFile: The path to the file to write the output of the command to. Optional.
    """

    # Call the helper function to get the path to the PowerShell executable
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
    subprocess.call('{} -Command \"New-PSSession -ComputerName {} -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList {}, (ConvertTo-SecureString {} -AsPlainText -Force)\")'.format(ps_executable, ip, username, password), shell=True)

    # If outFile is not None, then we want to write the output of the command to a file
    if outFile:
        # Open the file for writing
        with open(outFile, "w") as f:
            subprocess.call('{} -Command \"{}\"'.format(ps_executable, command), shell=True, stdout=f)
    # Else, just run and print the output of the command
    else:
        subprocess.call('{} -Command \"{}\"'.format(ps_executable, command), shell=True)

    # Exit the PSSession
    subprocess.call('{} -Command \"Exit-PSSession\"'.format(ps_executable), shell=True)


def testPowershellLocally(command, outFile=None):
    """
    Copy of startPowershellSession, but for testing PowerShell commands locally.
    Starts a Powershell session, calls the specified command (with parameters if any), and prints the output to the console.
    If outFile is specified, then the output of the command will be written to the file specified by outFile.

    Inputs:
        command: The PowerShell command to run. Call convertToCommand to get the Powershell command string. Required.
        outFile: The path to the file to write the output of the command to. Optional.
    """
    
    # Call the helper function to get the path to the PowerShell executable
    ps_executable = getPowershellPath()

    # If outFile is not None, then we want to write the output of the command to a file
    if outFile:
        # Open the file for writing
        with open(outFile, "w") as f:
            # Run the command and write the output to the file
            subprocess.call('{} -Command \"{}\"'.format(ps_executable, command), shell=True, stdout=f)
    # Else, just run and print the output of the command
    else:
        print('{} -Command \"{}\"'.format(ps_executable, command))
        subprocess.call('{} -Command \"{}\"'.format(ps_executable, command), shell=True)


# Demo of how to use the functions, uncomment each block to try it out

# Grab the services from the machine with IP 172.16.2.77
# startPowershellSession(ip='172.16.2.77', command='Get-Service')

# Grab the services from your machine and save it to Powershell\Get-Service.csv
# testCmd = convertToCommand(command='Get-Service | Export-CSV -Path "Powershell\\Get-Service.csv"')
# testPowershellLocally(command=testCmd)

# Start Google Chrome in Dark Mode, Incognito, and navigate to https://www.google.com on your machine
# testCmd = convertToCommand(command='Start-Process', filePath="C:\Program Files\Google\Chrome\Application\Chrome.exe", parameters='--force-dark-mode --incognito --new-window https://www.google.com')
# testPowershellLocally(command=testCmd)

# Disable the Windows Firewall on the machine with IP 172.16.2.77
# startPowershellSession(ip='172.16.2.77', command='Set-NetFirewallProfile -All -Enabled False')
# testPowershellLocally(command='Set-NetFirewallProfile -All -Enabled False')

# Enable the Windows Firewall on the machine with IP 172.16.2.77
# startPowershellSession(ip='172.16.2.77', cmd='Set-NetFirewallProfile -All -Enabled True')
