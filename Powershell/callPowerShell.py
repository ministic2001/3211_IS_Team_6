# Does not work on Windows with PowerShell 5.1 on cmd on PowerShell 7.3

import csv
import subprocess
import os
import platform
import shutil

def getPowershellPath():
    """
    Helper function to get the path to the PowerShell executable. If it doesn't exist, stop the whole program.

    Returns:
        string: The path to the PowerShell executable.
    """

    # Detect OS for PowerShell executable path (assumption, not final)
    ps_executable = None

    # Check Linux
    if platform.system() == "Linux":
        # Check if PowerShell is installed
        if os.path.exists("/usr/bin/pwsh"):
            ps_executable = "/usr/bin/pwsh"

    # Check Windows
    elif platform.system() == "Windows":
        # Check if Powershell 7 exists
        if os.path.exists("C:\\Program Files\\PowerShell\\7\\pwsh.EXE"):
            ps_executable = "C:\\Program Files\\PowerShell\\7\\pwsh.EXE"
        # Check if PowerShell 5.1 or lower exists
        elif os.path.exists("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"):
            ps_executable = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            print("Powershell 5.1 or below being used instead of Powershell 7")

    # Check macOS
    elif platform.system() == "Darwin":
        # Check if PowerShell is installed at the default location
        if os.path.exists("/usr/local/bin/pwsh"):
            ps_executable = "/usr/local/bin/pwsh"

    # If the path is still not found, use shutil to search for the executable
    if ps_executable is None:
        ps_executable = shutil.which("pwsh")

    # If PowerShell is still not found, stop the program
    if ps_executable is None:
        print("PowerShell is not installed on this system.")
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
    # Added $remoteSession = to command, revert if does not work
    subprocess.call('{} -Command \"$remoteSession = New-PSSession -ComputerName {} -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList {}, (ConvertTo-SecureString {} -AsPlainText -Force)\")'.format(ps_executable, ip, username, password), shell=True)
    # old code
    #subprocess.call('{} -Command \"New-PSSession -ComputerName {} -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList {}, (ConvertTo-SecureString {} -AsPlainText -Force)\")'.format(ps_executable, ip, username, password), shell=True)

    # If outFile is not None, then we want to write the output of the command to a file
    if outFile:
        # Open the file for writing
        with open(outFile, "w") as f:
            # old code, see testPowershellLocally
            #subprocess.call('{} -Command \"{}\"'.format(ps_executable, command), shell=True, stdout=f)
            subprocess.call('{} -Command "Invoke-Command -Session $remoteSession -ScriptBlock {{ {} }}"'.format(ps_executable, command), shell=True, stdout=f)
    # Else, just run and print the output of the command
    else:
        #subprocess.call('{} -Command \"{}\"'.format(ps_executable, command), shell=True)
        subprocess.call('{} -Command "Invoke-Command -Session $remoteSession -ScriptBlock {{ {} }}"'.format(ps_executable, command), shell=True)

    # print(('{} -Command \"New-PSSession -ComputerName {} -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList {}, (ConvertTo-SecureString {} -AsPlainText -Force)); $sb = [scriptblock]::Create(\'{}\'); Invoke-Command -Session $remoteSession -ScriptBlock $sb\"').format(ps_executable, ip, username, password, command))
    # subprocess.call(('{} -Command \"$remoteSession = New-PSSession -ComputerName {} -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList {}, (ConvertTo-SecureString {} -AsPlainText -Force)); $sb = [scriptblock]::Create(\'{}\'); Invoke-Command -Session $remoteSession -ScriptBlock $sb\"').format(ps_executable, ip, username, password, command))

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
            subprocess.call('{} -Command "Invoke-Command -ScriptBlock {{ {} }}"'.format(ps_executable, command), shell=True, stdout=f)
    # Else, just run and print the output of the command
    else:
        # old code
        #subprocess.call('{} -Command \"{}\"'.format(ps_executable, command), shell=True)
        print('{} -Command "Invoke-Command -ScriptBlock {{ {} }}"'.format(ps_executable, command))
        subprocess.call('{} -Command "Invoke-Command -ScriptBlock {{ {} }}"'.format(ps_executable, command), shell=True)


def runPowerShellScript(scriptPath, parameters=None, outFile=None):
    """
    Runs a PowerShell script and prints the output to the console.
    If outFile is specified, then the output of the command will be written to the file specified by outFile.

    Inputs:
        scriptPath: The path to the PowerShell script to run. Required.
        parameters: Any additional parameters to pass to the PowerShell script as a single string. Optional.
        outFile: The path to the file to write the output of the command to. Optional.
    """

    # Call the helper function to get the path to the PowerShell executable
    ps_executable = getPowershellPath()

    # Build the command to execute the PowerShell script with parameters
    command = [ps_executable, "-ExecutionPolicy", "Bypass", "-File", scriptPath]

    # If parameters are provided, add them to the command as a single string
    if parameters is not None:
        command.append(parameters)

    # Run the PowerShell script
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout, stderr = process.communicate()

    # Check if there were any errors
    if process.returncode != 0:
        print("An error occurred while executing the PowerShell script:")
        print(stderr.decode("utf-8"))
    else:
        print("PowerShell script executed successfully.")
        # If outFile is not None, then we want to write the output to a file
        if outFile:
            with open(outFile, "w") as f:
                f.write(stdout.decode("utf-8"))
        # Else, just print the output
        else:
            print(stdout.decode("utf-8"))


scriptPath = "Powershell\\test.ps1"
parameters = "Get-Process;Get-NetFirewallProfile -All | Select-Object -Property Name,Enabled"  # Pass the parameters as a single string
#parameters = "Get-Timezone;Get-Timezone"
runPowerShellScript(scriptPath, parameters)

# Demo of how to use the functions, uncomment each block to try it out

# Grab the services from the machine with IP 172.16.2.77
# startPowershellSession(ip='172.16.2.77', command='Get-TimeZone')

# Grab the services from your machine and save it to Powershell\Get-Service.csv
# testCmd = convertToCommand(command='Get-Service')
# testPowershellLocally(command=testCmd, outFile="Powershell\Get-Service.csv")

# Start Google Chrome in Dark Mode, Incognito, and navigate to https://www.google.com on your machine
# testCmd = convertToCommand(command='Start-Process', filePath="C:\Program Files\Google\Chrome\Application\Chrome.exe", parameters='--force-dark-mode --incognito --new-window https://www.google.com')
# testPowershellLocally(command=testCmd)

# Disable the Windows Firewall on the machine with IP 172.16.2.77 (not working due to permissions)
# startPowershellSession(ip='172.16.2.77', command='Set-NetFirewallProfile -All -Enabled False')
# testPowershellLocally(command='Set-NetFirewallProfile -All -Enabled False')

# Enable the Windows Firewall on the machine with IP 172.16.2.77 (not working due to permissions)
# startPowershellSession(ip='172.16.2.77', cmd='Set-NetFirewallProfile -All -Enabled True')

# Get the Windows Firewall status from your machine
#testPowershellLocally(command='Get-NetFirewallProfile -All | Select-Object -Property Name,Enabled')
#startPowershellSession(ip='172.16.2.77', command='Get-NetFirewallProfile -All | Select-Object -Property Name,Enabled')
