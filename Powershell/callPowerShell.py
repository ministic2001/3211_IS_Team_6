import subprocess
import platform
import os
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

def callPowershellScript(script_path):
    """
    Helper function to call a PowerShell script with arguments.

    Args:
        script_path (string): The path to the PowerShell script to run.
    """

    ps_executable = getPowershellPath()

    # Construct the PowerShell execution command based on the OS
    if platform.system() == "Windows":
        invoked_command = [
            ps_executable,
            '-NoProfile',
            '-ExecutionPolicy',
            'Bypass',
            '-File',
            script_path,
            '-Verb',
            'RunAs'
        ]
    else:
        invoked_command = [
            ps_executable,
            '-NoProfile',
            '-ExecutionPolicy',
            'Bypass',
            '-File',
            script_path
        ]

    # Run the PowerShell script
    subprocess.run(invoked_command)

callPowershellScript("Powershell\\baseScriptElevated.ps1")
