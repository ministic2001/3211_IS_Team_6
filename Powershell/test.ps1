# CSV file structure should be:
# Username,Password
# user1,pass1

# Import a CSV file with credentials
$credentialFile = Import-Csv -Path "Powershell\credentials.csv"
# Define IP address
#$ip = "172.16.2.223"
$ip = "172.16.2.77"

# Get the first set of credentials from the CSV file
foreach ($credential in $credentialFile) {
    $username = $credential.Username
    $password = ConvertTo-SecureString $credential.Password -AsPlainText -Force
    $credentialObject = New-Object System.Management.Automation.PSCredential($username, $password)
    break
}

# Start a new PSSession with the IP address and the credentials
New-PSSession -ComputerName $ip -Credential $credentialObject
# Invoke Get-Process on the remote machine and save it to a text file
Invoke-Command -ComputerName $ip -Credential $credentialObject -ScriptBlock {Get-Process} | Out-File -FilePath "Powershell\Get-Process.txt"
# Close the PSSession that we started
Exit-PSSession
