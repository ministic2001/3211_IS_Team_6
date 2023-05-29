# 3211_IS_Team_6

## Requirements
To install the packages, type the command pip install -r requirements.txt.

Python 3.10 is required for this to work.

If you do not have Powershell 7, please install that first.

### On Windows (Install Winget via Microsoft Store first)
```
# Install Powershell via Winget
winget install --id Microsoft.Powershell --source winget
# Start PowerShell
pwsh

# Update Powershell via Winget
winget upgrade --id Microsoft.Powershell --source winget
```

### On Linux (Ubuntu)
```
# Update the list of packages
sudo apt-get update
# Install pre-requisite packages.
sudo apt-get install -y wget apt-transport-https software-properties-common
# Download the Microsoft repository GPG keys
wget -q "https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb"
# Register the Microsoft repository GPG keys
sudo dpkg -i packages-microsoft-prod.deb
# Delete the the Microsoft repository GPG keys file
rm packages-microsoft-prod.deb
# Update the list of packages after we added packages.microsoft.com
sudo apt-get update
# Install PowerShell
sudo apt-get install -y powershell
# Start PowerShell
pwsh

# Update Powershell via apt-get
sudo apt-get update
apt-get install --only-upgrade powershell
```

### On MacOS
```
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
# Install Powershell via Homebrew
brew cask install powershell
# Start PowerShell
pwsh

# Update Powershell via Homebrew
brew update
brew upgrade powershell --cask
```

## Gaining Access to the Windows target
```
The credentials.csv should only have the headers (Username,Password) at the start
Run bruteforceWindowsOS.ps1 to get the credentials and write it to the credentials.csv
Afterwards the credentials.csv will contain the credentials in the format (user1,pass1)
You can then run baseScriptElevated.ps1
You can also run callPowerShell.py to call baseScriptElevated.ps1
```

Todo:
- [x] Powershell connection to the target does not key in password automatically. To resolve using private key authentication.
- [x] Fallback commands for Windows if using Powershell 5.1 or below.
- [x] Edit the methods to use the new way of connecting in Powershell 7.