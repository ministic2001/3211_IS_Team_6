# 3211_IS_Team_6

To install the packages, type the command pip install -r requirements.txt.
Python 3.10 is required for this to work.
If you do not have Powershell 7, please install that first 

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

Python 3.10 is required for this to work.

## Gaining Access to the Windows
```
The credentials.csv should only have the headers (Username,Password) at the start
Run bruteforceWindowsOS.ps1 to get the credentials and write it to the credentials.csv
Afterwards the credentials.csv will contain the credentials in the format (user1,pass1)
You can then run baseScriptElevated.ps1
You can also run callPowerShell.py to call baseScriptElevated.ps1
```
