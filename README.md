<a name="readme-top"></a>

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]


<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/ministic2001/3211_IS_Team_6">
    <img src="images/logo-color.png" alt="Logo" width="300" height="300">
  </a>

<h3 align="center">PROJECTNAME</h3>

  <p align="center">
SHORT PROJ DESCRIPTION
    <br />
    <br />
  </p>
</div>

# 3211_IS_Team_6


<div align="center">
To ensure compatibility and install the required packages, please follow the steps below:

Make sure you have Python 3.10 installed on your system. If not, please install it first.
Open your terminal or command prompt.
Navigate to the directory where the requirements.txt file is located.
Install the packages using the following command:
```
pip install -r requirements.txt
```
If you don't have PowerShell 7 installed, please install it before proceeding.
Please note that Python 3.10 is required for this to work properly, and the specified packages will be installed based on the requirements.txt file.
</div>
<p align="right">(<a href="#readme-top">Back to top</a>)</p>

## Gaining Access to Windows

<div align="center">
  
The credentials.csv should only have the headers (Username,Password) at the start
Run bruteforceWindowsOS.ps1 to get the credentials and write it to the credentials.csv
Afterwards, the credentials.csv will contain the credentials in the format (user1,pass1)
You can then run baseScriptElevated.ps1
You can also run callPowerShell.py to call baseScriptElevated.ps1.
</div>
<p align="right">(<a href="#readme-top">Back to top</a>)</p>

<!-- ABOUT THE PROJECT -->
## About The Project
<div align="center">
  
![image](https://user-images.githubusercontent.com/91510432/226091643-2e4fc2a1-7bdb-463b-9479-8de2372c3c38.png)
</div>

<br />

<div align="center">

LONG DESCRIPTION OF PROJ 
</div>

<p align="right">(<a href="#readme-top">back to top</a>)</p>



### Built With

* [![Python][Python-logo]][Python-url]
* [![JavaScript][JavaScript-logo]][JavaScript-url]
* [![Node.js][Node-logo]][Node-url]
* [![npm][npm-logo]][npm-url]
* [![Django][Django-logo]][Django-url]
* [![PyTorch][PyTorch-logo]][PyTorch-url]
* [![spaCy][spaCy-logo]][spaCy-url]
* [![NLTK][NLTK-logo]][NLTK-url]
* [![Hugging Face Transformers][Transformers-logo]][Transformers-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- GETTING STARTED -->
# Getting Started

This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.
<p align="right">(<a href="#readme-top">back to top</a>)</p>

# Prerequisites
List of things you need, to use the software and how to install them.
<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Windows (Install Winget via Microsoft Store)

#### Install Powershell via Winget
```sh
winget install --id Microsoft.Powershell --source winget
```

#### Start PowerShell
```sh
pwsh
```

#### Update Powershell via Winget
```sh
winget upgrade --id Microsoft.Powershell --source winget
```
<p align="right">(<a href="#readme-top">back to top</a>)</p>


## Linux

#### Update the list of packages

```sh
sudo apt-get update
```

#### Install pre-requisite packages.
```sh
sudo apt-get install -y wget apt-transport-https software-properties-common
```

#### Download the Microsoft repository GPG keys
```sh
wget -q "https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb"
```

####  Register the Microsoft repository GPG keys
```sh	
sudo dpkg -i packages-microsoft-prod.deb
```

#### Delete the the Microsoft repository GPG keys file
```sh	
rm packages-microsoft-prod.deb
```

#### Update the list of packages after we added packages.microsoft.com
```sh	
sudo apt-get update
```

#### Install PowerShell
```sh
sudo apt-get install -y powershell
```

#### Start PowerShell
```sh
pwsh
```

#### Update Powershell via apt-get
```sh
sudo apt-get update
apt-get install --only-upgrade powershell
```
<p align="right">(<a href="#readme-top">back to top</a>)</p>

## MacOS

#### Install Homebrew
```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### Install Powershell via Homebrew
```sh
brew cask install powershell
```

#### Start PowerShell
```sh
pwsh
```

#### Update Powershell via Homebrew
```sh
brew update
brew upgrade powershell --cask
```
 <p align="right">(<a href="#readme-top">back to top</a>)</p>
<br />

## Setup SSH key on target machine
1. Create the SSH key pair
   ```sh
   cd .ssh
   ssh-keygen -t ed25519 -b 256 -f <sshKeyName> -q -N ""
   ```
2. Transfer the sshd_config file to your machine, edit, then transfer it back
   
   Changes made:
   ``` 
   PubkeyAuthentication yes
   PasswordAuthentication yes
   Subsystem powershell c:/progra~1/powershell/7/pwsh.exe -sshs -nologo
   # Match Group administrators
   #       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
   ```
   
   ```sh
   scp <user>@<ip>:C:\ProgramData\ssh\sshd_config sshd_config
   <Make above edits>
   scp sshd_config <user>@<ip>:C:\ProgramData\ssh\sshd_config
   ```
3. Transfer the contents of the SSH key to the target machine, and place it in the authorized_keys file
   ```sh
   scp accessKey.pub <user>@<ip>:C:\Users\<user>\.ssh\authorized_keys
   ```
4. SSH into the target machine and edit the ACL of the authorized_keys file, then restart the sshd service
   ```sh
   ssh <user>@<ip>
   $acl = Get-Acl C:\Users\<user>\.ssh\authorized_keys
   $acl.SetAccessRuleProtection($true, $false)
   $administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule("Administrators","FullControl","Allow")
   $systemRule = New-Object system.security.accesscontrol.filesystemaccessrule("SYSTEM","FullControl","Allow")
   $acl.SetAccessRule($administratorsRule)
   $acl.SetAccessRule($systemRule)
   $acl | Set-Acl
   Restart-Service sshd
   ```
   
5. Test the SSH access using the private key
   ```sh
   ssh -i <sshKeyName> <user>@<ip>
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Installation and Usage on Windows and Mac
1. Clone the repo
   ```sh
   git clone https://github.com/ministic2001/3211_IS_Team_6.git
   ```
2. Install python Dependencies
   ```sh
   pip install -r requirements.txt
   cd 3211_IS_Team_6
   ```
3. NEXT STEP
   ```js
   cd 3211_IS_Team_6/djangoserver
   python ./manage.py runserver
   ```
4. NEXT STEP
   ```js
   cd 3211_IS_Team_6/FalseGuardian
   npm run build 
   or 
   npm run watch 
   ```
   
5. NEXT STEP

   Navigate to the newly create /build folder
   
   Select the folder

6. NEXT STEP
![image](https://user-images.githubusercontent.com/91510432/226081051-62e905c3-9f15-4ba3-b398-5abba3e59afd.png)
The results would appear at the popup extension. 

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.md` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/ministic2001/3211_IS_Team_6.svg?style=for-the-badge
[contributors-url]: https://github.com/ministic2001/3211_IS_Team_6/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/ministic2001/3211_IS_Team_6.svg?style=for-the-badge
[forks-url]: https://github.com/ministic2001/3211_IS_Team_6/network/members
[stars-shield]: https://img.shields.io/github/stars/ministic2001/3211_IS_Team_6.svg?style=for-the-badge
[stars-url]: https://github.com/ministic2001/3211_IS_Team_6/stargazers
[issues-shield]: https://img.shields.io/github/issues/ministic2001/3211_IS_Team_6.svg?style=for-the-badge
[issues-url]: https://github.com/ministic2001/3211_IS_Team_6/issues
[license-shield]: https://img.shields.io/github/license/ministic2001/3211_IS_Team_6.svg?style=for-the-badge
[license-url]: https://github.com/ministic2001/3211_IS_Team_6/blob/master/LICENSE.md
[product-screenshot]: images/screenshot.png
[Next.js]: https://img.shields.io/badge/next.js-000000?style=for-the-badge&logo=nextdotjs&logoColor=white
[Next-url]: https://nextjs.org/
[React.js]: https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB
[React-url]: https://reactjs.org/
[Vue.js]: https://img.shields.io/badge/Vue.js-35495E?style=for-the-badge&logo=vuedotjs&logoColor=4FC08D
[Vue-url]: https://vuejs.org/
[Angular.io]: https://img.shields.io/badge/Angular-DD0031?style=for-the-badge&logo=angular&logoColor=white
[Angular-url]: https://angular.io/
[Svelte.dev]: https://img.shields.io/badge/Svelte-4A4A55?style=for-the-badge&logo=svelte&logoColor=FF3E00
[Svelte-url]: https://svelte.dev/
[Laravel.com]: https://img.shields.io/badge/Laravel-FF2D20?style=for-the-badge&logo=laravel&logoColor=white
[Laravel-url]: https://laravel.com
[Bootstrap.com]: https://img.shields.io/badge/Bootstrap-563D7C?style=for-the-badge&logo=bootstrap&logoColor=white
[Bootstrap-url]: https://getbootstrap.com
[JQuery.com]: https://img.shields.io/badge/jQuery-0769AD?style=for-the-badge&logo=jquery&logoColor=white
[JQuery-url]: https://jquery.com 
[Django-logo]: https://img.shields.io/badge/django-%23092E20.svg?style=for-the-badge&logo=django&logoColor=white
[Django-url]: https://www.djangoproject.com/
[spaCy-logo]: https://img.shields.io/badge/spaCy-2ecc71?style=for-the-badge
[spaCy-url]: https://spacy.io/
[NLTK-logo]: https://img.shields.io/badge/NLTK-4c7a6a?style=for-the-badge
[NLTK-url]: https://www.nltk.org/
[Transformers-logo]: https://img.shields.io/badge/Transformers-9769ff?style=for-the-badge
[Transformers-url]: https://huggingface.co/transformers/
[Python-logo]: https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54
[Python-url]: https://www.python.org/
[JavaScript-logo]: https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E
[JavaScript-url]: https://developer.mozilla.org/en-US/docs/Web/JavaScript
[Node-logo]: https://img.shields.io/badge/node.js-6DA55F?style=for-the-badge&logo=node.js&logoColor=white
[Node-url]: https://nodejs.org/
[npm-logo]: https://img.shields.io/badge/NPM-%23CB3837.svg?style=for-the-badge&logo=npm&logoColor=white
[npm-url]: https://www.npmjs.com/
[PyTorch-url]: https://pytorch.org/
[PyTorch-logo]: https://img.shields.io/badge/PyTorch-%23EE4C2C.svg?style=for-the-badge&logo=PyTorch&logoColor=white
