import PySimpleGUI as sg
import ipaddress
import threading
import time
import RevampedAttackScript as attackscript
import sys
import os

class IORedirector(object):
    def __init__(self, multiline_element):
        self.multiline_element = multiline_element

class StdoutRedirector(IORedirector):
    def write(self, msg):
        self.multiline_element.update(msg, append=True)

class StderrRedirector(IORedirector):
    def write(self, msg):
        self.multiline_element.update(msg, append=True)
import RevampedAttackScript as attack
import sys

class IORedirector(object):
    def __init__(self, multiline_element):
        self.multiline_element = multiline_element

class StdoutRedirector(IORedirector):
    def write(self, msg):
        self.multiline_element.update(msg, append=True)

class StderrRedirector(IORedirector):
    def write(self, msg):
        self.multiline_element.update(msg, append=True)

def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False
    
def sleepyboi(duration):
    time.sleep(duration)


def launch_kep_exploit(exploit,ip,window,var1=None, var2=None,var3=None):
    if is_valid_ip(ip):
        status = f"The selected attack to run is {exploit} on IP: {ip}"
        update_status(status,"-KEP_STATUS_BOX-",window)
        ## Logic for attack selection here
        attack = attackscript.AttackScript(ip)
        try:
            match exploit:
                case "Connect to Wi-fi Network": attack.connect_to_wifi(var1,var2,var3)
                case "Start KEP server": attack.kep_server_start()
                case "Stop KEP server": attack.kep_server_stop()
                case "Get server information": attack.kep_server_info()
                case "Get all users": attack.kep_get_all_users()
                case "Enable user": attack.kep_enable_user(var1) # var1=user
                case "Disable user": attack.kep_disable_user(var1) # var1=user
                case "Get single user": attack.kep_get_single_user(var1) # var1=user
                case "Get all channels": attack.kep_get_all_channels()
                case "Get all devices": attack.kep_get_all_devices(var1) # var1=channel
                case "Get single device": attack.kep_get_single_device(var1,var2) # var1=channel, var2=device
                case "Add device": attack.kep_add_spoofed_device(var1,var2) # var1=channel, var2=device_name
                case "Delete device": attack.kep_delete_spoofed_device(var1,var2) # var1=channel, var2=device
                case "Bruteforce KEP credentials": attack.kep_bruteforce()
            update_status("Attack success","-KEP_STATUS_BOX-",window)
            window.write_event_value("-KEP_ATTACK_COMPLETE-", None)
        except Exception as e:
            print(e)
            update_status("Attack failed","-KEP_STATUS_BOX-",window)
            window.write_event_value("-KEP_ATTACK_FAILED-", None)

    else:
        print("error")

def remove_success_error(window):
    window["-SUCCESS-"].update(visible=False)
    window["-ERROR-"].update(visible=False)

def update_layout(old_layout, new_layout, window):
    window[old_layout].update(visible=False)
    window[new_layout].update(visible=True)
    return new_layout

def update_status(text, status_box, window, color = "white"):
    window[status_box].update(f"{text}\n", append=True, text_color = color)

def main():
    # Variables
    # Store all the options for exploits for KEP server attacks and their descriptions
    kep_exploit_dict = {
        "Connect to Wi-fi Network":"Connects to Wi-fi Network",
        "Start KEP server":"Starts the KEP server",
                        "Stop KEP server":"Stops the KEP server",
                        "Get server information":"Get the information of the KEP server",
                        "Get all users":"Get all the users of the KEP server",
                        "Enable user":"Enables the user specified",
                        "Disable user":"Disable the user specified",
                        "Get single user":"Get the information of a particular user",
                        "Get all channels":"Get all channels of the KEP server",
                        "Get all devices":"Get all devices of a channel",
                        "Get single device":"Get the information of a particular device",
                        "Add device":"Add a spoofed device to the KEP server under the channel specified",
                        "Delete device":"Delete the specified device in the channel of the KEP server",
                        "Bruteforce KEP credentials":"Run a bruteforce attack on the KEP server to get the admin credentials"
                        }
    # kep_exploit_dict = {}
    # scriptDirectory = './scripts/'
    # for file in os.listdir(scriptDirectory):
    # 
    #     if file.endswith(".sh"):
    #         filePath = scriptDirectory + file
    #         f = open(filePath, "r")
    #         Lines = f.readlines()
    # 
    #         kep_exploit_dict[file] = []
    # 
    #         for line in Lines:
    #             line = line.strip()
    #             line = line.lstrip('#')
    #             if "Description:" in line:
    #                 kep_exploit_dict[file].append(line)

    modbus_exploit_dict = {"Exploit 1":"Exploit 1 description", "Exploit 2":"Exploit 2 description", "Exploit 3":"Exploit 3 description"} # Stores all the options for exploits for Modbus related attacks
    kep_exploit_list = list(kep_exploit_dict.keys())
    modbus_exploit_list = list(modbus_exploit_dict.keys())
    # Set the theme of the GUI
    sg.theme('DarkGrey13')
    headingrow = ['SERVICE', 'STATUS']
    statusrow = [['Firewall Domain', 'HERE'],
    ['Firewall Private Profile', 'HERE'], 
    ['Firewall Public Profile', 'HERE' ], 
    ['Windows Defender', 'HERE'], 
    ['KEP Server', 'HERE']]
    
    # Layout for the home window
    home_layout = [   
        [sg.Text("Attack Dashboard",font=("Helvetica", 20, "bold"),expand_x=True,justification="center")],
        [sg.Table(values=statusrow, headings=headingrow, 
                  auto_size_columns=True,
                  display_row_numbers=False,
                  justification='center', key='-TABLE-',
                  selected_row_colors='red on yellow',
                  enable_events=True,
                  expand_x=True,
                  expand_y=True,
                  enable_click_events=True) ],
        [sg.Text("Please select exploits you want to run",expand_x=True,justification="center")],
        [sg.Column([
            [sg.Button('KEP Exploits'),sg.Button('Modbus Exploits')],
        ], justification="center")],  # Corrected the placement of 'justification'
        [sg.Column([
            [sg.Button('Exit')],
        ], justification="center")]  
    ]

    # Layout for the kep server exploits
    kep_layout = [
        [sg.Text("KEP server exploits",font=("Helvetica", 20, "bold"))],
        [sg.Text("Select IP address:", key="-SELECT_IP-"), sg.Radio("Level 6 (172.16.2.223)", "ip", key="-IP_LVL6-", enable_events=True, default=True), sg.Radio("Level 7 (172.16.2.77)" , "ip", key="-IP_LVL7-", enable_events=True), sg.Radio("Custom IP", "ip", key="-IP_CUSTOM-", enable_events=True)],
        [sg.Text("Please enter IP", key="-IP_TEXT-",visible=False), sg.Input("172.16.2.223", key="-IP_INPUT-",visible=False, size=(25,1))],
        [sg.Text("Exploit:"), sg.Combo(kep_exploit_list, default_value=kep_exploit_list[0], key='-KEP_EXPLOIT-', enable_events=True, readonly=True)],
        [sg.Text(kep_exploit_dict[kep_exploit_list[0]][0],key="-DESCRIPTION_TEXT-")],
        [sg.Text("Variable 1:", key="-VAR1_TEXT-", visible=False), sg.Input("",key="-VAR1_INPUT-", visible=False, size=(22,1)), sg.Text("Variable 2:",visible=False, key="-VAR2_TEXT-"), sg.Input("",key="-VAR2_INPUT-", visible=False, size=(22,1))],
        [sg.Button("Launch Exploit", key="-LAUNCH_KEP_EXPLOIT-"), sg.Image("./images/loading.gif",visible=False, key="-SPINNER-"),sg.Image("./images/success.png",visible=False, key="-SUCCESS-"),sg.Image("./images/error.png",visible=False, key="-ERROR-")],
        [sg.Multiline(background_color="#363636",text_color="black", expand_x=True, size=(1,15),no_scrollbar=True, disabled=True, key="-KEP_STATUS_BOX-")],
        [sg.Button("Back")]
    ]

    # Layout for the Modbus exploits
    modbus_layout = [
        [sg.Text("MODBUS exploits",font=("Helvetica", 20, "bold"))],
        [sg.Text("Exploit:"), sg.Combo(modbus_exploit_list, default_value=modbus_exploit_list[0], key='-MODBUS_EXPLOIT-')],
        [sg.Button("Launch Exploit"), sg.Button("Back")]
    ]

    # Layout for managing all the layouts
    main_layout = [
        [sg.Column(home_layout, key= '-HOME-',expand_x=True),
        sg.Column(kep_layout, key='-KEP-', visible=False),
        sg.Column(modbus_layout, key='-MODBUS-', visible=False)],
    ]

    # Create the main window
    window = sg.Window('Attack Dashboard', main_layout, resizable=True)

    # Here we set the stdout to the text area
    sys.stdout = StdoutRedirector(window['-KEP_STATUS_BOX-'])
    sys.stderr = StderrRedirector(window['-KEP_STATUS_BOX-'])

    # Variable to maintain which layout the user is on, default would be the home layout
    layout = '-HOME-'
    timeout = None

    # Event loop to handle events and button clicks
    while True:
        event, values = window.read(timeout=timeout)
        # print(f'event=> {event}\n values=> {values}', file=sys.__stdout__)
        if event in (None, 'Exit'):
            break
        if event == 'KEP Exploits':
            layout = update_layout(layout, "-KEP-", window)
        elif event == 'Modbus Exploits':
            layout = update_layout(layout, "-MODBUS-", window)
        elif event in ('Back', 'Back1'):
            layout = update_layout(layout, "-HOME-", window)
        elif event in ('-LAUNCH_KEP_EXPLOIT-', 'Launch Exploit0'):
            if layout == '-KEP-':
                timeout=25
                remove_success_error(window)
                window["-SPINNER-"].update(visible=True)
                window["-LAUNCH_KEP_EXPLOIT-"].update(disabled=True)
                window["-KEP_STATUS_BOX-"].update("")
                thread = threading.Thread(target=launch_kep_exploit, args=(values['-KEP_EXPLOIT-'], values["-IP_INPUT-"], window))
                thread.start()
            elif layout == '-MODBUS-':
                print(f"The selected attack to run is {values['-MODBUS_EXPLOIT-']}")
        elif event == "-KEP_ATTACK_COMPLETE-":
            timeout=None
            window["-SPINNER-"].update(visible=False)
            window["-SUCCESS-"].update(visible=True)
            window["-LAUNCH_KEP_EXPLOIT-"].update(disabled=False)
        elif event == "-KEP_ATTACK_FAILED-":
            timeout=None
            window["-SPINNER-"].update(visible=False)
            window["-ERROR-"].update(visible=True)
            window["-LAUNCH_KEP_EXPLOIT-"].update(disabled=False)
        elif event == "-IP_CUSTOM-":
            window["-IP_TEXT-"].update(visible=True)
            window["-IP_INPUT-"].update(visible=True)
        elif event == "-IP_LVL6-":
            window["-IP_TEXT-"].update(visible=False)
            window["-IP_INPUT-"].update("172.16.2.223",visible=False)
        elif event == "-IP_LVL7-":
            window["-IP_TEXT-"].update(visible=False)
            window["-IP_INPUT-"].update("172.16.2.77",visible=False)
        elif event == "-KEP_EXPLOIT-":
            selected_exploit = values["-KEP_EXPLOIT-"]
            window["-DESCRIPTION_TEXT-"].update(kep_exploit_dict[selected_exploit])
            print(f"selected exploit == {selected_exploit}", file=sys.__stdout__)
            if selected_exploit == "Enable user" or selected_exploit == "Disable user" or selected_exploit == "Get single user":
                window["-VAR1_TEXT-"].update("User:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)
            elif selected_exploit == "Get all devices":
                window["-VAR1_TEXT-"].update("Channel:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)
            elif selected_exploit == "Get single device" or selected_exploit == "Add device" or selected_exploit == "Delete device":
                window["-VAR1_TEXT-"].update("Channel:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)
                window["-VAR2_TEXT-"].update("Device:", visible=True)
                window["-VAR2_INPUT-"].update("", visible=True)
            else:
                window["-VAR1_TEXT-"].update("Variable 1:", visible=False)
                window["-VAR1_INPUT-"].update("", visible=False)
                window["-VAR2_TEXT-"].update("Variable 2:", visible=False)
                window["-VAR2_INPUT-"].update("", visible=False)
        window['-SPINNER-'].update_animation("./images/loading.gif",  time_between_frames=25)
    # Close the main window
    window.close()

if __name__ == "__main__":
    main()