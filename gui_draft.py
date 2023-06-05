import PySimpleGUI as sg
import ipaddress
import time

def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def launch_kep_exploit(exploit,ip,window):
    if is_valid_ip(ip):
        status = f"The selected attack to run is {exploit} on IP: {ip}"
        update_status(status,"-KEP_STATUS_BOX-",window)
        time.sleep(2)
    else:
        print("error")

def update_layout(old_layout, new_layout, window):
    window[old_layout].update(visible=False)
    window[new_layout].update(visible=True)
    return new_layout

def update_status(text, status_box, window):
    window[status_box].update(f"{text}\n", append=True)

def main():
    #Variables
    kep_exploit_dict = {"Exploit 1":"Exploit 1 description", "Exploit 2":"Exploit 2 description SDAFLKJASDKFJLSKDF  test est estesjiofja io;ssjf dasif j tehso ijasdfkl jsadlfkj sdf f iou opiud  ", "Exploit 3":"Exploit 3 description"} # Stores all the options for exploits for KEP server attacks
    modbus_exploit_dict = {"Exploit 1":"Exploit 1 description", "Exploit 2":"Exploit 2 description", "Exploit 3":"Exploit 3 description"} # Stores all the options for exploits for Modbus related attacks
    kep_exploit_list = list(kep_exploit_dict.keys())
    modbus_exploit_list = list(modbus_exploit_dict.keys())
    # Set the theme of the GUI
    sg.theme('DarkGrey6')

    # Layout for the home window
    home_layout = [
        [sg.Text("Attack Dashboard",font=("Helvetica", 20, "bold"),expand_x=True,justification="center")],
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
        [sg.Text("Please enter IP", key="-IP_TEXT-",visible=False), sg.Input("172.16.2.223", key="-IP_INPUT-",visible=False)],
        [sg.Text("Exploit:"), sg.Combo(kep_exploit_list, default_value=kep_exploit_list[0], key='-KEP_EXPLOIT-', enable_events=True, readonly=True)],
        [sg.Text("Description:", key="-DESCRIPTION-"), sg.Text(kep_exploit_dict[kep_exploit_list[0]],key="-DESCRIPTION_TEXT-")],
        [sg.Button("Launch Exploit", key="-LAUNCH_KEP_EXPLOIT-", disabled_button_color="pink"), sg.Image("./images/loading.gif",visible=False, enable_events=True, key="-SPINNER-")],
        [sg.Multiline(background_color="gray", expand_x=True, size=(1,15),no_scrollbar=True, disabled=True, key="-KEP_STATUS_BOX-")],
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
    window = sg.Window('Attack Dashboard', main_layout)

    # Variable to maintain which layout the user is on, default would be the home layout
    layout = '-HOME-'
    timeout = 10000

    # Event loop to handle events and button clicks
    while True:
        event, values = window.read(timeout=timeout)
        print(f'event=> {event}\n values=> {values}')
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
                window["-SPINNER-"].update(visible=True)
                window["-LAUNCH_KEP_EXPLOIT-"].update(disabled=True)
                launch_kep_exploit(values['-KEP_EXPLOIT-'], values["-IP_INPUT-"], window)
                timeout=10000
                window["-SPINNER-"].update(visible=False)
                window["-LAUNCH_KEP_EXPLOIT-"].update(disabled=False)
            elif layout == '-MODBUS-':
                print(f"The selected attack to run is {values['-MODBUS_EXPLOIT-']}")
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
            window["-DESCRIPTION_TEXT-"].update(kep_exploit_dict[values["-KEP_EXPLOIT-"]])
        window['-SPINNER-'].update_animation("./images/loading.gif",  time_between_frames=25)
    # Close the main window
    window.close()

if __name__ == "__main__":
    main()