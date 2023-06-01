import PySimpleGUI as sg

#Variables
kep_exploit_list = ["Exploit 1", "Exploit 2", "Exploit 3"] # Stores all the options for exploits for KEP server attacks
modbus_exploit_list = ["Exploit 3", "Exploit 2", "Exploit 1"] # Stores all the options for exploits for Modbus related attacks

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
    [sg.Combo(kep_exploit_list, default_value=kep_exploit_list[0], key='-KEP_EXPLOIT-')],
    [sg.Button("Launch Exploit"), sg.Button("Back")]
]

# Layout for the Modbus exploits
modbus_layout = [
    [sg.Text("MODBUS exploits",font=("Helvetica", 20, "bold"))],
    [sg.Combo(modbus_exploit_list, default_value=modbus_exploit_list[0], key='-MODBUS_EXPLOIT-')],
    [sg.Button("Launch Exploit"), sg.Button("Back")]
]

# Layout for managing all the layouts
main_layout = [
    [sg.Column(home_layout, key= '-HOME-',expand_x=True),
    sg.Column(kep_layout, key='-KEP-', visible=False),
    sg.Column(modbus_layout, key='-MODBUS-', visible=False)],
]

# Create the main window
window = sg.Window('Attack Dashboard', main_layout, size=(500,500))

# Variable to maintain which layout the user is on, default would be the home layout
layout = '-HOME-'

# Event loop to handle events and button clicks
while True:
    event, values = window.read()
    print(f'event=> {event}\n values=> {values}')
    if event in (None, 'Exit'):
        break
    if event == 'KEP Exploits':
        window[layout].update(visible=False)
        layout = '-KEP-'
        window[layout].update(visible=True)
    elif event == 'Modbus Exploits':
        window[layout].update(visible=False)
        layout = '-MODBUS-'
        window[layout].update(visible=True)
    elif event in ('Back', 'Back1'):
        window[layout].update(visible=False)
        layout = '-HOME-'
        window[layout].update(visible=True)
    elif event in ('Launch Exploit', 'Launch Exploit0'):
        if layout == '-KEP-':
            print(f"The selected attack to run is {values['-KEP_EXPLOIT-']}")
        elif layout == '-MODBUS-':
            print(f"The selected attack to run is {values['-MODBUS_EXPLOIT-']}")

# Close the main window
window.close()