import PySimpleGUI as sg
import ipaddress
import threading
import time
import RevampedAttackScript as attackscript
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
    
def get_service_statuses(ip, window):
    attack = attackscript.AttackScript(ip)
    try:
        status_list = attack.get_firewall_status()
        status_list.append("ON") if attack.get_windef_status() else status_list.append("OFF")
        status_list.append("ON") if attack.kep_get_service_status() else status_list.append("OFF")
        print(f"status_list is : {status_list}",file=sys.__stdout__)
        
        if status_list != None:
            window.write_event_value("-SERVICE_STATUS_SUCCESS-", status_list)

    except Exception as e:
        print(e,file=sys.__stderr__)
        window.write_event_value("-SERVICE_STATUS_FAILED-", None)

def launch_exploit(exploit,ip,window,var1=None, var2=None, var3=None, var4=None, var5=None):
    if is_valid_ip(ip):
        # status = f"The selected attack to run is {exploit} on IP: {ip}, var1 = {var1}, var2 = {var2}"
        # update_status(status,"-STATUS_BOX-",window)
        ## Logic for attack selection here
        attack = attackscript.AttackScript(ip)
        ##TODO: Add checks for attack success or fail even if there was no errors raised
        try:
            match exploit:
                case "Start KEP server": attack.kep_server_start()
                case "Stop KEP server": attack.kep_server_stop()
                case "Get server information": attack.kep_server_info()
                case "Bruteforce KEP credentials": attack.kep_bruteforce()
                case "Get all users": attack.kep_get_all_users()
                case "Get single user": attack.kep_get_single_user(var1) # var1=user
                case "Add user": attack.kep_add_user(var1,var2,var3) # var1=user, var2=groupname, var3=password
                case "Delete user": attack.kep_del_user(var1) # var1=user
                case "Enable user": attack.kep_enable_user(var1) # var1=user
                case "Disable user": attack.kep_disable_user(var1) # var1=user
                case "Modify user": attack.kep_modify_user(var1,var2,var3,var4) # var1=user, var2=description, var3=password, var4=groupname
                case "Get all user group": attack.kep_get_all_user_groups()
                case "Get single user group": attack.kep_get_single_user_group(var1) # var1=usergroup
                case "Add user group": attack.kep_add_user_group(var1) #var1=usergroup
                case "Delete user group": attack.kep_del_user_group(var1) # var1=usergroup
                case "Upgrade user group": attack.kep_upgrade_user_group(var1) # var1=usergroup
                case "Downgrade user group": attack.kep_downgrade_user_group(var1) # var1=user
                case "Get all channels": attack.kep_get_all_channels()
                case "Add spoofed channel": attack.kep_add_spoofed_channel(var1) # var1=channel_name
                case "Delete channel": attack.kep_del_spoofed_channel(var1) # var1=channel_name
                case "Modify channel": attack.kep_modify_channel(var1,var2) # var1=channel_name, var2=new_channel_name
                case "Get all devices": attack.kep_get_all_devices(var1) # var1=channel
                case "Get single device": attack.kep_get_single_device(var1,var2) # var1=channel, var2=device
                case "Add device": attack.kep_add_spoofed_device(var1,var2) # var1=channel, var2=device_name
                case "Delete device": attack.kep_delete_spoofed_device(var1,var2) # var1=channel, var2=device
                case "Modify device": attack.kep_modify_device(var1,var2,var3,var4) # var1=channel, var2=device, var3=project_id, var4=new_device_name, var5=device_id 
                case "Get full tag structure": attack.kep_get_full_tag_structure(var1,var2) # var1=channel, var2=device
                case "Get single tag": attack.kep_get_single_tag(var1,var2,var3) # var1=channel, var2=device, var3=tag
                case "Add tag": attack.kep_add_tag(var1,var2,var3,var4) # var1=channel, var2=device, var3=name, var4=tag_address
                case "Delete tag": attack.kep_del_tag(var1,var2,var3) # var1=channel, var2=device, var3=name
                case "Modify tag": attack.kep_modify_tag(var1,var2,var3,var4) # var1=channel, var2=device, var3=name, var4=projectID, var5=new_name
            
            update_status("Attack success","-STATUS_BOX-",window)
            window.write_event_value("-ATTACK_COMPLETE-", None)

        except Exception as e:
            print(e)
            update_status("Attack failed","-STATUS_BOX-",window)
            window.write_event_value("-ATTACK_FAILED-", None)

    else:
        print("error")

def remove_success_error(window):
    window["-SUCCESS-"].update(visible=False)
    window["-ERROR-"].update(visible=False)

def update_layout(old_layout, new_layout, window):
    window[old_layout].update(visible=False)
    window[new_layout].update(visible=True)
    return new_layout

def update_status(text, status_box, window, color = "black"):
    window[status_box].update(f"{text}\n", append=True, text_color = color)

def main():
    # Variables
    # Store all the options for exploits for KEP server attacks and their descriptions
    exploit_dict = {"Start KEP server":"Starts the KEP server",
                    "Stop KEP server":"Stops the KEP server",
                    "Get server information":"Get the information of the KEP server", 
                    "Bruteforce KEP credentials":"Run a bruteforce attack on the KEP server to get the admin credentials",
                    "Get all users":"Get all the users of the KEP server",
                    "Get single user":"Get the information of a particular user",
                    "Add user":"Add a user to the usergroup specified. (Note: password must be 14 characters or more)",
                    "Delete user":"Delete the user specified",
                    "Enable user":"Enables the user specified",
                    "Disable user":"Disable the user specified",
                    "Modify user":"Modify the description, groupname and password of the specified user",
                    "Get all user group":"Get all user groups in the KEP server",
                    "Get single user group":"Get the information of a particular user group",
                    "Add user group":"Add a user group to the KEP server",
                    "Delete user group":"Delete the user group specified",
                    "Upgrade user group":"Upgrade the user group to have all permissions (superuser)",
                    "Downgrade user group":"Downgrade the user group to have no permissions",
                    "Get all channels":"Get all channels of the KEP server",
                    "Add spoofed channel":"Add a spoofed channel to the KEP server",
                    "Delete channel":"Delete the specified channel",
                    "Modify channel":"Modify the channel specified to change the project id and channel name of the channel",
                    "Get all devices":"Get all devices of a channel",
                    "Get single device":"Get the information of a particular device",
                    "Add device":"Add a spoofed device to the KEP server under the channel specified",
                    "Delete device":"Delete the specified device in the channel of the KEP server",
                    "Modify device":"Modify the device specified to change the device name and device ID of the device.",
                    "Get full tag structure":"Get the full structure of the tag under the channel and device",
                    "Get single tag":"Get the particular tag of the device and channel specified",
                    "Add tag":"Add a spoofed tag to the KEP server under the channel and device specified",
                    "Delete tag":"Delete the specified tag under the channel and device name provided",
                    "Modify tag":"Modify the name of an existing tag",
                    } 
    modbus_exploit_dict = {"Exploit 1":"Exploit 1 description", "Exploit 2":"Exploit 2 description", "Exploit 3":"Exploit 3 description"} # Stores all the options for exploits for Modbus related attacks
    exploit_list = list(exploit_dict.keys())
    modbus_exploit_list = list(modbus_exploit_dict.keys())
    # Set the theme of the GUI
    sg.theme('Reddit')
    headingrow = ['SERVICE', 'STATUS']
    status_row = [['Firewall Domain Profile', '-'],
                  ['Firewall Private Profile', '-'],
                  ['Firewall Public Profile', '-' ], 
                  ['Windows Defender', '-'], 
                  ['KEP Server', '-']]

    
    # Layout for the kep server exploits
    exploit_layout = [
        [sg.Text("Exploits",font=("Helvetica", 28, "bold"), expand_x=True, justification="center", background_color="#363636", text_color="white",pad=((0, 0), (30, 30)))],
        [sg.Text("Exploit:", font=("Helvetica", 16, "bold")), sg.Combo(exploit_list, default_value=exploit_list[0], key='-EXPLOIT-', enable_events=True, readonly=True, font=("Helvetica", 16))],
        [sg.Text("Description:", key="-DESCRIPTION-", font=("Helvetica", 16, "bold")), sg.Text(exploit_dict[exploit_list[0]],key="-DESCRIPTION_TEXT-", font=("Helvetica", 16))],
        [sg.Text("Variable 1:", key="-VAR1_TEXT-", visible=False, font=("Helvetica", 16, "bold")), sg.Input("1",key="-VAR1_INPUT-", visible=False, size=(22,1), font=("Helvetica", 16)), 
         sg.Text("Variable 2:",visible=False, key="-VAR2_TEXT-", font=("Helvetica", 16, "bold")), sg.Input("2",key="-VAR2_INPUT-", visible=False, size=(22,1), font=("Helvetica", 16)),
         sg.Text("Variable 3:",visible=False, key="-VAR3_TEXT-", font=("Helvetica", 16, "bold")), sg.Input("3",key="-VAR3_INPUT-", visible=False, size=(22,1), font=("Helvetica", 16))],
        [sg.Text("Variable 4:",visible=False, key="-VAR4_TEXT-",font=("Helvetica", 16, "bold")), sg.Input("4",key="-VAR4_INPUT-", visible=False, size=(22,1), font=("Helvetica", 16)),
         sg.Text("Variable 5:",visible=False, key="-VAR5_TEXT-",font=("Helvetica", 16, "bold")), sg.Input("5",key="-VAR5_INPUT-", visible=False, size=(22,1), font=("Helvetica", 16))],
        [sg.Text("Please ensure that all fields are filled.", visible=False, key="-EXPLOIT_ERROR_TEXT-", text_color="red", justification="center", expand_x=True, font=("Helvetica", 16))],
        [sg.Button("Launch Exploit", key="-LAUNCH_EXPLOIT-", font=("Helvetica", 16, "bold"), expand_x=True), sg.Image("./images/loading.gif",visible=False, key="-SPINNER-"),sg.Image("./images/s.png",visible=False, key="-SUCCESS-"),sg.Image("./images/error.png",visible=False, key="-ERROR-")],
        [sg.Multiline(text_color="black", expand_x=True,no_scrollbar=True, disabled=True, key="-STATUS_BOX-", font=("Helvetica", 15), size=(1,25))],
    ]
    
    # Layout for the home window
    home_layout = [   
        [sg.Text("Attack Dashboard",font=("Helvetica", 28, "bold"),expand_x=True,justification="center", background_color="#363636", size=(63,1), text_color="white" ,pad=((0, 0), (0, 30)))],
        [sg.Text("Select IP address:", key="-SELECT_IP-",font=("Helvetica", 16, "bold")), 
            sg.Radio("Level 6 (172.16.2.223)", "ip", key="-IP_LVL6-", enable_events=True, default=True, font=("Helvetica", 16)),
            sg.Radio("Level 7 (172.16.2.77)" , "ip", key="-IP_LVL7-", enable_events=True, font=("Helvetica", 16)),
            sg.Radio("Custom IP", "ip", key="-IP_CUSTOM-", enable_events=True, font=("Helvetica", 16))],
        [sg.Text("Please enter IP:", key="-IP_TEXT-",visible=False, font=("Helvetica", 16, "bold")), sg.Input("172.16.2.223", key="-IP_INPUT-",visible=False, size=(25,1), font=("Helvetica", 16))],
        [sg.Text("Service Statuses:", font=("helvetica", 16, "bold"))],
        [sg.Table(values=status_row, header_font=("Helvetica", 16, "bold"),selected_row_colors=("black","white"),row_height=35, headings=headingrow, num_rows=5, expand_x=True, auto_size_columns=True, display_row_numbers=False, justification='center', key='-STATUS_TABLE-', hide_vertical_scroll=True, font=("Helvetica", 16))],
        [sg.Column([
            [sg.Button('Get Service Status', key="-GET_STATUS_BUTTON-", expand_x=True, font=("Helvetica", 16, "bold")),sg.Image("./images/Spinner-1s-21px.gif", size=(0.5,0.5),visible=False, key="-SERVICE_SPINNER-")],
        ], justification="center", expand_x=True)],
        [sg.Text("Error getting service status, please try again.", visible=False, key="-SERVICE_ERROR_TEXT-", text_color="red", justification="center", expand_x=True, font=("Helvetica", 16))],
        [sg.Column(exploit_layout, expand_x=True),],
        [sg.Column([
            [sg.Button('Exit', expand_x=True, font=("Helvetica", 16, "bold"))],
        ], justification="center", expand_x=True)],
        [sg.Text(size=(0,8))]
    ]

    # Layout for managing all the layouts
    main_layout = [
        [sg.Column(home_layout, key= '-HOME-',expand_x=True, expand_y=True, scrollable=True, vertical_scroll_only=True, sbar_background_color="grey", sbar_width=18, sbar_arrow_width=18),]
    ]

    # Create the main window
    window = sg.Window('Attack Dashboard', main_layout, size=(None,None), finalize=True)
    window.maximize()

    # Redirect stdout to status box
    sys.stdout = StdoutRedirector(window['-STATUS_BOX-'])
    sys.stderr = StderrRedirector(window['-STATUS_BOX-'])

    # Variable to maintain which layout the user is on, default would be the home layout
    timeout = None

    # Event loop to handle events and button clicks
    while True:
        event, values = window.read(timeout=timeout)
        # print(f'event=> {event}\n values=> {values}', file=sys.__stdout__)
        if event in (None, 'Exit'):
            break

        elif event == "-GET_STATUS_BUTTON-":
            timeout=25
            window["-SERVICE_SPINNER-"].update(visible=True)
            window["-GET_STATUS_BUTTON-"].update(disabled=True)
            window["-SERVICE_ERROR_TEXT-"].update(visible=False)
            thread = threading.Thread(target=get_service_statuses, args=(values["-IP_INPUT-"],window))
            thread.start()

        elif event == '-LAUNCH_EXPLOIT-':
            timeout=25
            remove_success_error(window)
            if values["-VAR1_INPUT-"] == "" or values["-VAR2_INPUT-"] == "" or values["-VAR3_INPUT-"] == "" or values["-VAR4_INPUT-"] == "" or values["-VAR5_INPUT-"] == "":
                    window["-EXPLOIT_ERROR_TEXT-"].update("Please ensure that all fields are filled.",visible=True)
            
            elif values["-EXPLOIT-"] == "Add user" and len(values["-VAR3_INPUT-"]) < 14:
                window["-EXPLOIT_ERROR_TEXT-"].update("Password must be more than 14 characters",visible=True)
                
            else:
                window["-EXPLOIT_ERROR_TEXT-"].update(visible=False)
                window["-SPINNER-"].update(visible=True)
                window["-LAUNCH_EXPLOIT-"].update(disabled=True)
                window["-STATUS_BOX-"].update("")
                thread = threading.Thread(target=launch_exploit, args=(values['-EXPLOIT-'], values["-IP_INPUT-"], window, values["-VAR1_INPUT-"], values["-VAR2_INPUT-"], values["-VAR3_INPUT-"], values["-VAR4_INPUT-"], values["-VAR5_INPUT-"]))
                thread.start()

        elif event == "-SERVICE_STATUS_SUCCESS-":
            timeout=None
            window["-SERVICE_SPINNER-"].update(visible=False)
            window["-GET_STATUS_BUTTON-"].update(disabled=False)
            status_row[0][1] = values["-SERVICE_STATUS_SUCCESS-"][0]
            status_row[1][1] = values["-SERVICE_STATUS_SUCCESS-"][1]
            status_row[2][1] = values["-SERVICE_STATUS_SUCCESS-"][2]
            status_row[3][1] = values["-SERVICE_STATUS_SUCCESS-"][3]
            status_row[4][1] = values["-SERVICE_STATUS_SUCCESS-"][4]
            window["-STATUS_TABLE-"].update(status_row)

        elif event == "-SERVICE_STATUS_FAILED-":
            timeout=None
            window["-SERVICE_SPINNER-"].update(visible=False)
            window["-GET_STATUS_BUTTON-"].update(disabled=False)
            window["-SERVICE_ERROR_TEXT-"].update(visible=True)

        elif event == "-ATTACK_COMPLETE-":
            timeout=None
            window["-SPINNER-"].update(visible=False)
            window["-SUCCESS-"].update(visible=True)
            window["-LAUNCH_EXPLOIT-"].update(disabled=False)

        elif event == "-ATTACK_FAILED-":
            timeout=None
            window["-SPINNER-"].update(visible=False)
            window["-ERROR-"].update(visible=True)
            window["-LAUNCH_EXPLOIT-"].update(disabled=False)

        elif event == "-IP_CUSTOM-":
            window["-IP_TEXT-"].update(visible=True)
            window["-IP_INPUT-"].update(visible=True)

        elif event == "-IP_LVL6-":
            window["-IP_TEXT-"].update(visible=False)
            window["-IP_INPUT-"].update("172.16.2.223",visible=False)

        elif event == "-IP_LVL7-":
            window["-IP_TEXT-"].update(visible=False)
            window["-IP_INPUT-"].update("172.16.2.77",visible=False)

        elif event == "-EXPLOIT-":
            selected_exploit = values["-EXPLOIT-"]
            window["-DESCRIPTION_TEXT-"].update(exploit_dict[selected_exploit])
            # print(f"selected exploit == {selected_exploit}", file=sys.__stdout__)
            window["-EXPLOIT_ERROR_TEXT-"].update(visible=False)
            window["-VAR1_TEXT-"].update("Variable 1:", visible=False)
            window["-VAR1_INPUT-"].update("1", visible=False)
            window["-VAR2_TEXT-"].update("Variable 2:", visible=False)
            window["-VAR2_INPUT-"].update("2", visible=False)
            window["-VAR3_TEXT-"].update("Variable 3:", visible=False)
            window["-VAR3_INPUT-"].update("3", visible=False)
            window["-VAR4_TEXT-"].update("Variable 4:", visible=False)
            window["-VAR4_INPUT-"].update("4", visible=False)
            window["-VAR5_TEXT-"].update("Variable 5:", visible=False)
            window["-VAR5_INPUT-"].update("5", visible=False)

            if selected_exploit == "Enable user" or selected_exploit == "Disable user" or selected_exploit == "Get single user" or selected_exploit == "Delete user":
                window["-VAR1_TEXT-"].update("User:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)
            
            elif selected_exploit == "Add user":
                window["-VAR1_TEXT-"].update("User:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)
                window["-VAR2_TEXT-"].update("Group name:", visible=True)
                window["-VAR2_INPUT-"].update("", visible=True)
                window["-VAR3_TEXT-"].update("Password:", visible=True)
                window["-VAR3_INPUT-"].update("", visible=True)
            
            elif selected_exploit == "Modify user":
                window["-VAR1_TEXT-"].update("User:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)
                window["-VAR2_TEXT-"].update("New Description:", visible=True)
                window["-VAR2_INPUT-"].update("", visible=True)
                window["-VAR3_TEXT-"].update("New Password", visible=True)
                window["-VAR3_INPUT-"].update("", visible=True)
                window["-VAR4_TEXT-"].update("New Group Name:", visible=True)
                window["-VAR4_INPUT-"].update("", visible=True)
            
            elif selected_exploit == "Get single user group" or selected_exploit == "Add user group" or selected_exploit == "Delete user group" or selected_exploit == "Upgrade user group" or selected_exploit == "Downgrade user group"  :
                window["-VAR1_TEXT-"].update("User group:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)

            elif selected_exploit == "Add spoofed channel" or selected_exploit == "Delete channel":
                window["-VAR1_TEXT-"].update("Channel name:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)     

            elif selected_exploit == "Modify channel":
                window["-VAR1_TEXT-"].update("Channel name:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)
                window["-VAR2_TEXT-"].update("New Channel name:", visible=True)
                window["-VAR2_INPUT-"].update("", visible=True)
            
            elif selected_exploit == "Get all devices":
                window["-VAR1_TEXT-"].update("Channel:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)

            elif selected_exploit == "Get single device" or selected_exploit == "Add device" or selected_exploit == "Delete device" or selected_exploit == "Get full tag structure" or selected_exploit == "Get single tag":
                window["-VAR1_TEXT-"].update("Channel:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)
                window["-VAR2_TEXT-"].update("Device:", visible=True)
                window["-VAR2_INPUT-"].update("", visible=True)

                if selected_exploit == "Get single tag":
                    window["-VAR3_TEXT-"].update("Tag Name:", visible=True)
                    window["-VAR3_INPUT-"].update("", visible=True)

            elif selected_exploit == "Modify device":
                window["-VAR1_TEXT-"].update("Channel:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)
                window["-VAR2_TEXT-"].update("Device:", visible=True)
                window["-VAR2_INPUT-"].update("", visible=True)
                window["-VAR3_TEXT-"].update("New device name:", visible=True)
                window["-VAR3_INPUT-"].update("", visible=True)
                window["-VAR4_TEXT-"].update("Device ID:", visible=True)
                window["-VAR4_INPUT-"].update("", visible=True)

            elif selected_exploit == "Add tag" or selected_exploit == "Delete tag" or selected_exploit == "Modify tag":
                window["-VAR1_TEXT-"].update("Channel:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)
                window["-VAR2_TEXT-"].update("Device:", visible=True)
                window["-VAR2_INPUT-"].update("", visible=True)
                window["-VAR3_TEXT-"].update("Tag Name:", visible=True)
                window["-VAR3_INPUT-"].update("", visible=True)

                if selected_exploit == "Add tag":
                    window["-VAR4_TEXT-"].update("Tag Address:", visible=True)
                    window["-VAR4_INPUT-"].update("", visible=True)

                elif selected_exploit == "Modify tag":
                    window["-VAR4_TEXT-"].update("New Name:",visible=True)
                    window["-VAR4_INPUT-"].update("", visible=True)

        window['-SPINNER-'].update_animation("./images/loading.gif",  time_between_frames=25)
        window['-SERVICE_SPINNER-'].update_animation("./images/Spinner-1s-21px.gif",  time_between_frames=25)
    # Close the main window
    window.close()

if __name__ == "__main__":
    main()
