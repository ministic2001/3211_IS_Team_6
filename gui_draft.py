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

def launch_exploit(exploit,ip,window,var1=None, var2=None, var3=None, var4=None, var5=None, revert: bool=False):
    if is_valid_ip(ip):
        status = f"The selected attack to run is {exploit} on IP: {ip}, var1 = {var1}, var2 = {var2}, var3={var3}, var4={var4}, var5={var5}, revert={revert}"
        update_status(status,"-STATUS_BOX-",window)
        attack = attackscript.AttackScript(ip)
        try:
            match exploit:
                ## ======================== KEP EXPLOITS ======================== ##
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
                case "Get single channel": attack.kep_get_channel(var1) # var1=channel_name
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
                case "Auto generate tags": attack.kep_auto_tag_gen(var1,var2) # var1=channel, var2=device
                # case "Get exchange": attack.kep_get_exchange(var1,var2,var3,var4) # var1=channel, var2=device, var3=ex_type, var4=exchange_name
                # case "Add exchange": attack.kep_add_exchange(var1,var2,var3) # var1=channel, var2=device, var3=exchange_name
                # case "Delete exchange": attack.kep_delete_exchange(var1,var2,var3,var4) # var1=channel, var2=device, var3=ex_type, var4=exchange_name
                # case "Get name resolutions": attack.kep_get_name_resolution(var1,var2) # var1=channel, var2=device
                # case "Add name resolution": attack.kep_add_name_resolution(var1,var2,var3) # var1=channel, var2=device, var3=resolution_name
                # case "Delete name resolution": attack.kep_delete_name_resolution(var1,var2,var3) # var1=channel, var2=device, var3=resolution_name
                # case "Modify name resolutions": attack.kep_modify_name_resolution(var1,var2,var3,var4,var5) # var1=channel, var2=device, var3=alias, var4=ip_addr, var5=resolution_name
                case "Get all UDD profiles": attack.kep_get_all_udd_profiles()
                case "Add UDD profile": attack.kep_add_udd_profile(var1,var2) # var1=profile_name, var2=description
                case "Delete UDD profile": attack.kep_delete_udd_profile(var1) # var1=profile_name
                case "Modify UDD profile": attack.kep_modify_udd_profile(var1,var2,var3) # var1=profile_name, var2=new_profile_name, var3=description
                case "Get all log items": attack.kep_get_all_log_items(var1) # var1=log_group
                case "Add log item": attack.kep_add_log_item(var1,var2) # var1=log_group, var2=log_item
                case "Delete log item": attack.kep_delete_log_item(var1,var2) # var1=log_group, var2=log_item
                case "Get all log groups": attack.kep_get_all_log_groups()
                case "Add log group": attack.kep_add_log_group(var1,var2) # var1=log_group, var2=description
                case "Delete log group": attack.kep_delete_log_group(var1) # var1=log_group
                case "Enable log group": attack.kep_enable_log_group(var1) # var1=log_group
                case "Disable log group": attack.kep_disable_log_group(var1) # var1=log_group
                case "Delete log files": attack.kep_delete_log_files()
                ## ======================== MODBUS EXPLOITS ======================== ##
                case "Get hardware information": attack.smartmeter_get_hardware_info()
                case "Change meter ID": attack.change_meterID(revert)
                case "Clear energy reading": attack.clear_energy_reading()
                case "Change baud rate": attack.baudrate_change(revert)
                case "Run mod interrupt": attack.run_modinterrupt()
                case "Disable COM port": attack.disable_COMPort(revert)
                ## ======================== IT EXPLOITS ======================== ##
                case "Task scheduler delete files": attack.scheduled_task_delete_files(var1, revert) # var1=folder_path
                case "Disable running schedules": attack.disable_running_schedules(revert)
                case "Change log data value": attack.ChangeLogDataValue(var1) # var1=meter_id
            update_status("Attack success","-STATUS_BOX-",window)
            window.write_event_value("-ATTACK_COMPLETE-", None)


                # case "Get exchange": attack.kep_get_exchange(var1,var2,var3,var4) # var1=channel, var2=device, var3=ex_type, var4=exchange_name
                # case "Add exchange": attack.kep_add_exchange(var1,var2,var3) # var1=channel, var2=device, var3=exchange_name
                # case "Delete exchange": attack.kep_delete_exchange(var1,var2,var3,var4) # var1=channel, var2=device, var3=ex_type, var4=exchange_name
                # case "Get name resolutions": attack.kep_get_name_resolution(var1,var2) # var1=channel, var2=device
                # case "Add name resolution": attack.kep_add_name_resolution(var1,var2,var3) # var1=channel, var2=device, var3=resolution_name
                # case "Delete name resolution": attack.kep_delete_name_resolution(var1,var2,var3) # var1=channel, var2=device, var3=resolution_name
                # case "Modify name resolutions": attack.kep_modify_name_resolution(var1,var2,var3,var4,var5) # var1=channel, var2=device, var3=alias, var4=ip_addr, var5=resolution_name
                # case "Get all log items": attack.kep_get_all_log_items(var1) # var1=log_group
                # case "Add log item": attack.kep_add_log_item(var1,var2) # var1=log_group, var2=log_item
                # case "Delete log item": attack.kep_delete_log_item(var1,var2) # var1=log_group, var2=log_item

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
    # ============= Variables ============= 
    # Store all the options for exploits for KEP server attacks and their descriptions
    exploit_dict = {"===== KEP SERVER EXPLOITS =====":"",
                    "Start KEP server":"Starts the KEP server",
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
                    "Get single channel":"Get the information of a particular channel",
                    "Add spoofed channel":"Add a spoofed channel to the KEP server",
                    "Delete channel":"Delete the specified channel",
                    "Modify channel":"Modify the channel specified to change the channel name of the channel",
                    "Get all devices":"Get all devices of a channel",
                    "Get single device":"Get the information of a particular device",
                    "Add device":"Add a spoofed device to the KEP server under the channel specified",
                    "Delete device":"Delete the specified device in the channel of the KEP server",
                    "Modify device":"Modify the device specified to change the device name and device ID of the device.",
                    "Get full tag structure":"Get the full structure of the tag under the channel and device",
                    "Get single tag":"Get the particular tag of the device and channel specified",
                    "Add tag":"Add a spoofed tag to the KEP server under the channel and device specified (Example of a tag address: 40001)",
                    "Delete tag":"Delete the specified tag under the channel and device name provided",
                    "Modify tag":"Modify the name of an existing tag",
                    "Auto generate tags":"Execute the auto tag generation function on the KEP server",
                    # "Get exchange":"Get the properties of the exchange specified",
                    # "Add exchange":"Add an exchange object to the KEP server",
                    # "Delete exchange":"Delete the exchange object specified",
                    # "Get name resolutions":"Get all the name resolutions on the KEP server",
                    # "Add name resolution":"Add a name resolution to the KEP server",
                    # "Delete name resolution":"Delete the name resolution specified",
                    # "Modify name resolutions":"Modify the alias and IP address of a name resolution",
                    "Get all UDD profiles":"Get all UDD profiles in the KEP server",
                    "Add UDD profile":"Add a UDD profile to the KEP server",
                    "Delete UDD profile":"Delete the UDD profile specified",
                    "Modify UDD profile":"Modify the UDD profile's name and description",
                    "Get all log items":"Gets all the log items of the log group specified",
                    "Add log item":"Adds a log item to the log group specified",
                    "Delete log item":"Delete the log item specified",
                    "Get all log groups":"Get all the log groups in the KEP server",
                    "Add log group":"Add a log group to the KEP server",
                    "Delete log group":"Delete the log group specified",
                    "Enable log group":"Enables the log group specified",
                    "Disable log group":"Disables the log group specified",
                    # "Modify project properties":"Modifies the project name of a project",
                    "Delete log files":"Delete the log files to cover up tracks",
                    "====== MODBUS EXPLOITS ======":"",
                    "Get hardware information": "Get hardware information of the smartmeter",
                    "Change meter ID": "Run modpoll to change register 40201 (Which handle the meter ID) to 26",
                    "Clear energy reading": "Run modpoll to clear energy reading",
                    "Change baud rate": "Run modpoll to change baud rate - Register 40206",
                    "Run mod interrupt": "Run modpoll to interrupt COM1 port by disabling KEP Server and then run modpoll indefinitely",
                    "Disable COM port": "Disable a COM port",
                    "======== IT EXPLOITS ========":"",
                    "Task scheduler delete files": "Delete the smartmeter path prediodically through task scheduler ",
                    "Disable running schedules": "Disables MoveFiles and KEPServerEX 6.12 running schedules in task scheduler",
                    "Change log data value":"Change the data value of the latest meter log file, in the specified meter ID's folder (E.g. 2)"
                    } 

    exploit_list = list(exploit_dict.keys())
    revertible_attacks = ["Change meter ID", "Change baud rate", "Disable COM port", "Task scheduler delete files", "Disable running schedules"]
    headingrow = ['SERVICE', 'STATUS']
    status_row = [['Firewall Domain Profile', '-'],
                  ['Firewall Private Profile', '-'],
                  ['Firewall Public Profile', '-' ], 
                  ['Windows Defender', '-'], 
                  ['KEP Server', '-']]


    # Set the theme of the GUI
    sg.theme('Reddit')
    
    # Layout for the kep server exploits
    exploit_layout = [
        [sg.Text("Exploits",font=("Helvetica", 28, "bold"), expand_x=True, justification="center", background_color="#363636", text_color="white",pad=((0, 0), (30, 30)))],
        [sg.Text("Exploit:", font=("Helvetica", 16, "bold")), sg.Combo(exploit_list, default_value=exploit_list[1], key='-EXPLOIT-', enable_events=True, readonly=True, font=("Helvetica", 16)),sg.Checkbox("Revert Attack", key="-REVERT_CHECKBOX-", visible=False, font=("Helvetica", 16))],
        [sg.Text("Description:", key="-DESCRIPTION-", font=("Helvetica", 16, "bold")), sg.Text(exploit_dict[exploit_list[1]],key="-DESCRIPTION_TEXT-", font=("Helvetica", 16))],
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
                thread = threading.Thread(target=launch_exploit, args=(values['-EXPLOIT-'], values["-IP_INPUT-"], window, values["-VAR1_INPUT-"], values["-VAR2_INPUT-"], values["-VAR3_INPUT-"], values["-VAR4_INPUT-"], values["-VAR5_INPUT-"], values["-REVERT_CHECKBOX-"]))
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
            window["-REVERT_CHECKBOX-"].update(visible=False, value=False)
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

            if selected_exploit in revertible_attacks:
                window["-REVERT_CHECKBOX-"].update(visible=True)

            if selected_exploit == "===== KEP SERVER EXPLOITS =====":
                window["-EXPLOIT-"].update(value=exploit_list[1])
            
            elif selected_exploit == "====== MODBUS EXPLOITS ======":
                window["-EXPLOIT-"].update(value=exploit_list[54])
                
            elif selected_exploit == "======== IT EXPLOITS ========":
                window["-EXPLOIT-"].update(value=exploit_list[60])

            elif selected_exploit in ["Enable user", "Disable user", "Get single user", "Delete user"]:
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
            
            elif selected_exploit in ["Get single user group", "Add user group", "Delete user group", "Upgrade user group", "Downgrade user group"]:
                window["-VAR1_TEXT-"].update("User group:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)

            elif selected_exploit in ["Add spoofed channel", "Delete channel", "Get single channel"]:
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

            elif selected_exploit in ["Get single device", "Add device", "Delete device", "Get full tag structure", "Get single tag", "Auto generate tags"]:
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

            elif selected_exploit in ["Add UDD profile", "Delete UDD profile", "Modify UDD profile"]:
                window["-VAR1_TEXT-"].update("Profile Name:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)

                if selected_exploit == "Add UDD profile":
                    window["-VAR2_TEXT-"].update("Description:", visible=True)
                    window["-VAR2_INPUT-"].update("", visible=True)
                
                elif selected_exploit == "Modify UDD profile":
                    window["-VAR2_TEXT-"].update("New Profile Name:", visible=True)
                    window["-VAR2_INPUT-"].update("", visible=True)
                    window["-VAR2_TEXT-"].update("New Description:", visible=True)
                    window["-VAR2_INPUT-"].update("", visible=True)

            elif selected_exploit in ["Get all log items", "Add log item", "Delete log item", "Add log group", "Delete log group", "Enable log group", "Disable log group"]:
                window["-VAR1_TEXT-"].update("Log Group:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)
                
                if selected_exploit in ["Add log item", "Delete log item"]:
                    window["-VAR2_TEXT-"].update("Log Item:", visible=True)
                    window["-VAR2_INPUT-"].update("", visible=True)
                
                elif selected_exploit == "Add log group":
                    window["-VAR2_TEXT-"].update("Description:", visible=True)
                    window["-VAR2_INPUT-"].update("", visible=True)

            elif selected_exploit == "Change log data value":
                window["-VAR1_TEXT-"].update("Meter ID:", visible=True)
                window["-VAR1_INPUT-"].update("", visible=True)

        window['-SPINNER-'].update_animation("./images/loading.gif",  time_between_frames=25)
        window['-SERVICE_SPINNER-'].update_animation("./images/Spinner-1s-21px.gif",  time_between_frames=25)
    # Close the main window
    window.close()

if __name__ == "__main__":
    main()