from kepconfig import connection, admin, connectivity
import json

# 172.16.2.77 if at lv 7
# 172.16.2.223 if at lv 6
server = connection.server(host = '172.16.2.77', port = 57412, user = 'Administrator', pw = 'administrator2022')

DATA = ""

### Get Server info
print(server.get_info())

### Get all users
#print(admin.users.get_all_users(server))

### Enable/Disable single user
#print(admin.users.enable_user(server, "User1"))
#print(admin.users.disable_user(server, "User1"))

### Get single user to confirm
#print(admin.users.get_user(server, "administrator"))
#print(admin.users.get_user(server, "bigboi"))

### Get all user groups
#print(json.dumps(admin.user_groups.get_all_user_groups(server), indent=4))

### Get single user group
#print(json.dumps(admin.user_groups.get_user_group(server, "readtesting"), indent=4))

print(json.dumps(admin.users.modify_user(server, {"common.ALLTYPES_DESCRIPTION": "TEST UPDATE", "libadminsettings.USERMANAGER_USER_GROUPNAME": "readtesting"}, "bigboi" ), indent=4))
print(admin.users.get_user(server, "bigboi"))


### Modify user group permissions
# print(json.dumps(admin.user_groups.modify_user_group(server, {"common.ALLTYPES_DESCRIPTION": "Built-in group for bigboi", "libadminsettings.USERMANAGER_IO_TAG_READ": "Enable" 
#         # "libadminsettings.USERMANAGER_GROUP_ENABLED": "true",
#         # "libadminsettings.USERMANAGER_IO_TAG_READ": "true" , 
#         # "libadminsettings.USERMANAGER_IO_TAG_WRITE": "true",
#         # "libadminsettings.USERMANAGER_IO_TAG_DYNAMIC_ADDRESSING": "true",
#         # "libadminsettings.USERMANAGER_SYSTEM_TAG_READ": "true",
#         # "libadminsettings.USERMANAGER_SYSTEM_TAG_WRITE": "true",
#         # "libadminsettings.USERMANAGER_INTERNAL_TAG_READ": "true",
#         # "libadminsettings.USERMANAGER_INTERNAL_TAG_WRITE": "true",
#         # "libadminsettings.USERMANAGER_SERVER_MANAGE_LICENSES": "true",
#         # "libadminsettings.USERMANAGER_SERVER_RESET_OPC_DIAGS_LOG": "true",
#         # "libadminsettings.USERMANAGER_SERVER_RESET_COMM_DIAGS_LOG": "true",
#         # "libadminsettings.USERMANAGER_SERVER_MODIFY_SERVER_SETTINGS": "true",
#         # "libadminsettings.USERMANAGER_SERVER_DISCONNECT_CLIENTS": "true",
#         # "libadminsettings.USERMANAGER_SERVER_RESET_EVENT_LOG": "true",
#         # "libadminsettings.USERMANAGER_SERVER_OPCUA_DOTNET_CONFIGURATION": "true",
#         # "libadminsettings.USERMANAGER_SERVER_CONFIG_API_LOG_ACCESS": "true",
#         # "libadminsettings.USERMANAGER_SERVER_REPLACE_RUNTIME_PROJECT": "true",
#         # "libadminsettings.USERMANAGER_BROWSE_BROWSENAMESPACE": "true",
#         # "libadminsettings.USERMANAGER_SERVER_VIEW_EVENT_LOG_SECURITY": "true",
#         # "libadminsettings.USERMANAGER_SERVER_VIEW_EVENT_LOG_ERROR": "true",
#         # "libadminsettings.USERMANAGER_SERVER_VIEW_EVENT_LOG_WARNING": "true",
#         # "libadminsettings.USERMANAGER_SERVER_VIEW_EVENT_LOG_INFO": "true"
#         }, user_group="readtesting"), indent=4)) 


### Get all channel
#print("\n\n" + json.dumps(connectivity.channel.get_all_channels(server), indent=4))

### After getting channel, get all device within channel
#print("\n\n" + str(connectivity.device.get_all_devices(server, "SmartMeter")))

### After getting channel, get single device within channel
#print("\n\n" + json.dumps(connectivity.device.get_device(server, "SmartMeter.ministicHACKED"), indent=4))

#print(json.dumps(connectivity.tag.get_full_tag_structure(server,"SmartMeter.ministicHACKED"), indent=4))

print(json.dumps(connectivity.tag.get_all_tags(server, "SmartMeter.ministicHACKED"), indent=4))



#print(json.dumps(connectivity.tag.add_tag(server, "SmartMeter.ministicHACKED", {"common.ALLTYPES_NAME": "TEST", "servermain.TAG_ADDRESS": "40003"}), indent=4))

#print(json.dumps(connectivity.tag.del_tag(server, "SmartMeter.ministicHACKED.TEST"), indent=4))

print(json.dumps(connectivity.tag.modify_tag(server, "SmartMeter.ministicHACKED.UPDATEBOI", {"PROJECT_ID": 3708177172,  "common.ALLTYPES_NAME": "UPDATEBOI1"}), indent=4))
print(json.dumps(connectivity.tag.get_all_tags(server, "SmartMeter.ministicHACKED"), indent=4))

print(json.dumps(connectivity.udd.profile.modify_profile(server, {"common.ALLTYPES_NAME": "ModbusProfile",
                                                                  "common.ALLTYPES_DESCRIPTION": "a short description"}),
                 indent=4))
print(json.dumps(connectivity.udd.profile.get_profile(server, "Derrick"), indent=4))
###  Add Device to spoof 
#print("ADD DEVICE: " + json.dumps(connectivity.device.add_device(server, "SmartMeter", {"common.ALLTYPES_NAME": "Device69", "servermain.MULTIPLE_TYPES_DEVICE_DRIVER": "Modbus RTU Serial", "servermain.DEVICE_SCAN_MODE_RATE_MS": 8888888}), indent=4))
#print("\n" + json.dumps(connectivity.device.get_device(server, "SmartMeter.Device69"), indent=4))

### Delete Device 
#print("DELETE DEVICE: " + json.dumps(connectivity.device.del_device(server, "SmartMeter.Device69"), indent=4))

print(json.dumps(connectivity.egd.name.modify_name_resolution(server, "SmartMeter.Device69", {
    "ge_ethernet_global_data.NAME_RESOLUTION_ALIAS": "PLC1",
    "ge_ethernet_global_data.NAME_RESOLUTION_IP_ADDRESS": "192.168.1.200"}), indent=4))
print(json.dumps(connectivity.egd.name.get_name_resolution(server, "SmartMeter.Device69"), indent=4))

