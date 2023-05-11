from kepconfig import connection, admin, connectivity

# 172.16.2.77 if at lv 7
# 172.16.2.223 if at lv 6
server = connection.server(host = '172.16.2.77', port = 57412, user = 'Administrator', pw = 'administrator2022')

DATA = ""

print(server.get_info())

print(admin.users.get_all_users(server))

print(admin.users.enable_user(server, "User1"))

print(admin.users.get_user(server, "User1"))


#Get all channel
print("\n\n" + str(connectivity.channel.get_all_channels(server)))

#After getting channel, get single device within channel

print("\n\n" + str(connectivity.device.get_device(server, "SmartMeter.Device10")))

#After getting channel, get all device within channel

#print("\n\n" + str(connectivity.device.get_all_devices(server, "SmartMeter")))

