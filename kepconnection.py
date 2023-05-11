from kepconfig import connection, admin

# 172.16.2.77 if at lv 7
# 172.16.2.223 if at lv 6
server = connection.server(host = '172.16.2.77', port = 57412, user = 'Administrator', pw = 'administrator2022')

print(server.get_info())

print(admin.users.get_all_users(server))

print(admin.users.enable_user(server, "User1"))

print(admin.users.get_user(server, "User1" ))

