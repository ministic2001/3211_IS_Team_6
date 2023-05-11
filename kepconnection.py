from kepconfig import connection

# 172.16.2.77 if at lv 7
# 172.16.2.223 if at lv 6
server = connection.server(host = '172.16.2.77', port = 57412, user = 'Administrator', pw = 'administrator2022')

print(server.get_info())