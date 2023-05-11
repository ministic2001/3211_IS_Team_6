from kepconfig import connection

server = connection.server(host = '172.16.2.77', port = 57412, user = 'Administrator', pw = 'administrator2022')

print(server.get_info())