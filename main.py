import os
import socket
import struct
import time
import ssl
import dns.resolver

# constants
ENCODING = 'utf-8'
HTTP_PORT = 80
SMTP_PORT = 25
SSL_PORT = 443
HTTP_GET_REQUEST = 'GET / HTTP/1.1\n\n'
RECEIVE_LENGTH = 4096  # 4kB
MESSAGE_LENGTH_SIZE = 16  # 16B
DEFAULT_DESTINATION_SMTP_SERVER = 'aut.ac.ir'
WELCOME_MESSAGE = 'Server > Welcome. Connection Stablished and you can start sending commands.'


# default SMTP information to send an email (you should fill it yourself with your info.)
DEFAULT_SMTP_INFORMATION = {
    'destination_smtp_server': 'asg.aut.ac.ir',
    'source_domain': 'gmail.com',
    'sender_email_address': 'mr.dorudian@gmail.com',
    'recipient_email_address': 'elmo@aut.ac.ir',
    'message_subject': 'Emailing with Telnet',
    'message_body': '___congrats___',
}


# SMTP commands to send an email
SMTP_COMMANDS = [
    f'OPEN {DEFAULT_SMTP_INFORMATION["destination_smtp_server"]} {SMTP_PORT}\n',
    f'EHLO {DEFAULT_SMTP_INFORMATION["source_domain"]}\n',
    f'MAIL FROM: <{DEFAULT_SMTP_INFORMATION["sender_email_address"]}>\n',
    f'RCPT TO: <{DEFAULT_SMTP_INFORMATION["recipient_email_address"]}>\n',
    f'DATA\n',
    f'Subject: {DEFAULT_SMTP_INFORMATION["message_subject"]}\n',
    f'{DEFAULT_SMTP_INFORMATION["message_body"]}\n.\n',
    f'QUIT\n',
]


# scans the given IP ports and prints the result
def port_scan():
    target = input('Enter the host to be scanned: ')
    address = socket.gethostbyname(target)
    print('Specify the range:')
    starting_port = int(input('Start >>> '))
    ending_port = int(input('End >>> '))
    for port in range(starting_port, ending_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((address, port)) == 0:
                print(f'Port {port} is: OPEN')


# finds out the IP address of of the receiver mail-server
# def dns_lookup(domain):
#     response = str(dns.resolver.resolve(domain, 'MX')[0])
#     for element in response:
#         if element.isdigit():
#             response = response.replace(element, '')
#     print(response.strip()[:-1])
#     DEFAULT_SMTP_INFORMATION['destination_smtp_server'] = response.strip()[:-1]


# sends and email based on the given information
def send_email(client_socket):
    # dns_lookup(DEFAULT_DESTINATION_SMTP_SERVER)
    for i in range(len(SMTP_COMMANDS)):
        client_socket.send(SMTP_COMMANDS[i].encode(ENCODING))
        print(f'Server > {client_socket.recv(RECEIVE_LENGTH).decode(ENCODING)}')

# sends an HTTP request to the given host
def send_HTTP_request(client_socket):
    print('You are able to send HTTP request based on the Port you entered.')
    request = int(input('choose:\n    Enter a HTTP command[1]\n    We send a sample request[2]\n'))
    command = None
    if request == 1:
        command = input('Enter your command:\n')
        command += '\n\n'
    elif request == 2:
        command = HTTP_GET_REQUEST
    print('Sending command...')
    command = command.encode(ENCODING)
    client_socket.send(command)
    response = client_socket.recv(RECEIVE_LENGTH).decode(ENCODING)
    input('Response is ready, press ENTER to show\n')
    print(response)


# handle whole client-side works
def send_telnet_request(hostname='127.0.0.1', port=23):
    address = socket.gethostbyname(hostname)
    server_information = (address, port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        try:
            client.connect(server_information)
            print('Connected to Sever.')
        except Exception as e:
            print(f'ERROR occurred: {e}')
            try_again = input('Try again? [y/n]: ')
            if try_again == 'y':
                send_telnet_request(input('Enter Hostname: '), int(input('Enter port: ')))
            else:
                print('Connection Closed by Client.')
                return -1
        if port == HTTP_PORT:
            send_HTTP_request(client)
        elif port == SMTP_PORT:
            print('You are able to send an Email based on the Port you entered.')
            request = int(input('choose:\n    Enter a SMTP command[1]\n    We send a sample request[2]\n'))
            if request == 1:
                DEFAULT_SMTP_INFORMATION['destination_smtp_server'] = input('Enter <destination_smtp_server>: ')
                DEFAULT_SMTP_INFORMATION['source_domain'] = input('Enter <source_domain> : ')
                DEFAULT_SMTP_INFORMATION['sender_email_address'] = input('Enter <sender_email_address> : ')
                DEFAULT_SMTP_INFORMATION['recipient_email_address'] = input('Enter <recipient_email_address> : ')
                DEFAULT_SMTP_INFORMATION['message_subject'] = input('Enter <message_subject> : ')
                DEFAULT_SMTP_INFORMATION['message_body'] = input('Enter <message_body> : ')
            send_email(client)
        else:
            print(receive_message(client))
            while True:
                command = input('Your command: ')
                if 'telnet send "' in command:
                    send_message(client, command)
                elif '-e "' in command:
                    send_message(client, command)
                    time.sleep(1)
                    encrypt(hostname, command.split('"')[1].strip())
                elif 'telnet upload "' in command:
                    send_message(client, command)
                    upload_command(client, command)
                elif 'telnet exec "' in command:
                    send_message(client, command)
                elif 'telnet history' in command:
                    send_message(client, command)
                else:
                    continue
                print(receive_message(client))


# handle "telnet history" command
def history_command(connection):
    with open('history.txt', 'r') as file:
        message = '==========History==========\n'
        message += file.read()
        message += '==========History==========\n'
        send_message(connection, message)
    pass


# main function to send any type of data with no volume limit
def send_message(client, message):
    if type(message) is not bytes:
        message = message.encode(ENCODING)
    message_length = str(len(message)).encode(ENCODING)
    message_length += b'' * (MESSAGE_LENGTH_SIZE - len(message_length))
    client.send(message_length)
    client.send(message)


# a function to receive messages
def receiveall(connection):
    def recv_msg(socket_connection):
        raw_message_length = receive_all(socket_connection, 4)
        if not raw_message_length:
            return None
        message_length = struct.unpack('>I', raw_message_length)[0]
        return receive_all(socket_connection, message_length)

    def receive_all(socket_connection, n):
        data = bytearray()
        while len(data) < n:
            segment = socket_connection.recv(n - len(data))
            if not segment:
                return None
            data.extend(segment)
        return data

    return recv_msg(connection)


# main function to receive any type of data with no volume limit
def receive_message(client):
    message_length = int(client.recv(MESSAGE_LENGTH_SIZE).decode(ENCODING))
    message = client.recv(message_length).decode(ENCODING)
    return message


# handle "telnet send 'message' command"
def send_command(connection, message='Hello'):
    send_message(connection, message)


# handle "telnet upload 'path' command"
def upload_command(connection, path):
    path = path.split('"')[1].strip()
    with open(path, 'rb') as file:
        data = file.read()
    data = struct.pack('>I', len(data)) + data
    connection.sendall(data)


# handle "telnet exec 'command' command"
def exec_command(connection, command):
    command = command.split('"')[1].strip()
    os.system(command)


# save command history in history.txt file
def save_history(command):
    with open('history.txt', 'a') as file:
        file.write(command)
        file.write('\n')
    pass


# used for TLS encryption
def encrypt(address, message='Hello'):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('cert.pem')
    with socket.create_connection((address, SSL_PORT)) as client:
        with context.wrap_socket(client, server_hostname='example.org') as tls:
            print(f'**{tls.version()}**')
            send_message(tls, message)
            data = receive_message(tls)
            print(data)


# used for TLS decryption
def decrypt(connection):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('cert.pem', 'key.pem')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((connection[0], SSL_PORT))
        server.listen()
        print('TLS server waiting...')
        with context.wrap_socket(server, server_side=True) as tls:
            connection, address = tls.accept()
            print(f'Connected by {address}\n')
            data = receive_message(connection)
            send_message(connection, 'TLS Server > Ack')
            return data


# handle a single client works
def handle_client(connection, address):
    print(f'New connection form: {address}')
    send_message(connection, WELCOME_MESSAGE)
    while True:
        command = receive_message(connection)
        save_history(command)

        if 'telnet send "' in command:
            print(command.split('"')[1].strip())
            send_message(connection, 'Server > Ack')

        elif '-e "' in command:
            message = decrypt(address)
            print(message)
            time.sleep(1)
            send_message(connection, 'Server > Ack')

        elif 'telnet upload "' in command:
            path = command.split('"')[1].strip()
            name = path.split(".")[0].split("/")
            if len(name) == 1:
                name = name[0]
            else:
                name = name[1]
            file_format = command.split(".")[-1][:-1]
            data = receiveall(connection)
            with open(f'downloads/downloaded_{name}.{file_format}', 'wb') as file:
                file.write(data)
            send_message(connection, 'Server > Ack')

        elif 'telnet exec "' in command:
            exec_command(connection, command)
            send_message(connection, 'Server > Ack')

        elif 'telnet history' in command:
            history_command(connection)

        else:
            print(receive_message(connection))
            send_message(connection, 'Invalid command'.encode(ENCODING))


# handle whole server-side works
def handle_telnet_request(hostname='127.0.0.1', port=23):
    address = socket.gethostbyname(hostname)
    host_information = (address, port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(host_information)
        server.listen()
        print('waiting for a connection...')
        while True:
            connection, client_address = server.accept()
            handle_client(connection, client_address)


# some initialization
def initialize():
    # Erase the history file and start a new one
    open('history.txt', 'w').close()


def main():
    initialize()
    print('Welcome to Telnet.\n')
    mode = input('Choose server-peer[1] or client-peer[2]\n')
    address = input('Enter a hostname or an IP address: ')
    check_ports = input('You can check ports now if you want to make sure to choose a free port [y/n]: ')
    if check_ports == 'y':
        port_scan()
    port = input('Enter a port number: ')
    input('Everything set up.\nPress Enter to start connecting')
    if mode == '1':
        handle_telnet_request(address, int(port))
    elif mode == '2':
        send_telnet_request(address, int(port))


if __name__ == '__main__':
    main()
