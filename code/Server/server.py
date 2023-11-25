import socket

LISTEN_PORT = 666
RECV = 1024

WELCOME_MESSAGE = "Welcome to our Network Scanning server"

def open_client_socket():
    """
    the function creates a listening socket and bind the socket, what creates client socket,
    then the server send the welcome message to the client
    :return: the client socket and the listening socket
    :rtype: tuple
    """
    listening_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create listening socket
    server_address = ('', LISTEN_PORT)
    listening_sock.bind(server_address)
    listening_sock.listen(1)
    client_sock, client_address = listening_sock.accept()  # create conversation socket
    client_sock.sendall(WELCOME_MESSAGE.encode())
    return client_sock, listening_sock

def main():
    client_sock, listening_sock = open_client_socket()

    try:
        client_msg = client_sock.recv(RECV)  # get message from the client
        client_msg = client_msg.decode()
        print(client_msg)
    except Exception:
        listening_sock.close()


if(__name__ == "__main__"):
    main()
