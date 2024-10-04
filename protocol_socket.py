import socket
import json
from protocol_wrapper import ProtocolWrapper, DATA_FLAG, RESPONSE_FLAG, binary_string_to_bytes
import sys

class SocketProtocolWrapper:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.protocol_wrapper = ProtocolWrapper()

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        print(f"Server listening on {self.host}:{self.port}")

        connection, address = server_socket.accept()
        print(f"Connection established with {address}")

        try:
            # Receive handshake request from client
            handshake_request = connection.recv(4096)
            print("Received handshake request")
            response = binary_string_to_bytes(self.protocol_wrapper.respond_handshake(handshake_request))
            print("Sending handshake response")
            connection.sendall(response)

            while True:
                # Receive data from client
                data = connection.recv(4096)
               
                if not data:
                    break
                print("Received data")
                # Decrypt and process the received message
                received_data, header, message_type = self.protocol_wrapper.decrypt_and_receive(data)
                print(f"Received from client: {received_data}")

                # Send a response back to client
                response_data = {"response": "Message received"}
                encrypted_response = binary_string_to_bytes(self.protocol_wrapper.encrypt_and_send(response_data, RESPONSE_FLAG))
                print("Sending encrypted response")
                connection.sendall(encrypted_response)

        finally:
            connection.close()
            server_socket.close()

    def start_client(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host, self.port))
        print(f"Connected to server at {self.host}:{self.port}")

        try:
            # Initiate handshake with server
            handshake_request = self.protocol_wrapper.create_handshake_request()
            print(len(handshake_request))
            print("Sending handshake request")
            client_socket.sendall(binary_string_to_bytes(handshake_request))

            # Receive handshake response from server
            print("Receiving handshake response")
            response = client_socket.recv(4096)
            self.protocol_wrapper.complete_handshake(response)

            while True:
                # Send a message to server
                message = input("Enter message to send: ")
                request_data = {"message": message}
                encrypted_request = binary_string_to_bytes(self.protocol_wrapper.encrypt_and_send(request_data, DATA_FLAG))
                print("Sending encrypted request")
                client_socket.sendall(encrypted_request)

                # Receive a response from server
                data = client_socket.recv(4096)
                if not data:
                    break
                print("Received encrypted response")
                # Decrypt and process the received response
                received_response, header, message_type = self.protocol_wrapper.decrypt_and_receive(data)
                print(f"Received from server: {received_response}")

        finally:
            client_socket.close()



def main():

    host = '0.0.0.0'
    port = 12345

    if len(sys.argv) != 2:
        wrapper = SocketProtocolWrapper(host=host, port=port)  # Use '0.0.0.0' to listen on all interfaces

        wrapper.start_server()
        exit()

    role = sys.argv[1].lower()
    wrapper = SocketProtocolWrapper(host=host, port=port)  # Use '0.0.0.0' to listen on all interfaces

    if role == 'server':
        wrapper.start_server()
    elif role == 'client':
        wrapper.start_client()
    else:
        wrapper.start_server()

if __name__ == "__main__":
    main()