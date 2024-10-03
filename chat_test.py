import socket
import os
import sys
import json
from protocol import SilentProtocol, binary_string_to_bytes, bytes_to_binary_string

SOCKET_PATH = "/tmp/protocol_socket"

def run_protocol(role):
    # Initialize SilentProtocol
    protocol = SilentProtocol()

    if role == 'a':
        # Act as Protocol A (Server)
        server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # Ensure the socket does not already exist
        try:
            os.unlink(SOCKET_PATH)
        except OSError:
            if os.path.exists(SOCKET_PATH):
                raise

        server_socket.bind(SOCKET_PATH)
        server_socket.listen(1)
        print("Protocol A (Server) listening...")

        connection, _ = server_socket.accept()
        print("Connection established with Protocol B.")

        try:
            # Receive handshake request from Protocol B
            handshake_request = connection.recv(4096)
            print(f"Server received handshake request: {handshake_request.hex()}")

            # Respond to the handshake request
            response, private_key, session_id = protocol.perform_handshake_response(handshake_request)
            if not response:
                print("Failed to perform handshake response.")
                return
            print(f"Server sending handshake response: {response.hex()}")
            connection.sendall(response)

            print("Handshake completed successfully.")
            print("Session ID: ", session_id.hex())

            while True:
                # Receive data from Protocol B
                data = connection.recv(4096)
                if not data:
                    break

                # Decrypt and process the received message
                decrypted_message, header, message_type = protocol.decrypt_data(bytes_to_binary_string(data))
                if decrypted_message is None:
                    print("Failed to decrypt message.")
                    continue
                print(f"Received from Protocol B: {decrypted_message.decode(header['encoding'])}")

                # Send a response back to Protocol B
                response_data = json.dumps({"response": "Message received"}).encode('utf-8')
                encrypted_response = protocol.create_response(session_id, response_data)
                connection.sendall(binary_string_to_bytes(encrypted_response))

        finally:
            connection.close()
            server_socket.close()
            os.unlink(SOCKET_PATH)

    elif role == 'b':
        # Act as Protocol B (Client)
        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_socket.connect(SOCKET_PATH)
        print("Connected to Protocol A (Server).")

        try:
            # Initiate handshake with Protocol A
            handshake_request, private_key = protocol.perform_handshake_request()
            print(f"Client sending handshake request: {handshake_request.hex()}")
            client_socket.sendall(handshake_request)

            # Receive handshake response from Protocol A
            response = client_socket.recv(4096)
            print(f"Client received handshake response: {response.hex()}")
            session_id = protocol.complete_handshake(response, private_key)
            if not session_id:
                print("Failed to complete handshake.")
                return

            print("Handshake completed successfully.")
            print("Session ID: ", session_id.hex())

            while True:
                # Send a message to Protocol A
                message = input("Enter message to send: ")
                request_data = json.dumps({"message": message}).encode('utf-8')
                encrypted_request = protocol.create_request(session_id, request_data)
                client_socket.sendall(binary_string_to_bytes(encrypted_request))

                # Receive a response from Protocol A
                data = client_socket.recv(4096)
                if not data:
                    break

                # Decrypt and process the received response
                decrypted_response, header, message_type = protocol.decrypt_data(bytes_to_binary_string(data))
                if decrypted_response is None:
                    print("Failed to decrypt response.")
                    continue
                print(f"Received from Protocol A: {decrypted_response.decode(header['encoding'])}")

        finally:
            client_socket.close()

    else:
        print("Invalid role specified. Use 'a' for Protocol A or 'b' for Protocol B.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        role = 'b'
    else:
        role = sys.argv[1].lower()
    run_protocol(role)