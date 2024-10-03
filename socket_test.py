import time
import threading
import socket
import os
from protocol import SilentProtocol
import json

SOCKET_PATH = "/tmp/protocol_socket"

def binary_string_to_bytes(binary_str: str) -> bytes:
    binary_str = binary_str.replace(" ", "")
    byte_data = int(binary_str, 2)
    return byte_data.to_bytes((len(binary_str) + 7) // 8, byteorder='big')

def bytes_to_binary_string(byte_data: bytes) -> str:
    return ''.join(format(byte, '08b') for byte in byte_data)

def server():
    protocol = SilentProtocol()
    server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    try:
        os.unlink(SOCKET_PATH)
    except OSError:
        if os.path.exists(SOCKET_PATH):
            raise

    server_socket.bind(SOCKET_PATH)
    server_socket.listen(1)
    print("Server listening...")

    connection, _ = server_socket.accept()
    print("Connection established with client.")

    try:
        # Receive handshake request from client
        handshake_request = connection.recv(4096)
      #  print(f"Server received handshake request: {handshake_request.hex()}")

        # Respond to the handshake request
        response, private_key, session_id = protocol.perform_handshake_response(handshake_request)
        if not response:
            print("Failed to perform handshake response.")
            return
       # print(f"Server sending handshake response: {response.hex()}")
        connection.sendall(response)

        # Receive data from client
        data = connection.recv(4096)
     #   print(f"Server received data: {data.hex()}")
        if data:
            decrypted_message, header, message_type = protocol.decrypt_data(bytes_to_binary_string(data))
            received_message = decrypted_message.decode(header['encoding'])
            print(f"Received from client: {received_message}")

            # Verify data integrity
            expected_message = '{"message": "Hello, Server!"}'
            if received_message == expected_message:
                print("Data integrity verified: Received message matches expected message.")
            else:
                print("Data integrity check failed: Received message does not match expected message.")

            # Send a response back to client
            response_data = json.dumps({"response": "Message received"}).encode('utf-8')
            encrypted_response = protocol.create_response(session_id, response_data)
         #   print(f"Server sending response: {encrypted_response}")
            connection.sendall(binary_string_to_bytes(encrypted_response))

    finally:
        connection.close()
        server_socket.close()
        os.unlink(SOCKET_PATH)

def client():
    protocol = SilentProtocol()
    client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    
    # Wait for the server to be ready
    time.sleep(1)
    
    client_socket.connect(SOCKET_PATH)
    print("Connected to server.")

    try:
        # Initiate handshake with server
        handshake_request, private_key = protocol.perform_handshake_request()
      #  print(f"Client sending handshake request: {handshake_request.hex()}")
        client_socket.sendall(handshake_request)

        # Receive handshake response from server
        response = client_socket.recv(4096)
      #  print(f"Client received handshake response: {response.hex()}")
        session_id = protocol.complete_handshake(response, private_key)
        if not session_id:
            print("Failed to complete handshake.")
            return

        print("Handshake completed successfully.")
        print("Session ID: ", session_id.hex())

        # Send a message to server
        message = "Hello, Server!"
        request_data = json.dumps({"message": message}).encode('utf-8')
        encrypted_request = protocol.create_request(session_id, request_data)
      #  print(f"Client sending request: {encrypted_request}")
        client_socket.sendall(binary_string_to_bytes(encrypted_request))

        # Receive a response from server
        data = client_socket.recv(4096)
    #    print(f"Client received response: {data.hex()}")
        if data:
            decrypted_response, header, message_type = protocol.decrypt_data(bytes_to_binary_string(data))
            received_response = decrypted_response.decode(header['encoding'])
     #       print(f"Received from server: {received_response}")

            # Verify response integrity
            expected_response = '{"response": "Message received"}'
            if received_response == expected_response:
                print("Response integrity verified: Received response matches expected response.")
            else:
                print("Response integrity check failed: Received response does not match expected response.")

    finally:
        client_socket.close()

def main():
    # Run server and client in separate threads
    server_thread = threading.Thread(target=server)
    client_thread = threading.Thread(target=client)

    server_thread.start()
    client_thread.start()

    server_thread.join()
    client_thread.join()

if __name__ == "__main__":
    main()