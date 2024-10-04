from protocol import SilentProtocol, HANDSHAKE_FLAG, DATA_FLAG, RESPONSE_FLAG, binary_string_to_bytes
import json


class ProtocolWrapper:
    def __init__(self):
        self.protocol = SilentProtocol()
        self.session_id = None
        self.private_key = None

    def create_handshake_request(self):
        # Create a handshake request and store the private key
        handshake_request, self.private_key = self.protocol.perform_handshake_request()
        if not handshake_request:
            raise Exception("Failed to initiate handshake request.")
        if self.private_key is None:
            raise Exception("Private key was not generated.")
        return handshake_request

    def respond_handshake(self, handshake_request):
        # Respond to a handshake request and generate a new private key
        response, self.private_key, self.session_id = self.protocol.perform_handshake_response(handshake_request)
        if not response:
            raise Exception("Failed to create handshake response.")
        if self.private_key is None:
            raise Exception("Private key was not generated.")
        if not self.session_id:
            raise Exception("Session ID was not generated.")
        print(f"Session ID established: {self.session_id.hex()}")
        return response

    def complete_handshake(self, response):
        # Complete the handshake using the response and private key
        self.session_id = self.protocol.complete_handshake(response, self.private_key)
        if not self.session_id:
            raise Exception("Failed to complete handshake.")
        print(f"Session ID established: {self.session_id.hex()}")

    def encrypt_and_send(self, data, flag, response_code=200):
        if not self.session_id:
            raise Exception("No active session. Please initiate a handshake first.")

        request_data = json.dumps(data).encode('utf-8')

        if flag == DATA_FLAG:
            encrypted_message = self.protocol.create_request(self.session_id, request_data)
        elif flag == RESPONSE_FLAG:
            encrypted_message = self.protocol.create_response(self.session_id, request_data, response_code)
        else:
            raise ValueError("Invalid flag provided. Use DATA_FLAG or RESPONSE_FLAG.")

        if encrypted_message is None:
            raise Exception("Failed to encrypt message.")

        return encrypted_message

    def decrypt_and_receive(self, encrypted_response):
        if not self.session_id:
            raise Exception("No active session. Please initiate a handshake first.")

        decrypted_response, response_header, flag = self.protocol.decrypt_data(encrypted_response)
        if decrypted_response is None:
            raise Exception("Failed to decrypt response.")

        # Determine the message type based on the flag
        if flag == DATA_FLAG:
            message_type = "data"
        elif flag == RESPONSE_FLAG:
            message_type = "response"
        elif flag == HANDSHAKE_FLAG:
            message_type = "handshake"
        else:
            message_type = "unknown"

        response_data = json.loads(decrypted_response.decode(response_header['encoding']))
        return response_data, response_header, message_type



def main():
    print("=== Testing ProtocolWrapper ===")

    # Initialize wrapper objects for Node A and Node B
    wrapper_a = ProtocolWrapper()
    wrapper_b = ProtocolWrapper()

    # Node A creates a handshake request
    handshake_request = wrapper_a.create_handshake_request()
    print(f"Node A created handshake request")

    # Node B responds to the handshake request
    response = wrapper_b.respond_handshake(handshake_request)
    print(f"Node B created handshake response")

    # Node A completes the handshake using the response
    wrapper_a.complete_handshake(response)

    # Node A sends a request to Node B
    request_data = {"action": "get_data"}
    encrypted_request = wrapper_a.encrypt_and_send(request_data, DATA_FLAG)
    print("Node A sends encrypted request")

    # Node B decrypts the request and sends a response
    received_request, request_header, message_type = wrapper_b.decrypt_and_receive(encrypted_request)
    print("Message Type:", message_type)
    print("Request Header:", request_header)
    print("Node B received request:", received_request)
    
    response_data = {"data": "Here is your data"}
    encrypted_response = wrapper_b.encrypt_and_send(response_data, RESPONSE_FLAG)
    print(f"Node B sends encrypted response")

    # Node A decrypts the response
    received_response, response_header, message_type = wrapper_a.decrypt_and_receive(encrypted_response)
    print("Message Type:", message_type)
    print("Response Header:", response_header)
    print("Node A received response:", received_response)
    

if __name__ == "__main__":
    main()