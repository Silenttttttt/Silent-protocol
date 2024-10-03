import json
from protocol import SilentProtocol


class SilentProtocolWrapper:
    def __init__(self):
        self.protocol = SilentProtocol()
        self.private_key = None
        self.session_id = None

    def initiate_handshake(self):
        handshake_request, self.private_key = self.protocol.perform_handshake_request()
        return handshake_request

    def respond_to_handshake(self, handshake_request):
        response, self.private_key = self.protocol.perform_handshake_response(handshake_request)
        return response

    def complete_handshake(self, response):
        self.session_id = self.protocol.complete_handshake(response, self.private_key)
        return self.session_id

    def set_session_id(self, session_id):
        self.session_id = session_id

    def send_request(self, request_data):
        if not self.session_id:
            print("Session not established.")
            return None
        return self.protocol.create_request(self.session_id, request_data)

    def send_response(self, response_data, response_code=200):
        if not self.session_id:
            print("Session not established.")
            return None
        return self.protocol.create_response(self.session_id, response_data, response_code)

    def receive_data(self, encoded_packet):
        return self.protocol.decrypt_data(encoded_packet)

# Example usage
def main():
    print("=== Using SilentProtocolWrapper ===")
    # Initialize wrapper objects for Node A and Node B
    node_a = SilentProtocolWrapper()
    node_b = SilentProtocolWrapper()

    # Node A initiates a handshake request to Node B
    handshake_request = node_a.initiate_handshake()
    if not handshake_request:
        print("Failed to perform handshake request.")
        return

    # Node B responds to the handshake request
    response = node_b.respond_to_handshake(handshake_request)
    if not response:
        print("Failed to perform handshake response.")
        return

    # Node A completes the handshake by processing the response
    session_id = node_a.complete_handshake(response)
    if not session_id:
        print("Failed to complete handshake.")
        return

    # Node B also needs to complete the handshake to set its session ID
    node_b.set_session_id(session_id)

    # Node A sends a request to Node B
    request_data = json.dumps({"action": "get_data"}).encode('utf-8')
    encrypted_request = node_a.send_request(request_data)
    if encrypted_request is None:
        print("Failed to send request.")
        return

    # Node B decrypts the request and sends a response
    decrypted_request, request_header, message_type = node_b.receive_data(encrypted_request)
    if decrypted_request is None:
        print("Failed to decrypt request.")
        return

    print("Message Type:", message_type)
    print("Decrypted request:", decrypted_request.decode(request_header['encoding']))
    print("Request Header:", request_header)

    response_data = json.dumps({"data": "Here is your data"}).encode('utf-8')
    encrypted_response = node_b.send_response(response_data)
    if encrypted_response is None:
        print("Failed to send response.")
        return

    # Node A decrypts the response
    decrypted_response, response_header, message_type = node_a.receive_data(encrypted_response)
    if decrypted_response is None:
        print("Failed to decrypt response.")
        return
    print("Message Type:", message_type)
    print("Response Header:", response_header)
    print("Decrypted response:", decrypted_response.decode(response_header['encoding']))

if __name__ == "__main__":
    main()