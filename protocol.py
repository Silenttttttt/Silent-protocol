from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
import os
import json
import struct
import time
from hamming import encode_binary_string, decode_binary_string

HANDSHAKE_FLAG = b'HSK'  # Special flag to indicate a handshake request
DATA_FLAG = b'DTA'       # Special flag to indicate a data message
RESPONSE_FLAG = b'RTN'   # Special flag to indicate a response message

def binary_string_to_bytes(binary_str: str) -> bytes:
    binary_str = binary_str.replace(" ", "")
    byte_data = int(binary_str, 2)
    return byte_data.to_bytes((len(binary_str) + 7) // 8, byteorder='big')

def bytes_to_binary_string(byte_data: bytes) -> str:
    return ''.join(format(byte, '08b') for byte in byte_data)


class SilentProtocol:
    DEFAULT_VALIDITY_PERIOD = 3600  # Default validity period of 1 hour

    def __init__(self):
        self.sessions = {}  # Store session information

    def generate_key_pair(self):
        try:
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            return private_key, public_key
        except Exception as e:
            print(f"Key pair generation failed: {e}")
            return None, None

    def exchange_keys(self, private_key, peer_public_key_bytes):
        try:
            if not peer_public_key_bytes:
                print("Peer public key bytes are None.")
                return None
            if not private_key:
                print("Private key is None.")
                return None

            peer_public_key = serialization.load_der_public_key(peer_public_key_bytes)
            shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
            return shared_secret
        except Exception as e:
            print(f"Key exchange failed: {e}")
            return None

    def derive_session_key(self, shared_secret):
        if shared_secret is None:
            print("Shared secret is None, cannot derive session key.")
            return None
        try:
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_secret)
            return session_key
        except Exception as e:
            print(f"Session key derivation failed: {e}")
            return None

    def initialize_session(self, session_id, session_key, valid_until, private_key):
        self.sessions[session_id] = {
            'session_key': session_key,
            'valid_until': valid_until,
            'private_key': private_key
        }

    def perform_handshake_request(self):
        private_key, public_key = self.generate_key_pair()
        if not private_key or not public_key:
            print("Failed to generate key pair for handshake.")
            return None, None

        # Send public key with handshake flag in DER format
        return public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ) + HANDSHAKE_FLAG, private_key


    def perform_handshake_response(self, handshake_request):
        # Convert binary string to bytes if necessary
        if isinstance(handshake_request, str):
            handshake_request = binary_string_to_bytes(handshake_request)

        if not handshake_request.endswith(HANDSHAKE_FLAG):
            print("Invalid handshake request.")
            return None, None, None

        peer_public_key_bytes = handshake_request[:-len(HANDSHAKE_FLAG)]
        private_key, public_key = self.generate_key_pair()
        shared_secret = self.exchange_keys(private_key, peer_public_key_bytes)
        if not shared_secret:
            print("Failed to exchange keys during handshake.")
            return None, None, None

        session_key = self.derive_session_key(shared_secret)
        if not session_key:
            print("Failed to derive session key during handshake.")
            return None, None, None

        session_id = os.urandom(16)
        valid_until = time.time() + self.DEFAULT_VALIDITY_PERIOD
        self.initialize_session(session_id, session_key, valid_until, private_key)

        # Prepare encrypted data with session ID and validity timestamp
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)
        handshake_data = json.dumps({
            'session_id': session_id.hex(),
            'valid_until': valid_until
        }).encode('utf-8')
        encrypted_handshake_data = aesgcm.encrypt(nonce, handshake_data, None)

        # Send back public key, HSK flag, and encrypted handshake data
        response = (
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ) +
            HANDSHAKE_FLAG +
            nonce +
            encrypted_handshake_data
        )
        return response, private_key, session_id

    def complete_handshake(self, response, private_key):
        # Convert binary string to bytes if necessary
        if isinstance(response, str):
            response = binary_string_to_bytes(response)

        # Find the position of the HSK flag to separate the public key and the encrypted data
        hsk_index = response.find(HANDSHAKE_FLAG)
        if hsk_index == -1:
            print("HSK flag not found in response.")
            return None

        # Extract the public key bytes and the encrypted handshake data
        peer_public_key_bytes = response[:hsk_index]
        encrypted_data_start = hsk_index + len(HANDSHAKE_FLAG)
        nonce = response[encrypted_data_start:encrypted_data_start + 12]
        encrypted_handshake_data = response[encrypted_data_start + 12:]

        shared_secret = self.exchange_keys(private_key, peer_public_key_bytes)
        session_key = self.derive_session_key(shared_secret)
        if not session_key:
            print("Failed to derive session key during handshake completion.")
            return None

        # Decrypt the handshake data
        aesgcm = AESGCM(session_key)
        handshake_data_json = aesgcm.decrypt(nonce, encrypted_handshake_data, None)
        handshake_data = json.loads(handshake_data_json.decode('utf-8'))

        session_id = bytes.fromhex(handshake_data['session_id'])
        valid_until = handshake_data['valid_until']

        self.initialize_session(session_id, session_key, valid_until, private_key)
        return session_id

    def create_request(self, session_id, request_data) -> str:
        header = {
            "timestamp": int(time.time()),
            "encoding": 'utf-8',
            "content_type": 'application/json'
        }
        return self.encrypt_data(session_id, request_data, header, flag=DATA_FLAG)

    def create_response(self, session_id, response_data, response_code=200) -> str:
        header = {
            "timestamp": int(time.time()),
            "encoding": 'utf-8',
            "content_type": 'application/json',
            "response_code": response_code
        }
        return self.encrypt_data(session_id, response_data, header, flag=RESPONSE_FLAG)

    def encrypt_data(self, session_id, data, header, flag) -> str:
        try:
            # Validate header
            if not all(k in header for k in ("timestamp", "encoding", "content_type")):
                print("Header must include 'timestamp', 'encoding', and 'content_type'.")
                return None

            session_info = self.sessions.get(session_id)
            if not session_info:
                print("Session not found.")
                return None

            if time.time() > session_info['valid_until']:
                print("Session expired, please perform a new handshake.")
                return None

            session_key = session_info['session_key']
            aesgcm = AESGCM(session_key)
            nonce = os.urandom(12)

            # Encrypt header and data
            header_json = json.dumps(header).encode('utf-8')
            encrypted_header = aesgcm.encrypt(nonce, header_json, None)
            encrypted_data = aesgcm.encrypt(nonce, data, None)

            encrypted_header_length = struct.pack('!I', len(encrypted_header))
            packet = session_id + flag + nonce + encrypted_header_length + encrypted_header + encrypted_data

            # Convert packet to binary string
            packet_binary_str = ''.join(format(byte, '08b') for byte in packet)

            # Encode the entire packet using Hamming code
            encoded_packet = encode_binary_string(packet_binary_str)

            # Return the encoded binary string
            return encoded_packet

        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Encryption failed: {e}")
            return None


    def decrypt_data(self, packet):
        try:
            # Check if packet is a binary string or bytes and convert accordingly
            if isinstance(packet, bytes):
                encoded_packet = bytes_to_binary_string(packet)
            elif isinstance(packet, str):
                encoded_packet = packet
            else:
                print("Invalid packet type. Must be bytes or binary string.")
                return None, None, None

            # Decode the entire packet using Hamming code
            decoded_packet_binary_str = decode_binary_string(encoded_packet)

            # Convert binary string back to bytes
            decoded_packet = bytes(int(decoded_packet_binary_str[i:i+8], 2) for i in range(0, len(decoded_packet_binary_str), 8))

            session_id = decoded_packet[:16]
            flag = decoded_packet[16:19]
            if flag not in [DATA_FLAG, RESPONSE_FLAG]:
                print("Invalid data packet.")
                return None, None, None

            decoded_packet = decoded_packet[19:]  # Skip the flag
            session_info = self.sessions.get(session_id)
            if not session_info:
                print("Session not found.")
                return None, None, None

            if time.time() > session_info['valid_until']:
                print("Session expired, please perform a new handshake.")
                return None, None, None

            session_key = session_info['session_key']
            nonce = decoded_packet[:12]
            encrypted_header_length = struct.unpack('!I', decoded_packet[12:16])[0]
            encrypted_header = decoded_packet[16:16+encrypted_header_length]
            ciphertext = decoded_packet[16+encrypted_header_length:]

            aesgcm = AESGCM(session_key)
            header_json = aesgcm.decrypt(nonce, encrypted_header, None)
            header_dict = json.loads(header_json.decode('utf-8'))

            # Validate header fields
            if not all(k in header_dict for k in ("timestamp", "encoding", "content_type")):
                print("Decrypted header must include 'timestamp', 'encoding', and 'content_type'.")
                return None, None, None

            # Check if the request is older than 1 minute
            if time.time() - header_dict["timestamp"] > 60:
                print("Request is older than 1 minute.")
                return None, None, None

            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            return plaintext, header_dict, flag
        except InvalidSignature:
            print("Decryption failed: Integrity check failed.")
            return None, None, None
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Decryption failed: {e}")
            return None, None, None

# Example usage
def main():
    print("=== Using SilentProtocol Directly ===")
    # Initialize protocol objects for Node A and Node B
    protocol_a = SilentProtocol()
    protocol_b = SilentProtocol()

    # Node A initiates a handshake request to Node B
    handshake_request, node_a_private_key = protocol_a.perform_handshake_request()

    if not handshake_request:
        print("Failed to perform handshake request.")
        return

    # Node B responds to the handshake request
    response, node_b_private_key = protocol_b.perform_handshake_response(handshake_request)

    if not response:
        print("Failed to perform handshake response.")
        return

    # Node A completes the handshake by processing the response
    session_id = protocol_a.complete_handshake(response, node_a_private_key)

    if not session_id:
        print("Failed to complete handshake.")
        return

    # Node A sends a request to Node B
    request_data = json.dumps({"action": "get_data"}).encode('utf-8')
    encrypted_request = protocol_a.create_request(session_id, request_data)
    if encrypted_request is None:
        print("Failed to send request.")
        return

#    print("Encrypted request:", encrypted_request)

    # Node B decrypts the request and sends a response
    decrypted_request, request_header, message_type = protocol_b.decrypt_data(encrypted_request)
    if decrypted_request is None:
        print("Failed to decrypt request.")
        return

    print("Decrypted request:", decrypted_request.decode(request_header['encoding']))
    print("Request Header:", request_header)

    response_data = json.dumps({"data": "Here is your data"}).encode('utf-8')
    encrypted_response = protocol_b.create_response(session_id, response_data)
    if encrypted_response is None:
        print("Failed to send response.")
        return

  #  print("Encrypted response:", encrypted_response)

    # Node A decrypts the response
    decrypted_response, response_header, message_type = protocol_a.decrypt_data(encrypted_response)
    if decrypted_response is None:
        print("Failed to decrypt response.")
        return

    
    print("Response Header:", response_header)
    print("Decrypted response:", decrypted_response.decode(response_header['encoding']))

if __name__ == "__main__":
    main()