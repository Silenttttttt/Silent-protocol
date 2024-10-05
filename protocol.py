from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
import os
import json
import struct
import time
import zlib
import hashlib
#from hamming import encode_binary_string, decode_binary_string, binary_string_to_bytes, bytes_to_binary_string
from c_hamming import encode_bytes_with_hamming, decode_bytes_with_hamming

HANDSHAKE_FLAG = b'HSK'  # Special flag to indicate a handshake request
HANDSHAKE_RESPONSE_FLAG = b'HSR'  # Special flag to indicate a handshake response
DATA_FLAG = b'DTA'       # Special flag to indicate a data message
RESPONSE_FLAG = b'RTN'   # Special flag to indicate a response message
HPW_FLAG = b'HPW'        # Special flag to indicate a handshake proof of work request
HPW_RESPONSE_FLAG = b'HPR'  # Special flag to indicate a handshake proof of work response



class SilentProtocol:
    DEFAULT_VALIDITY_PERIOD = 3600  # Default validity period of 1 hour
    POW_DIFFICULTY = 4  # Number of leading zeros required in the hash
    NONCE_VALIDITY_PERIOD = 60  # Nonce validity period of 1 minute
    DIFFICULTY_LIMIT = 10  # Difficulty limit
    MAX_PROOF_LENGTH = 64  # Example limit for proof length
    POW_TIMEOUT = 20  # Timeout for proof of work in seconds
    MAX_PACKET_SIZE = 8192 

    PUBLIC_KEY_SIZE = 91  # Size of the public key in bytes

    def __init__(self):
        self.sessions = {}  # Store session information
        self.nonce_store = {}  # Store handshake proof of work nonces and their metadata

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

    def perform_handshake_request(self) -> tuple[bytes, bytes]:
        private_key, public_key = self.generate_key_pair()
        if not private_key or not public_key:
            print("Failed to generate key pair for handshake.")
            return None, None
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Prepare the PoW request with public key, packet size limit, and HPW flag
        pow_request = (
            public_key_bytes +
            struct.pack('!I', self.MAX_PACKET_SIZE) +
            HPW_FLAG
        )
        pow_request_encoded = encode_bytes_with_hamming(pow_request)
        return pow_request_encoded, private_key


    def perform_pow_challenge(self, pow_request) -> tuple[bytes, bytes]:
        pow_request = decode_bytes_with_hamming(pow_request)
        
        # Extract public key and packet size limit based on known lengths
    
        hpw_index = pow_request.find(HPW_FLAG)
        
        if hpw_index == -1:
            print("Invalid PoW request.")
            return None, None

        # Extract public key and packet size limit
        public_key_bytes = pow_request[:self.PUBLIC_KEY_SIZE]
        packet_size_limit = struct.unpack('!I', pow_request[self.PUBLIC_KEY_SIZE:hpw_index])[0]
        
        # Generate nonce and difficulty
        nonce = os.urandom(16)
        difficulty = self.POW_DIFFICULTY

        # Store the nonce and its metadata
        self.nonce_store[public_key_bytes] = {
            'nonce': nonce,
            'difficulty': difficulty,
            'timestamp': time.time()
        }

        # Prepare the PoW challenge with the new response flag
        pow_challenge = nonce + HPW_RESPONSE_FLAG + difficulty.to_bytes(1, 'big')
        pow_challenge_encoded = encode_bytes_with_hamming(pow_challenge)
        return pow_challenge_encoded, public_key_bytes


    def verify_pow(self, nonce, proof, difficulty) -> bool:
        hash_result = hashlib.sha256(nonce + proof).hexdigest()
        return hash_result.startswith('0' * difficulty)

    def complete_handshake_request(self, pow_challenge, private_key) -> bytes:

        pow_challenge = decode_bytes_with_hamming(pow_challenge)
        # Check if the challenge contains the correct structure
        hpw_index = pow_challenge.find(HPW_RESPONSE_FLAG)
        if hpw_index == -1:
            print("Invalid PoW challenge structure.")
            return None

        # Extract the nonce and difficulty from the challenge
        nonce = pow_challenge[:hpw_index]
        difficulty = pow_challenge[hpw_index + len(HPW_RESPONSE_FLAG)]


        if difficulty > self.DIFFICULTY_LIMIT:
            raise Exception("Difficulty too high.")
        

        # Perform proof of work with timeout
        proof = 0
        start_time = time.time()
        while True:
            if time.time() - start_time > self.POW_TIMEOUT:
                print("Proof of work timed out.")
                return None

            proof_bytes = proof.to_bytes((proof.bit_length() + 7) // 8, byteorder='big')
            if len(proof_bytes) <= self.MAX_PROOF_LENGTH and self.verify_pow(nonce, proof_bytes, difficulty):
                break
            proof += 1



        # Prepare the handshake request with the proof of work solution
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        handshake_request = public_key_bytes + HANDSHAKE_FLAG + proof_bytes
        handshake_request_encoded = encode_bytes_with_hamming(handshake_request)
        return handshake_request_encoded

    def perform_handshake_response(self, handshake_request):

        handshake_request = decode_bytes_with_hamming(handshake_request)

        # Find the position of the HANDSHAKE_FLAG to separate the public key and the proof
        hsk_index = handshake_request.find(HANDSHAKE_FLAG)
        if hsk_index == -1:
            print("Invalid handshake request.")
            return None, None, None

        # Extract the public key bytes and the proof of work solution
        peer_public_key_bytes = handshake_request[:hsk_index]
        proof_bytes = handshake_request[hsk_index + len(HANDSHAKE_FLAG):]

        # Check proof length
        if len(proof_bytes) > self.MAX_PROOF_LENGTH:
            print("Proof of work solution is too long, possible attack.")
            return None, None, None

        # Retrieve the correct nonce and difficulty
        nonce_data = self.nonce_store.get(peer_public_key_bytes)
        if not nonce_data:
            print("Nonce not found or expired.")
            return None, None, None

        # Check nonce validity
        if time.time() - nonce_data['timestamp'] > self.NONCE_VALIDITY_PERIOD:
            print("Nonce expired.")
            del self.nonce_store[peer_public_key_bytes]
            return None, None, None

        nonce = nonce_data['nonce']
        difficulty = nonce_data['difficulty']

        # Verify PoW
        if not self.verify_pow(nonce, proof_bytes, difficulty):
            print("Invalid PoW solution.")
            return None, None, None

        # Proceed with key generation and session initialization
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

        # Prepare the response
        response = (
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ) +
            HANDSHAKE_RESPONSE_FLAG +  # Use HSR instead of HSK
            nonce +
            encrypted_handshake_data
        )

        response_encoded = encode_bytes_with_hamming(response)

        return response_encoded, private_key, session_id

    def complete_handshake(self, response, private_key) -> bytes:
        if not response:
            print("Response is empty.")
            return None

        response = decode_bytes_with_hamming(response)

        # Find the position of the HSR flag to separate the public key and the encrypted data
        hsr_index = response.find(HANDSHAKE_RESPONSE_FLAG)
        if hsr_index == -1:
            print("HSR flag not found in response.")
            return None

        # Extract the public key bytes and the encrypted handshake data
        peer_public_key_bytes = response[:hsr_index]
        encrypted_data_start = hsr_index + len(HANDSHAKE_RESPONSE_FLAG)
        nonce = response[encrypted_data_start:encrypted_data_start + 12]
        encrypted_handshake_data = response[encrypted_data_start + 12:]

        #derive shared secret and session key
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

    def create_request(self, session_id, request_data) -> bytes:
        header = {
            "timestamp": int(time.time()),
            "encoding": 'utf-8',
            "content_type": 'application/json'
        }
        return self.encrypt_data(session_id, request_data, header, flag=DATA_FLAG)

    def create_response(self, session_id, response_data, response_code=200) -> bytes:
        header = {
            "timestamp": int(time.time()),
            "encoding": 'utf-8',
            "content_type": 'application/json',
            "response_code": response_code
        }
        return self.encrypt_data(session_id, response_data, header, flag=RESPONSE_FLAG)

    def encrypt_data(self, session_id, data, header, flag) -> bytes:
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

            # Compress, then encrypt header and data
            header_json = zlib.compress(json.dumps(header).encode('utf-8'))
            data = zlib.compress(data)

            encrypted_header = aesgcm.encrypt(nonce, header_json, None)
            encrypted_data = aesgcm.encrypt(nonce, data, None)

            encrypted_header_length = struct.pack('!I', len(encrypted_header))
            packet = session_id + flag + nonce + encrypted_header_length + encrypted_header + encrypted_data

            # Encode the entire packet using Hamming code
            encoded_packet = encode_bytes_with_hamming(packet)

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
            if not isinstance(packet, bytes):
                print("Invalid packet type. Must be bytes or binary string.")
                return None, None, None
            
            # Decode the entire packet using Hamming code
            decoded_packet = decode_bytes_with_hamming(packet)

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
            header_json = zlib.decompress(aesgcm.decrypt(nonce, encrypted_header, None))
            header_dict = json.loads(header_json.decode('utf-8'))

            # Validate header fields
            if not all(k in header_dict for k in ("timestamp", "encoding", "content_type")):
                print("Decrypted header must include 'timestamp', 'encoding', and 'content_type'.")
                return None, None, None

            # Check if the request is older than 1 minute
            if time.time() - header_dict["timestamp"] > 60:
                print("Request is older than 1 minute.")
                return None, None, None

            plaintext = zlib.decompress(aesgcm.decrypt(nonce, ciphertext, None))

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
    print("=== Using SilentProtocol with PoW ===")
    # Initialize protocol objects for Node A and Node B
    protocol_a = SilentProtocol()
    protocol_b = SilentProtocol()

    # Node A initiates a handshake request to Node B
    pow_request, node_a_private_key = protocol_a.perform_handshake_request()

    if not pow_request:
        print("Failed to perform handshake request.")
        return

    # Node B responds with a PoW challenge
    pow_challenge, peer_public_key_bytes = protocol_b.perform_pow_challenge(pow_request)

    if not pow_challenge:
        print("Failed to perform PoW challenge.")
        return

    # Node A completes the handshake request with PoW solution
    handshake_request = protocol_a.complete_handshake_request(pow_challenge, node_a_private_key)

    if not handshake_request:
        print("Failed to complete handshake request.")
        return

    # Node B processes the handshake request and responds
    response, node_b_private_key, session_id_b = protocol_b.perform_handshake_response(handshake_request)

    if not response:
        print("Failed to perform handshake response.")
        return

    # Node A completes the handshake by processing the response
    session_id = protocol_a.complete_handshake(response, node_a_private_key)

    if not session_id:
        print("Failed to complete handshake.")
        return

    print("Handshake completed successfully. Session ID:", session_id.hex())


    # Node A sends a request to Node B
    request_data = json.dumps({"action": "Hello world"}).encode('utf-8')
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
    encrypted_response = protocol_b.create_response(session_id_b, response_data)
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

    assert decrypted_response.decode(response_header['encoding']) == response_data.decode('utf-8')

if __name__ == "__main__":
    main()