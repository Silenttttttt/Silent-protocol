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
import threading
from collections import defaultdict
from queue import Queue, Empty
import traceback
#from hamming import encode_binary_string, decode_binary_string, binary_string_to_bytes, bytes_to_binary_string
from c_hamming import encode_bytes_with_hamming, decode_bytes_with_hamming


class SilentProtocol:


    HANDSHAKE_FLAG = b'HSK'  # Special flag to indicate a handshake request
    HANDSHAKE_RESPONSE_FLAG = b'HSR'  # Special flag to indicate a handshake response
    DATA_FLAG = b'DTA'       # Special flag to indicate a data message
    RESPONSE_FLAG = b'RTN'   # Special flag to indicate a response message
    HPW_FLAG = b'HPW'        # Special flag to indicate a handshake proof of work request
    HPW_RESPONSE_FLAG = b'HPR'  # Special flag to indicate a handshake proof of work response
    DST_FLAG = b'DST' # Special flag to indicate a data stream message
    NST_FLAG = b'NST' # Special flag to indicate a NACK not acknowledged stream message, and the other side will re-send the specified segments
    EST_FLAG = b'EST' # Special flag to indicate that the sender should stop sending more stream messages
    CST_FLAG = b'CST' # Special flag to indicate that the receiver is still active and wants to continue receiving stream messages
    STR_FLAG = b'SST' # Special flag to indicate a successful stream message
    FST_FLAG = b'FST' # Special flag to indicate a failed stream message

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
        self.processed_uuids = {}  # Store processed packet UUIDs with timestamps
        self.stream_manager = StreamManager(self)

    def cleanup_uuids(self):
        current_time = time.time()
        # Remove UUIDs older than 1 minute
        self.processed_uuids = {uuid: ts for uuid, ts in self.processed_uuids.items() if current_time - ts < 60}

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

    def initialize_session(self, session_id, session_key, valid_until, private_key, max_packet_size_a, max_packet_size_b):
        self.sessions[session_id] = {
            'session_key': session_key,
            'valid_until': valid_until,
            'private_key': private_key,
            'max_packet_size': min(max_packet_size_a, max_packet_size_b)
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
        
        # Prepare the PoW request with public key and HPW flag
        pow_request = (
            public_key_bytes +
            self.HPW_FLAG
        )
        pow_request_encoded = encode_bytes_with_hamming(pow_request)
        return pow_request_encoded, private_key
    
    def perform_pow_challenge(self, pow_request) -> tuple[bytes, bytes]:
        pow_request = decode_bytes_with_hamming(pow_request)
        
        # Extract public key based on known length
        hpw_index = pow_request.find(self.HPW_FLAG)
        
        if hpw_index == -1:
            print("Invalid PoW request.")
            return None, None

        # Extract public key
        public_key_bytes = pow_request[:self.PUBLIC_KEY_SIZE]
        # Generate nonce and difficulty
        nonce = os.urandom(16)
        difficulty = self.POW_DIFFICULTY

        # Store the nonce and its metadata
        self.nonce_store[public_key_bytes] = {
            'nonce': nonce,
            'difficulty': difficulty,
            'timestamp': time.time()
        }

        # Prepare the PoW challenge with the public key and response flag
        pow_challenge = public_key_bytes + nonce + self.HPW_RESPONSE_FLAG + difficulty.to_bytes(1, 'big')
        pow_challenge_encoded = encode_bytes_with_hamming(pow_challenge)
        return pow_challenge_encoded, public_key_bytes



    def verify_pow(self, nonce, proof, difficulty) -> bool:
        hash_result = hashlib.sha256(nonce + proof).hexdigest()
        return hash_result.startswith('0' * difficulty)

    def complete_handshake_request(self, pow_challenge, private_key) -> bytes:
        pow_challenge = decode_bytes_with_hamming(pow_challenge)
        
        # Extract the public key, nonce, and difficulty from the challenge
        public_key_bytes_received = pow_challenge[:self.PUBLIC_KEY_SIZE]
        
        hpw_index = pow_challenge.find(self.HPW_RESPONSE_FLAG, self.PUBLIC_KEY_SIZE)
        if hpw_index == -1:
            print("Invalid PoW challenge structure.")
            return None

        nonce = pow_challenge[self.PUBLIC_KEY_SIZE:hpw_index]
        difficulty = pow_challenge[hpw_index + len(self.HPW_RESPONSE_FLAG)]

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

        # Prepare the handshake request with the proof of work solution and max packet size
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        handshake_request = (
            public_key_bytes +
            struct.pack('!I', self.MAX_PACKET_SIZE) +  # Include max packet size
            self.HANDSHAKE_FLAG +
            proof_bytes
        )
        handshake_request_encoded = encode_bytes_with_hamming(handshake_request)
        return handshake_request_encoded

    def perform_handshake_response(self, handshake_request):

        handshake_request = decode_bytes_with_hamming(handshake_request)

        # Find the position of the self.HANDSHAKE_FLAG to separate the public key, max packet size, and the proof
        hsk_index = handshake_request.find(self.HANDSHAKE_FLAG)
        if hsk_index == -1:
            print("Invalid handshake request.")
            return None, None, None

        # Extract the public key bytes, max packet size, and the proof of work solution
        peer_public_key_bytes = handshake_request[:self.PUBLIC_KEY_SIZE]
        max_packet_size = struct.unpack('!I', handshake_request[self.PUBLIC_KEY_SIZE:hsk_index])[0]
        proof_bytes = handshake_request[hsk_index + len(self.HANDSHAKE_FLAG):]

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
        self.initialize_session(session_id, session_key, valid_until, private_key, self.MAX_PACKET_SIZE, max_packet_size)

        # Prepare encrypted data with session ID and validity timestamp
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)
        handshake_data = json.dumps({
            'session_id': session_id.hex(),
            'valid_until': valid_until,
            'max_packet_size': self.MAX_PACKET_SIZE  # Include your own max packet size in the response, the least of the two will be the one used
        }).encode('utf-8')
        encrypted_handshake_data = aesgcm.encrypt(nonce, handshake_data, None)




        # Prepare the response
        response = (
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ) +
            self.HANDSHAKE_RESPONSE_FLAG +  # Use HSR instead of HSK
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
        hsr_index = response.find(self.HANDSHAKE_RESPONSE_FLAG)
        if hsr_index == -1:
            print("HSR flag not found in response.")
            return None

        # Extract the public key bytes and the encrypted handshake data
        peer_public_key_bytes = response[:hsr_index]
        encrypted_data_start = hsr_index + len(self.HANDSHAKE_RESPONSE_FLAG)
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
        max_packet_size = handshake_data['max_packet_size']

        self.initialize_session(session_id, session_key, valid_until, private_key, self.MAX_PACKET_SIZE, max_packet_size)
        return session_id

    def create_request(self, session_id, request_data) -> bytes:
        header = {
            "timestamp": int(time.time()),
            "encoding": 'utf-8',
            "content_type": 'application/json'
        }
        encrypted_packet = self.encrypt_data(session_id, request_data, header, flag=self.DATA_FLAG)
        if encrypted_packet is None:
            raise Exception("Failed to create request.")
           

        # Derive packet UUID by hashing the encrypted packet
        packet_uuid = hashlib.sha256(encrypted_packet).hexdigest()

        # Encode the entire packet using Hamming code
        encoded_packet = encode_bytes_with_hamming(encrypted_packet)

        return encoded_packet, packet_uuid

    def create_response(self, session_id, response_data, original_packet_uuid, response_code=200) -> bytes:
        header = {
            "timestamp": int(time.time()),
            "encoding": 'utf-8',
            "content_type": 'application/json',
            "response_code": response_code,
            "packet_uuid": original_packet_uuid  # Include original packet UUID
        }
        encrypted_packet = self.encrypt_data(session_id, response_data, header, flag=self.RESPONSE_FLAG)
        if encrypted_packet is None:
            raise Exception("Failed to create response.")

        # Encode the entire packet using Hamming code
        encoded_packet = encode_bytes_with_hamming(encrypted_packet)

        return encoded_packet

    def encrypt_data(self, session_id, data, header, flag) -> bytes:
        try:
            # Validate header
            if not all(k in header for k in ("timestamp", "encoding", "content_type")):
                print("Header must include 'timestamp', 'encoding', and 'content_type'.")
                return None

            session_info = self.sessions.get(session_id)
            if not session_info:
                print("Session not found in encrypt data.")
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

            return packet

        except Exception as e:
            
            traceback.print_exc()
            print(f"Encryption failed: {e}")
            return None
    def decrypt_data_packet(self, packet: bytes) -> tuple[bytes, dict, str, str]:
        try:
            # Decode the entire packet using Hamming code
            decoded_packet = decode_bytes_with_hamming(packet)

            # Derive packet UUID by hashing the decoded packet
            packet_uuid = hashlib.sha256(decoded_packet).hexdigest()

            session_id = decoded_packet[:16]
            flag = decoded_packet[16:19]
            if flag != self.DATA_FLAG:
                print("Invalid data packet.")
                return None, None, None, None

            decoded_packet = decoded_packet[19:]  # Skip the flag
            session_info = self.sessions.get(session_id)
            if not session_info:
                print("Session not found decrypt data packet.")
                return None, None, None, None

            if time.time() > session_info['valid_until']:
                print("Session expired, please perform a new handshake.")
                return None, None, None, None

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
                return None, None, None, None

            # Check if the request is older than 1 minute
            if time.time() - header_dict["timestamp"] > 60:
                print("Request is older than 1 minute.")
                return None, None, None, None

            # Check for replay attack
            if packet_uuid in self.processed_uuids:
                print("Replay attack detected: Packet UUID already processed.")
                return None, None, None, None

            # Process the packet
            if ciphertext:
                plaintext = zlib.decompress(aesgcm.decrypt(nonce, ciphertext, None))
            else:
                plaintext = b''

            # Store the UUID with the current timestamp
            self.processed_uuids[packet_uuid] = time.time()

            # Cleanup old UUIDs
            self.cleanup_uuids()

            return plaintext, header_dict, flag, packet_uuid
        except InvalidSignature:
            print("Decryption data packet failed: Integrity check failed.")
            return None, None, None, None
        except Exception as e:
            
            traceback.print_exc()
            print(f"Decryption data packet failed: {e}")
            return None, None, None, None

    def decrypt_response_packet(self, packet: bytes) -> tuple[bytes, dict, str, str]:
        try:
            # Decode the entire packet using Hamming code
            decoded_packet = decode_bytes_with_hamming(packet)

            session_id = decoded_packet[:16]
            flag = decoded_packet[16:19]
            if flag != self.RESPONSE_FLAG:
                print("Invalid response packet.")
                return None, None, None, None

            decoded_packet = decoded_packet[19:]  # Skip the flag
            session_info = self.sessions.get(session_id)
            if not session_info:
                print("Session not found decrypt response packet.")
                return None, None, None, None

            if time.time() > session_info['valid_until']:
                print("Session expired, please perform a new handshake.")
                return None, None, None, None

            session_key = session_info['session_key']
            nonce = decoded_packet[:12]
            encrypted_header_length = struct.unpack('!I', decoded_packet[12:16])[0]
            encrypted_header = decoded_packet[16:16+encrypted_header_length]
            ciphertext = decoded_packet[16+encrypted_header_length:]

            aesgcm = AESGCM(session_key)
            header_json = zlib.decompress(aesgcm.decrypt(nonce, encrypted_header, None))
            header_dict = json.loads(header_json.decode('utf-8'))

            # Validate header fields
            if not all(k in header_dict for k in ("timestamp", "encoding", "content_type", "packet_uuid")):
                print("Decrypted header must include 'timestamp', 'encoding', 'content_type', and 'packet_uuid'.")
                return None, None, None, None

            # Check if the request is older than 1 minute
            if time.time() - header_dict["timestamp"] > 60:
                print("Request is older than 1 minute.")
                return None, None, None, None

            # Derive packet UUID from the encrypted header
            packet_uuid = header_dict["packet_uuid"]

            # Check for replay attack
            if packet_uuid in self.processed_uuids:
                print("Replay attack detected: Packet UUID already processed.")
                return None, None, None, None

            if ciphertext:
                plaintext = zlib.decompress(aesgcm.decrypt(nonce, ciphertext, None))
            else:
                plaintext = b''

            # Store the UUID with the current timestamp
            self.processed_uuids[packet_uuid] = time.time()

            # Cleanup old UUIDs
            self.cleanup_uuids()

            return plaintext, header_dict, flag, packet_uuid
        except InvalidSignature:
            print("Decryption response packet failed: Integrity check failed.")
            return None, None, None, None
        except Exception as e:
            
            traceback.print_exc()
            print(f"Decryption response packet failed: {e}")
            return None, None, None, None


    def create_stream_packet(self, session_id, sequence_number, flags, data, stream_id=None, total_segments=None) -> bytes:
        # If stream_id is None, derive it from the first packet's content
        if stream_id is None:
            stream_id = hashlib.sha256(data).digest()  # Use the full SHA-256 hash

        # Validate flags and total_segments
        if flags == 2 and total_segments is not None:
            raise ValueError("Total segments should not be present for a continuous stream (flag 2).")

        # Create a JSON header
        header = {
            "stream_id": stream_id.hex(),
            "sequence_number": sequence_number,
            "flags": flags,
            "timestamp": int(time.time())
        }
        if total_segments is not None:
            header["total_segments"] = total_segments
        
        # Encrypt the data with the header
        encrypted_packet = self.encrypt_stream_data(session_id, data, header)
        if encrypted_packet is None:
            raise Exception("Failed to create stream packet.")
        
        # Encode the entire packet using Hamming code
        encoded_packet = encode_bytes_with_hamming(encrypted_packet)
        
        # Store packet info in the session under the stream ID
        session_info = self.sessions.get(session_id)
        if session_info:
            streams = session_info.setdefault('streams', {})
            stream_data = streams.setdefault(stream_id, {})
            stream_data[sequence_number] = {
                'data': data,
                'header': header
            }
        
        return encoded_packet, stream_id, header


    def encrypt_stream_data(self, session_id, data, header) -> bytes:
        try:
            session_info = self.sessions.get(session_id)
            if not session_info:
                print("Session not found in stream encryption.")
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
            packet = session_id + self.DST_FLAG + nonce + encrypted_header_length + encrypted_header + encrypted_data

            return packet

        except Exception as e:
            print(f"Encryption failed: {e}")
            return None

    def decrypt_stream_packet(self, packet: bytes) -> tuple[bytes, dict, str]:
        try:
            # Decode the entire packet using Hamming code
            decoded_packet = decode_bytes_with_hamming(packet)

            session_id = decoded_packet[:16]
            flag = decoded_packet[16:19]
            if flag not in [self.DST_FLAG, self.EST_FLAG, self.CST_FLAG]:
                print("Invalid stream packet.")
                return None, None, None

            decoded_packet = decoded_packet[19:]  # Skip the flag
            session_info = self.sessions.get(session_id)
            if not session_info:
                print("Session decrypt not found in stream decrypt packet.")
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
            
            # Validate header fields based on the flag
            required_keys = ["stream_id", "flags", "timestamp"]
            if flag in [self.DST_FLAG]:  # Only data packets require sequence numbers
                required_keys.append("sequence_number")
            
            if not all(k in header_dict for k in required_keys):
                print("Decrypted header must include required fields.")
                return None, None, None

            # Process the packet
            if ciphertext:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            else:
                plaintext = b''

            # Store received packet info in the session under the stream ID
            streams = session_info.setdefault('streams', {})
            stream_id = bytes.fromhex(header_dict['stream_id'])
            stream_data = streams.setdefault(stream_id, {})
            if "sequence_number" in header_dict:
                stream_data[header_dict['sequence_number']] = {
                    'data': plaintext,
                    'header': header_dict
                }

            if flag == self.CST_FLAG:
                self.received_cst.set()

            return plaintext, header_dict, flag
        except Exception as e:
            traceback.print_exc()
            print(f"Decryption failed stream packet: {e}")
            return None, None, None

    def finalize_stream(self, session_id, stream_id):
        session_info = self.sessions.get(session_id)
        if not session_info:
            print("Session not found in finalize stream.")
            return None

        streams = session_info.get('streams', {})
        stream_data = streams.get(stream_id, {})
        if not stream_data:
            print("No stream data found for this stream ID.")
            return None

        # Check for missing packets
        total_segments = next(iter(stream_data.values()))['header'].get('total_segments')
        if total_segments is not None:
            missing_packets = [i for i in range(1, total_segments + 1) if i not in stream_data]
            if missing_packets:
                nack_packet = self.create_nack_stream_packet(session_id, stream_id, missing_packets)
                print("NACK packet created for missing packets:", missing_packets)
                return nack_packet

        # Sort packets by sequence number and join data
        sorted_data = [stream_data[seq]['data'] for seq in sorted(stream_data)]
        complete_data = b''.join(sorted_data)

        # Clear stream data from session
        del streams[stream_id]

        return complete_data

    def create_nack_stream_packet(self, session_id, stream_id, missing_packets) -> bytes:
        # Create a JSON header for the NACK packet
        header = {
            "stream_id": stream_id.hex(),
            "missing_packets": missing_packets,
            "timestamp": int(time.time())
        }
        
        # Encrypt the header with no data
        encrypted_packet = self.encrypt_nack_data(session_id, header)
        if encrypted_packet is None:
            raise Exception("Failed to create NACK stream packet.")
        
        # Encode the entire packet using Hamming code
        encoded_packet = encode_bytes_with_hamming(encrypted_packet)
        
        return encoded_packet

    def encrypt_nack_data(self, session_id, header) -> bytes:
        try:
            session_info = self.sessions.get(session_id)
            if not session_info:
                print("Session not found in encrypt nack data.")
                return None

            session_key = session_info['session_key']
            aesgcm = AESGCM(session_key)
            nonce = os.urandom(12)

            # Encrypt header
            header_json = json.dumps(header).encode('utf-8')
            encrypted_header = aesgcm.encrypt(nonce, header_json, None)

            encrypted_header_length = struct.pack('!I', len(encrypted_header))
            packet = session_id + self.NST_FLAG + nonce + encrypted_header_length + encrypted_header

            return packet

        except Exception as e:
            print(f"Encryption failed: {e}")
            return None

    def create_end_stream_packet(self, session_id, stream_id, flags) -> bytes:
        # Create a JSON header for the End Stream packet
        header = {
            "stream_id": stream_id.hex(),
            "timestamp": int(time.time()),
            "flags": flags # indicates the stream has ended.
        }
        
        
        # Encrypt the header with no data
        encrypted_packet = self.encrypt_end_stream_data(session_id, header)
        if encrypted_packet is None:
            raise Exception("Failed to create End Stream packet.")
        
        # Encode the entire packet using Hamming code
        encoded_packet = encode_bytes_with_hamming(encrypted_packet)
        
        return encoded_packet, header

    def encrypt_end_stream_data(self, session_id, header) -> bytes:
        try:
            session_info = self.sessions.get(session_id)
            if not session_info:
                print("Session not found in encrypt end stream data.")
                return None

            session_key = session_info['session_key']
            aesgcm = AESGCM(session_key)
            nonce = os.urandom(12)

            # Encrypt header
            header_json = json.dumps(header).encode('utf-8')
            encrypted_header = aesgcm.encrypt(nonce, header_json, None)

            encrypted_header_length = struct.pack('!I', len(encrypted_header))
            packet = session_id + self.EST_FLAG + nonce + encrypted_header_length + encrypted_header

            return packet

        except Exception as e:
            print(f"Encryption failed: {e}")
            return None

    def create_continue_stream_packet(self, session_id, stream_id) -> tuple[bytes, dict]:
        # Create a JSON header for the Continue Stream packet
        header = {
            "stream_id": stream_id.hex(),
            "timestamp": int(time.time())
        }
        
        # Encrypt the header with no data
        encrypted_packet = self.encrypt_continue_stream_data(session_id, header)
        if encrypted_packet is None:
            raise Exception("Failed to create Continue Stream packet.")
        
        # Encode the entire packet using Hamming code
        encoded_packet = encode_bytes_with_hamming(encrypted_packet)
        
        return encoded_packet, header

    def encrypt_continue_stream_data(self, session_id, header) -> bytes:
        try:
            session_info = self.sessions.get(session_id)
            if not session_info:
                print("Session not found in encrypt continue stream data.")
                return None

            session_key = session_info['session_key']
            aesgcm = AESGCM(session_key)
            nonce = os.urandom(12)

            # Encrypt header
            header_json = json.dumps(header).encode('utf-8')
            encrypted_header = aesgcm.encrypt(nonce, header_json, None)

            encrypted_header_length = struct.pack('!I', len(encrypted_header))
            packet = session_id + self.CST_FLAG + nonce + encrypted_header_length + encrypted_header

            return packet

        except Exception as e:
            print(f"Encryption failed: {e}")
            return None

    def segment_data(self, data, max_packet_size):
        return [data[i:i + max_packet_size] for i in range(0, len(data), max_packet_size)]




class StreamManager:
    def __init__(self, protocol):
        self.protocol = protocol
        self.active_streams = {}
        self.lock = threading.Lock()

    def create_stream(self, session_id, stream_id, send_callback, receive_callback, data_processing_callback=None):
        """Create a new stream."""
        with self.lock:
            if stream_id not in self.active_streams:
                stream = Stream(self, session_id, stream_id, send_callback, receive_callback, data_processing_callback)
                self.active_streams[stream_id] = stream
                return stream
            else:
                print(f"Stream {stream_id.hex()} already exists.")
                return self.active_streams[stream_id]

    def send_stream(self, session_id, stream_id, data):
        """Send data through an existing stream."""
        with self.lock:
            stream = self.active_streams.get(stream_id)
            if stream:
                stream.send(data)
            else:
                print(f"Stream {stream_id.hex()} not found.")

    def close_stream(self, stream_id):
        """Close an existing stream."""
        with self.lock:
            stream = self.active_streams.pop(stream_id, None)
            if stream:
                stream.close()




class Stream:
    def __init__(self, protocol, session_id, stream_id, role, send_callback, receive_callback, data_processing_callback=None):
        self.protocol = protocol
        self.session_id = session_id
        self.stream_id = stream_id
        self.role = role  # 'sender' or 'receiver'
        self.send_callback = send_callback
        self.receive_callback = receive_callback
        self.data_processing_callback = data_processing_callback
        self.buffer = Queue()
        self.active = True
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._process_stream)
        self.thread.start()

    def send(self, data):
        """Send data through the stream."""
        with self.lock:
            self.buffer.put(data)

    def _process_stream(self):
        """Internal method to handle sending and receiving data."""
        while self.active:
            try:
                # Process sending data
                if self.role == 'sender':
                    data = self.buffer.get(timeout=1)
                    self.send_callback(self.session_id, data, {'stream_id': self.stream_id})
            except Empty:
                pass

            # Process receiving data
            packet = self.receive_callback(self.stream_id, self.session_id)
            if packet:
                plaintext, header, flag = self._decrypt_packet(packet)
                if self.data_processing_callback and plaintext:
                    self.data_processing_callback(plaintext, header)
    def _decrypt_packet(self, packet):
        """Decrypt a received packet."""
        try:
            decoded_packet = decode_bytes_with_hamming(packet)
            session_id = decoded_packet[:16]
            flag = decoded_packet[16:19]
            if flag not in [self.protocol.DST_FLAG, self.protocol.EST_FLAG, self.protocol.CST_FLAG]:
                print("Invalid stream packet.")
                return None, None, None

            decoded_packet = decoded_packet[19:]  # Skip the flag
            session_info = self.protocol.sessions.get(session_id)
            if not session_info:
                print("Session not found decrypt packet in stream.")
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

            # Validate header fields based on the flag
            required_keys = ["stream_id", "flags", "timestamp"]
            if flag in [self.protocol.DST_FLAG]:  # Only data packets require sequence numbers
                required_keys.append("sequence_number")

            if not all(k in header_dict for k in required_keys):
                print("Decrypted header must include required fields.")
                return None, None, None

            if ciphertext:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            else:
                plaintext = b''

            return plaintext, header_dict, flag
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None, None, None

    def close(self):
        """Close the stream."""
        self.active = False
        self.thread.join()



class StreamSocket:
    def __init__(self, protocol, session_id):
        self.protocol = protocol
        self.session_id = session_id
        self.streams = {}
        self.lock = threading.Lock()
        self.received_packets = defaultdict(lambda: defaultdict(Queue))

    def create_stream(self, stream_id=None, send_callback=None):
        """Create a new stream within the session."""
        stream_id = stream_id or os.urandom(16)
        with self.lock:
            if stream_id not in self.streams:
                stream = Stream(self.protocol, self.session_id, stream_id, 'sender', send_callback, self._receive_callback, self._data_processing_callback)
                self.streams[stream_id] = stream
                return stream
            else:
                print(f"Stream {stream_id} already exists.")
                return self.streams[stream_id]

    def _receive_callback(self, stream_id, session_id):
        try:
            return self.received_packets[session_id][stream_id].get_nowait()
        except Empty:
            return None

    def _data_processing_callback(self, data, header):
        stream_id = header['stream_id']
        self.received_packets[self.session_id][stream_id].put(data)

    def send(self, stream_id, data):
        """Send data through a specific stream."""
        with self.lock:
            stream = self.streams.get(stream_id)
            if stream:
                stream.send(data)
            else:
                print(f"Stream {stream_id} not found.")

    def receive(self, stream_id):
        """Receive data from a specific stream."""
        with self.lock:
            stream = self.streams.get(stream_id)
            if not stream:
                # Automatically create a stream for the receiver
                stream = Stream(self.protocol, self.session_id, stream_id, 'receiver', None, self._receive_callback, self._data_processing_callback)
                self.streams[stream_id] = stream
            try:
                return self.received_packets[self.session_id][stream_id].get(timeout=1)
            except Empty:
                return None

    def close_stream(self, stream_id):
        """Close a specific stream."""
        with self.lock:
            stream = self.streams.pop(stream_id, None)
            if stream:
                stream.close()

    def close(self):
        """Close all streams."""
        with self.lock:
            for stream in self.streams.values():
                stream.close()
            self.streams.clear()




# Example usage
def main():
    protocol_a = SilentProtocol()
    protocol_b = SilentProtocol()



    # Node A initiates a handshake request to Node B
    pow_request, node_a_private_key = protocol_a.perform_handshake_request()

    # Node B responds with a PoW challenge
    pow_challenge, peer_public_key_bytes = protocol_b.perform_pow_challenge(pow_request)

    # Node A completes the handshake request with PoW solution
    handshake_request = protocol_a.complete_handshake_request(pow_challenge, node_a_private_key)

    # Node B processes the handshake request and responds
    response, private_key, session_id_b = protocol_b.perform_handshake_response(handshake_request)

    # Node A completes the handshake by processing the response
    session_id_a = protocol_a.complete_handshake(response, node_a_private_key)

    print("Handshake completed successfully.")
    print("Session ID A:", session_id_a.hex())
    print("Session ID B:", session_id_b.hex())


    # Create a StreamSocket for Node A
    stream_socket_a = StreamSocket(protocol_a, session_id_a)

    # Create a StreamSocket for Node B
    stream_socket_b = StreamSocket(protocol_b, session_id_b)

    # Define the send callback to simulate network communication
    def send_callback(session_id, packet, header):
        # Simulate sending from A to B
        stream_socket_b.received_packets[session_id][header['stream_id']].put(packet)

    # Create a stream for Node A with the send callback
    stream_a = stream_socket_a.create_stream(send_callback=send_callback)

    packet = protocol_a.encrypt_stream_data(session_id_a, b"First part of the data.", {})
    
    # Send data from Node A to Node B
    stream_socket_a.send(stream_a.stream_id, packet)
   # stream_socket_a.send(stream_a.stream_id, b"Second part of the data.")

    # Node B will automatically create a stream instance when data is received
    received_data = stream_socket_b.receive(stream_a.stream_id)
    while received_data:
        print(f"Node B received: {received_data}")
        received_data = stream_socket_b.receive(stream_a.stream_id)

    stream_socket_a.close()
    stream_socket_b.close()

if __name__ == "__main__":
    main()