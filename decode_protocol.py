from c_hamming import decode_bytes_with_hamming
import struct
import sys

# Define a maximum allowable length for the proof of work solution
MAX_PROOF_LENGTH = 64  # Example limit, adjust as needed

def decode_packet(input_data):
    def try_decode(encoded_bytes):
        try:
            # Decode using Hamming
            decoded_bytes = decode_bytes_with_hamming(encoded_bytes)

            # Determine packet type and process accordingly
            if decoded_bytes[16:19] == b'DTA':
                process_data_packet(decoded_bytes)
            elif decoded_bytes[16:19] == b'RTN':
                process_response_packet(decoded_bytes)
            elif b'HPW' in decoded_bytes:
                process_initial_pow_packet(decoded_bytes)
            elif b'HPR' in decoded_bytes:
                process_pow_challenge_packet(decoded_bytes)
            elif b'HSK' in decoded_bytes:
                if is_handshake_request(decoded_bytes):
                    process_handshake_request_packet(decoded_bytes)
            elif b'HSR' in decoded_bytes:
                process_handshake_response_packet(decoded_bytes)
            else:
                print("Unknown packet type.")
        except ValueError as e:
            import traceback
            traceback.print_exc()
            print(f"Error decoding packet: {e}")

    # If input is a byte string representation
    if isinstance(input_data, bytes):
        try_decode(input_data)
        return

    # Convert input to bytes if it's a hexadecimal string
    if is_hex(input_data):
        try:
            byte_data = bytes.fromhex(input_data)
            try_decode(byte_data)
            return
        except ValueError:
            print("Invalid hexadecimal string format.")
            return

    print("Invalid input format. Please provide a byte string or a hexadecimal string.")

def is_handshake_request(decoded_bytes):
    # Check if the packet structure matches the initial handshake request
    hsk_index = decoded_bytes.find(b'HSK')
    if hsk_index == -1:
        return False
    # Check if the data after the HANDSHAKE_FLAG is likely a proof and within the limit
    proof_length = len(decoded_bytes) - (hsk_index + len(b'HSK'))
    return proof_length < MAX_PROOF_LENGTH

def process_data_packet(decoded_bytes):
    print("Data Packet")
    # Extract session ID and flag
    session_id = decoded_bytes[:16]
    flag = decoded_bytes[16:19]
    print(f"Session ID: {session_id.hex()}, Flag: {flag}")

    # Skip the flag
    decoded_packet = decoded_bytes[19:]

    # Extract nonce
    nonce = decoded_packet[:12]

    # Extract encrypted header length
    encrypted_header_length = struct.unpack('!I', decoded_packet[12:16])[0]

    # Extract encrypted header
    encrypted_header = decoded_packet[16:16+encrypted_header_length]

    # Extract ciphertext
    ciphertext = decoded_packet[16+encrypted_header_length:]

    # Print extracted information
    print("Nonce:", nonce.hex())
    print("Encrypted Header Length:", encrypted_header_length)
    print("Encrypted Header:", encrypted_header.hex())
    print("Ciphertext length:", len(ciphertext))
    print("Ciphertext:", ciphertext.hex())

def process_response_packet(decoded_bytes):
    print("Response Packet")
    # Extract session ID and flag
    session_id = decoded_bytes[:16]
    flag = decoded_bytes[16:19]
    print(f"Session ID: {session_id.hex()}, Flag: {flag}")

    # Skip the flag
    decoded_packet = decoded_bytes[19:]

    # Extract nonce
    nonce = decoded_packet[:12]

    # Extract encrypted header length
    encrypted_header_length = struct.unpack('!I', decoded_packet[12:16])[0]

    # Extract encrypted header
    encrypted_header = decoded_packet[16:16+encrypted_header_length]

    # Extract ciphertext
    ciphertext = decoded_packet[16+encrypted_header_length:]

    # Print extracted information
    print("Nonce:", nonce.hex())
    print("Encrypted Header Length:", encrypted_header_length)
    print("Encrypted Header:", encrypted_header.hex())
    print("Ciphertext length:", len(ciphertext))
    print("Ciphertext:", ciphertext.hex())

def process_initial_pow_packet(decoded_bytes):
    print("Initial PoW Packet")
    # Find the position of the HPW flag to separate the public key and packet size limit
    hpw_index = decoded_bytes.find(b'HPW')
    if hpw_index == -1:
        print("Invalid initial PoW packet.")
        return

    # Extract the public key bytes and packet size limit
    public_key_bytes = decoded_bytes[:91]  # Assuming public key is 91 bytes
    packet_size_limit = struct.unpack('!I', decoded_bytes[91:hpw_index])[0]
    print("Peer Public Key:", public_key_bytes.hex())
    print("Packet Size Limit:", packet_size_limit)

def process_pow_challenge_packet(decoded_bytes):
    print("PoW Challenge Packet")
    # Find the position of the HPR flag to separate the nonce and difficulty
    hpr_index = decoded_bytes.find(b'HPR')
    if hpr_index == -1:
        print("Invalid PoW challenge packet.")
        return

    # Extract the nonce and difficulty
    nonce = decoded_bytes[:hpr_index]
    difficulty = decoded_bytes[hpr_index + len(b'HPR')]
    print("Nonce:", nonce.hex())
    print("Difficulty:", difficulty)

def process_handshake_request_packet(decoded_bytes):
    print("Handshake Request Packet")
    # Find the position of the HANDSHAKE_FLAG to separate the public key and the proof
    hsk_index = decoded_bytes.find(b'HSK')
    if hsk_index == -1:
        print("Invalid handshake request.")
        return

    # Extract the public key bytes and the proof of work solution
    peer_public_key_bytes = decoded_bytes[:hsk_index]
    proof_bytes = decoded_bytes[hsk_index + len(b'HSK'):]
    
    # Check if the proof length is within the acceptable limit
    if len(proof_bytes) > MAX_PROOF_LENGTH:
        print("Proof of work solution is too long, possible attack.")
        return

    print("Peer Public Key:", peer_public_key_bytes.hex())
    print("Proof of Work Solution:", proof_bytes.hex())

def process_handshake_response_packet(decoded_bytes):
    print("Handshake Response Packet")
    # Find the position of the HSR flag to separate the public key and the encrypted data
    hsr_index = decoded_bytes.find(b'HSR')
    if hsr_index == -1:
        print("HSR flag not found in response.")
        return

    # Extract the public key bytes and the encrypted handshake data
    peer_public_key_bytes = decoded_bytes[:hsr_index]
    encrypted_data_start = hsr_index + len(b'HSR')
    nonce = decoded_bytes[encrypted_data_start:encrypted_data_start + 12]
    encrypted_handshake_data = decoded_bytes[encrypted_data_start + 12:]
    print("Peer Public Key:", peer_public_key_bytes.hex())
    print("Nonce:", nonce.hex())
    print("Encrypted Handshake Data:", encrypted_handshake_data.hex())

def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

# Example usage
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python decode_protocol.py <hex_or_binary_string>")
        sys.exit(1)

    input_string = sys.argv[1]
    decode_packet(input_string)