from hamming import decode_binary_string, binary_string_to_bytes
import struct
import sys
import ast

def hex_to_binary(hex_string):
    return bin(int(hex_string, 16))[2:].zfill(len(hex_string) * 4)



def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False
    

def extract_hamming_padding(encoded_string: str) -> int:
    """
    Extract the Hamming padding length from the encoded binary string.

    Args:
        encoded_string (str): The encoded binary string with padding information.

    Returns:
        int: The number of padding bits used in the Hamming encoding.
    """
    # Find the rightmost '1' to identify the padding info
    padding_info_index = encoded_string.rfind('1')
    if padding_info_index < 3:
        raise ValueError("Invalid padding information in the encoded string.")

    padding_info = encoded_string[padding_info_index-3:padding_info_index]
    try:
        padding_length = int(padding_info, 2)
    except ValueError:
        raise ValueError(f"Invalid padding information: {padding_info}")

    return padding_length

def decode_packet(input_string):
    def try_decode(binary_string):
        try:
            padding_length = extract_hamming_padding(binary_string)
            print("Padding length: ", padding_length)

            # Decode using Hamming
            corrected_binary_string = decode_binary_string(binary_string)

            # Convert binary to bytes
            decoded_bytes = binary_string_to_bytes(corrected_binary_string)

            # Extract session ID and flag
            session_id = decoded_bytes[:16]
            flag = decoded_bytes[16:19]

            # Determine packet type and process accordingly
            if flag == b'DTA':
                process_data_packet(decoded_bytes)
                return True
            elif flag == b'RTN':
                process_response_packet(decoded_bytes)
                return True
            elif b'HSK' in decoded_bytes:
                process_handshake_packet(decoded_bytes)
                return True
            else:
                print("Unknown packet type.")
                return False
        except ValueError as e:
            import traceback
            traceback.print_exc()
            print(f"Error decoding packet: {e}")
            return False

    # Convert input to binary string if it's a byte string representation
    if input_string.startswith("b'") and input_string.endswith("'"):
        try:
            # Safely evaluate the byte string
            byte_string = ast.literal_eval(input_string)
            if isinstance(byte_string, bytes):
                # Convert bytes to binary string
                binary_string = ''.join(format(byte, '08b') for byte in byte_string)
                print(f"Binary string length: {len(binary_string)}")
                try_decode(binary_string)
                return
        except (ValueError, SyntaxError):
            print("Invalid byte string format.")
            return

    # Convert input to binary string if it's a hexadecimal string
    if is_hex(input_string):
        binary_string = hex_to_binary(input_string)
        try_decode(binary_string)
        return

    # If input is already a binary string, try decoding directly
    if all(c in '01' for c in input_string):
        try_decode(input_string)
    else:
        print("Invalid input format.")

def process_data_packet(decoded_bytes):
    print("Data Packet")
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
    print()
    print("Ciphertext:", ciphertext.hex())

def process_response_packet(decoded_bytes):
    print("Response Packet")
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
    print()
    print("Ciphertext:", ciphertext.hex())

def process_handshake_packet(decoded_bytes):
    # Find the position of the HSK flag
    hsk_index = decoded_bytes.find(b'HSK')
    if hsk_index == -1:
        print("HSK flag not found.")
        return

    # Determine if it's an initial handshake or a response
    if hsk_index == len(decoded_bytes) - 3:
        print("Initial Handshake Packet")
        public_key = decoded_bytes[:hsk_index]
        print("Public Key:", public_key.hex())
    else:
        print("Handshake Response Packet")
        peer_public_key_bytes = decoded_bytes[:hsk_index]
        encrypted_data_start = hsk_index + 3
        nonce = decoded_bytes[encrypted_data_start:encrypted_data_start + 12]
        encrypted_handshake_data = decoded_bytes[encrypted_data_start + 12:]

        print("Peer Public Key:", peer_public_key_bytes.hex())
        print("Nonce:", nonce.hex())
        print("Encrypted Handshake Data:", encrypted_handshake_data.hex())

# Example usage
# Data packet 

#input_string = "e130cff99a59aacd9b4f0865aaa5cda78551fa47b3aaf0025b5559964aa92cc985ad5acdfe655876b843550ed5ab4f26161fc2ad532cc00000000001fc07da9803825fe66a8001fea800096669feabfd54bfd543aa01500d3a78257894033e096af0b400b5aaa67fbc4af1e5a99307f0b557fd5663e1b3cdc1569feccb0f1ffcb7086f2ada66cd9a5ab3332aabfea9901334e6543f325b5fd28054a8066783ea80016a1f001a61e69866d16cd55533ff57fd5e0674cce1987c386959bc54f34964bc079698cc7cc2c01e0faa661cc32a8cbc86034f0b56a1ffb4aad0f323f85ae03e63c4a66655ff0d299550d9bc79c150f86a803c00f34a52dff32ab59804ce19a19667a59b35557fda7803870003c7da9803843fe95e16d369e3cd3fd2c3ff6ad7f983e199aaa92bc990de4ce0592daaa0381667a6d16e0f19c3d2678694a3c7c3b569980b458ce6b5a7faa7933f99545b355aba4033330f4f0866735501c19b31f544"
 

if __name__ == "__main__":
    if len(sys.argv) != 2:
       print("Usage: python decode_protocol.py <hex_or_binary_string>")
       sys.exit(1)


    print()
    input_string = sys.argv[1]
    decode_packet(input_string)


