from hamming import decode_binary_string
import struct

def hex_to_binary(hex_string):
    return bin(int(hex_string, 16))[2:].zfill(len(hex_string) * 4)

def binary_to_bytes(binary_string):
    byte_array = bytearray()
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        byte_array.append(int(byte, 2))
    return bytes(byte_array)

def decode_packet(hex_string):
    # Convert hex to binary
    binary_string = hex_to_binary(hex_string)

    # Decode using Hamming
    corrected_binary_string = decode_binary_string(binary_string)

    # Convert binary to bytes
    decoded_bytes = binary_to_bytes(corrected_binary_string)

    # Extract session ID and flag
    session_id = decoded_bytes[:16]
    flag = decoded_bytes[16:19]

    # Determine packet type and process accordingly
    if flag == b'DTA':
        process_data_packet(decoded_bytes)
    elif flag == b'RTN':
        process_response_packet(decoded_bytes)
    elif b'HSK' in decoded_bytes:
        process_handshake_packet(decoded_bytes)
    else:
        print("Unknown packet type.")

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
hex_string = "05784a544a98aa3298861e9854545400322c5498cc9800d28654fee0862c0098662c98984a9898d2e01e66aae01eb400b4feaacc661e1e662c78fe4a86000078000000000000cc54782c1e98ccb46686fe86aaaae0324a1e5486cc7832d200aa1e5486ccfe66d2cc98e01e666654b486cc2c32324a3200aa7800ccaa2cb400d2664acc78541e78001e324a2c782c1e66feb43232982c3278782cb49854b42c4ab41eaa78b478002c321e54fe86fe2c98e086fe664a662c32321e662ccc2ce0782ce0862ce0aafee078fe86d22c7866662c86986654d22c784ae0cce032cc0098cc1e544a7832d2d2324afe2c789800e098cc32e04a861ee0d2867886b4fee0fefe86002c2c86863232e0e0fe782c1e981e8666fe2caa786632669898541e5486aa6600feccb41e2cb4fe98aad2cc5486b4662c78861eaae0004a4ae0782c8600321e2cb4b4d298542c98325432b4e0b400784acc32ccb44afe98e0aafe660000"

#handshake response = #hex_string = "067886004a328600d28600cc001e54b4e0cc98e0782c86aa005400d200cc00e054b4e0cc98e0782c86aa008600d2001e008698540000009898fee0d2fe32782c987832aa86fe2ce0aacc4a66d2b4ccaa1e2ce06678aa66e0667854aa86d2fe8686aa32aa3298fe66b48686d200feccccaa00981eb4fee0b432fee0d2aa78d2d254d2d24aaa78e08666e0e0d2786654aae0862c2c54988686e054aa4a98b4667886aa2ce0ccccfe784a001ecc00cc98865400e0fe322c989898e04a8698662c1e3232b4d2e01e5400980000324a2c3254aa5486d21ecc1e2c1e3286321e54861e7800ccaa32321e862c1e4a5454002c54781e00ccfe321e4aaad22c0098aa861e4a2c663254b42c00662c54e000b4d24ad2b4d21e4accfed2661efe3266aa86fee04a1efe86fe98aaaafe1e1e1eb4e0d21e78322ce02c2cb4e04ab4cc2c1e2c5454cc4acce02c1e54fe1e4a001ee086ccaad200d24a3254b454665400b47800b4fed22cb4541efe1e54aa54fe98b4988666d27800cc00b4781e54cc86002c329898d200d22c2c2cb4b400cc66cc006678fe541ed200b4cc4aaad2d2322cb4862c"

#initial handshake packet = #hex_string = "02f086004a328600d28600cc001e54b4e0cc98e0782c86aa005400d200cc00e054b4e0cc98e0782c86aa008600d2001e0086985400000098b4325486d2e01efe4ae0fe66e04aaa00e01eaad23266861e54e0541e3232fe2c4ad23286781eb41ed286006698fe004ae078cc86aa004a2c861e661eaafe1eaa323298b49832662c66fecc2c1eb486006632fe1e4ae00078784a1e1e66aaaa98fefecc549898862c86862cfe00321e325400b4b44ae0aa2c2c78fe0000cc320098e04a869866"
decode_packet(hex_string)