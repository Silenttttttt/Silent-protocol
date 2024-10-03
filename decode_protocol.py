from hamming import decode_binary_string
import struct

def hex_to_binary(hex_string):
    # Convert hex to binary
    return bin(int(hex_string, 16))[2:].zfill(len(hex_string) * 4)



def binary_to_bytes(binary_string):
    # Convert binary string to bytes
    byte_array = bytearray()
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        byte_array.append(int(byte, 2))
    return bytes(byte_array)

# Given hex string
hex_string = "05784a544a98aa3298861e9854545400322c5498cc9800d28654fee0862c0098662c98984a9898d2e01e66aae01eb400b4feaacc661e1e662c78fe4a86000078000000000000cc54782c1e98ccb46686fe86aaaae0324a1e5486cc7832d200aa1e5486ccfe66d2cc98e01e666654b486cc2c32324a3200aa7800ccaa2cb400d2664acc78541e78001e324a2c782c1e66feb43232982c3278782cb49854b42c4ab41eaa78b478002c321e54fe86fe2c98e086fe664a662c32321e662ccc2ce0782ce0862ce0aafee078fe86d22c7866662c86986654d22c784ae0cce032cc0098cc1e544a7832d2d2324afe2c789800e098cc32e04a861ee0d2867886b4fee0fefe86002c2c86863232e0e0fe782c1e981e8666fe2caa786632669898541e5486aa6600feccb41e2cb4fe98aad2cc5486b4662c78861eaae0004a4ae0782c8600321e2cb4b4d298542c98325432b4e0b400784acc32ccb44afe98e0aafe660000"

# Convert hex to binary
binary_string = hex_to_binary(hex_string)

# Decode using Hamming
corrected_binary_string = decode_binary_string(binary_string)

# Convert binary to bytes
decoded_bytes = binary_to_bytes(corrected_binary_string)


# Extract session ID and flag
session_id = decoded_bytes[:16]
flag = decoded_bytes[16:19]

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
print("Session ID:", session_id.hex())
print("Flag:", flag)
print("Nonce:", nonce.hex())
print("Encrypted Header Length:", encrypted_header_length)
print("Encrypted Header:", encrypted_header.hex())
print("Ciphertext:", ciphertext.hex())