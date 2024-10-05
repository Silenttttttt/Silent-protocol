import subprocess
from hamming import bytes_to_binary_string, decode_binary_string

def encode_bytes_with_hamming(data_bytes: bytes) -> bytes:
    """
    Encode bytes using the Hamming(7,4) encoding implemented in C.

    Args:
        data_bytes (bytes): The input data to encode.

    Returns:
        bytes: The encoded data.
    """
    if not isinstance(data_bytes, bytes):
        raise ValueError("Input data must be bytes")

    process = subprocess.run(
        ['./c_hamming/hamming', 'encode'],
        input=data_bytes,
        capture_output=True,
        text=False  # Ensure binary mode
    )
    if process.returncode != 0:
        raise RuntimeError(f"Fast encoding failed: {process.stderr.decode()}")

    result = process.stdout
    # print(f'Encoded bytes: {result}')

    return result

def decode_bytes_with_hamming(encoded_bytes: bytes) -> bytes:
    """
    Decode bytes using the Hamming(7,4) decoding implemented in C.

    Args:
        encoded_bytes (bytes): The encoded data to decode.

    Returns:
        bytes: The decoded data.
    """
    if not isinstance(encoded_bytes, bytes):
        raise ValueError("Encoded data must be bytes")

    process = subprocess.run(
        ['./c_hamming/hamming', 'decode'],
        input=encoded_bytes,
        capture_output=True,
        text=False  # Ensure binary mode
    )
    if process.returncode != 0:
        raise RuntimeError(f"Fast decoding failed: {process.stderr.decode()}")

    result = process.stdout
    # print(f'Decoded bytes: {result}')

    return result



# with open('data_bytes.bin', 'rb') as f:
#     data_bytes = f.read()



# data_bytes = b"Hello World"

# encoded_bytes = encode_bytes_with_hamming(data_bytes)




# decoded_bytes = decode_bytes_with_hamming(encoded_bytes)
# print(decoded_bytes)
# assert data_bytes == decoded_bytes


# # Example usage
# if __name__ == "__main__":
#     message = b"Hello World"
#     message_bytes = message # message.encode('utf-8')
#     print(f'Original message bytes: {message_bytes}')

#     encoded_bytes = encode_bytes_with_hamming(message_bytes)
#     print(f'Encoded bytes: {encoded_bytes}')

#     decoded_bytes = decode_bytes_with_hamming(encoded_bytes)
#     print(f'Decoded bytes: {decoded_bytes}')   

#     try:
#         decoded_text = decoded_bytes#.decode('utf-8')
#         print(f'Decoded text: {decoded_text}')
#         print(f'Length of decoded text: {len(decoded_text)}')
#         assert decoded_text == message
#     except UnicodeDecodeError as e:
#         print(f"Error decoding bytes: {e}")


    # python_binary_string = bytes_to_binary_string(encoded_bytes)
    # print(f'Python binary string: {python_binary_string}')

    # corrected_binary_string = decode_binary_string(python_binary_string)
    # print(f'Corrected binary string: {corrected_binary_string}')

    # decoded_text = ''.join(chr(int(corrected_binary_string[i:i+8], 2)) for i in range(0, len(corrected_binary_string), 8))
    # print(f'Decoded text: {decoded_text}')

    # encoded_bytes_with_error = bytearray(encoded_bytes)
    # encoded_bytes_with_error[2] ^= 0x01  # Flip a bit to introduce an error
    # print(f'Encoded bytes with error: {encoded_bytes_with_error}')

    # corrected_bytes = decode_bytes_with_hamming(bytes(encoded_bytes_with_error))
    # print(f'Corrected bytes: {corrected_bytes}')

    # try:
    #     decoded_text = corrected_bytes.decode('utf-8')
    #     print(f'Decoded text: {decoded_text}')
    # except UnicodeDecodeError as e:
    #     print(f"Error decoding bytes: {e}")

