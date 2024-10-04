def generate_hamming_code(data_bits: str) -> str:
    """
    Generate a Hamming(7,4) code from 4 data bits.

    Args:
        data_bits (str): A string of 4 binary digits.

    Returns:
        str: A string of 7 binary digits representing the Hamming code.
    """
    data = list(map(int, data_bits))
    m = len(data)
    r = 3  # For Hamming(7,4), we have 3 parity bits

    hamming_code = [0] * (m + r)
    j = 0
    for i in range(1, len(hamming_code) + 1):
        if (i & (i - 1)) == 0:
            continue
        hamming_code[i - 1] = data[j]
        j += 1

    # Calculate parity bits
    for i in range(r):
        parity_pos = 2 ** i
        parity = 0
        for j in range(parity_pos, len(hamming_code) + 1):
            if j & parity_pos:
                parity ^= hamming_code[j - 1]
        hamming_code[parity_pos - 1] = parity

    return ''.join(map(str, hamming_code))

def detect_and_correct_error(hamming_code: str) -> str:
    """
    Detect and correct a single-bit error in a Hamming(7,4) code.

    Args:
        hamming_code (str): A string of 7 binary digits.

    Returns:
        str: A string of 4 binary digits representing the corrected data.
    """
    hamming = list(map(int, hamming_code))
    n = len(hamming)
    r = 3  # For Hamming(7,4), we have 3 parity bits

    error_pos = 0
    for i in range(r):
        parity_pos = 2 ** i
        parity = 0
        for j in range(parity_pos, n + 1):
            if j & parity_pos:
                parity ^= hamming[j - 1]
        if parity != 0:
            error_pos += parity_pos

    if error_pos != 0:
        hamming[error_pos - 1] ^= 1

    data_bits = []
    for i in range(1, n + 1):
        if (i & (i - 1)) != 0:
            data_bits.append(hamming[i - 1])

    return ''.join(map(str, data_bits))

def encode_binary_string(data_bits: str) -> str:
    """
    Encode a binary string using Hamming(7,4) encoding.

    Args:
        data_bits (str): A binary string to encode.

    Returns:
        str: The encoded binary string with padding information.
    """
    padding_length = (4 - len(data_bits) % 4) % 4
    padded_data_bits = data_bits + '0' * padding_length

    encoded_parts = []
    for i in range(0, len(padded_data_bits), 4):
        part = padded_data_bits[i:i+4]
        hamming_code = generate_hamming_code(part)
        encoded_parts.append(hamming_code)

    # Append the padding length as a 4-bit binary string at the end
    padding_info = format(padding_length, '03b') + '1'
    binary_string = ''.join(encoded_parts) + padding_info

    # Calculate additional padding to make the length a multiple of 8
    total_padding_length = (8 - len(binary_string) % 8) % 8
    binary_string += '0' * total_padding_length

    return binary_string

def decode_binary_string(encoded_string: str) -> str:
    """
    Decode a binary string encoded with Hamming(7,4) and correct errors.

    Args:
        encoded_string (str): The encoded binary string with padding information.

    Returns:
        str: The original binary string after decoding and error correction.
    """
    # Find the rightmost '1' to identify the padding info
    padding_info_index = encoded_string.rfind('1')
    padding_info = encoded_string[padding_info_index-3:padding_info_index]
    padding_length = int(padding_info, 2)

    # Remove the padding info from the encoded string
    encoded_string = encoded_string[:padding_info_index-3]

    decoded_parts = []
    for i in range(0, len(encoded_string), 7):
        hamming_code = encoded_string[i:i+7]
        corrected_code = detect_and_correct_error(hamming_code)
        decoded_parts.append(corrected_code)

    decoded_binary_string = ''.join(decoded_parts)

    # Remove the padding that was added earlier
    if padding_length > 0:
        decoded_binary_string = decoded_binary_string[:-padding_length]

    return decoded_binary_string

def bytes_to_binary_string(byte_data: bytes) -> str:
    """
    Convert bytes to an 8-bit binary string.

    Args:
        byte_data (bytes): The byte data to convert.

    Returns:
        str: The binary string representation of the byte data.
    """
    return ''.join(format(byte, '08b') for byte in byte_data)

def binary_string_to_bytes(binary_str: str) -> bytes:
    """
    Convert a binary string back to bytes.

    Args:
        binary_str (str): The binary string to convert. Must be a multiple of 8.

    Returns:
        bytes: The byte representation of the binary string.
    """
    if len(binary_str) % 8 != 0:
        raise ValueError("Binary string length must be a multiple of 8")

    return bytes(int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8))

# Example usage
if __name__ == "__main__":
    # Convert "Hello world" to a binary string
    message = "Hello world!"
    binary_string = ''.join(format(ord(char), '08b') for char in message)
    print(f'Original binary string: {binary_string}')

    # Encode the binary string
    encoded_string = encode_binary_string(binary_string)
    print(f'Encoded binary string: {encoded_string}')

    # Introduce an error in the encoded string
    encoded_string_with_error = list(encoded_string)
    if encoded_string_with_error[16] == '0':
        encoded_string_with_error[16] = '1'
    else:
        encoded_string_with_error[16] = '0'
    encoded_string_with_error = ''.join(encoded_string_with_error)
    print(f'Encoded string with error: {encoded_string_with_error}')

    # Decode and correct the error
    corrected_string = decode_binary_string(encoded_string_with_error)
    print(f'Corrected binary string: {corrected_string}')

    # Convert the corrected binary string back to text
    decoded_text = ''.join(chr(int(corrected_string[i:i+8], 2)) for i in range(0, len(corrected_string), 8))
    print(f'Decoded text: {decoded_text}')
    print("Original message: ", message)
    print("Length of original message: ", len(message))
    print("Length of decoded message: ", len(decoded_text))

    # Show different chars
    print("Different chars: ", set(decoded_text) - set(message))

    assert decoded_text == message