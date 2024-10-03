def generate_hamming_code(data_bits: str) -> str:
    # Hamming(8,4) code: 4 data bits, 4 parity bits
    data = list(map(int, data_bits))
    m = len(data)
    r = 4  # For Hamming(8,4), we have 4 parity bits

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
    hamming = list(map(int, hamming_code))
    n = len(hamming)
    r = 4  # For Hamming(8,4), we have 4 parity bits

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

def encode_binary_string(binary_string: str) -> str:
    # Calculate padding needed to make the binary string a multiple of 4
    padding_length = (4 - len(binary_string) % 4) % 4
    padded_binary_string = binary_string + '0' * padding_length

    # Encode the original length of the binary string
    original_length = len(binary_string)
    length_bits = f"{original_length:016b}"  # Use 16 bits to store the length

    encoded_parts = [length_bits]
    for i in range(0, len(padded_binary_string), 4):
        part = padded_binary_string[i:i+4]
        hamming_code = generate_hamming_code(part)
        encoded_parts.append(hamming_code)
    return ''.join(encoded_parts)

def decode_binary_string(encoded_string: str) -> str:
    # Extract the original length of the binary string
    length_bits = encoded_string[:16]
    original_length = int(length_bits, 2)

    decoded_parts = []
    for i in range(16, len(encoded_string), 8):
        hamming_code = encoded_string[i:i+8]
        corrected_code = detect_and_correct_error(hamming_code)
        decoded_parts.append(corrected_code)

    decoded_binary_string = ''.join(decoded_parts)
    return decoded_binary_string[:original_length]

# Example usage
if __name__ == "__main__":
    # Convert "Hello world" to a binary string
    binary_string = ''.join(format(ord(char), '08b') for char in "Hello world!")
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