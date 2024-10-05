import os
import json
import zlib
import math
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from c_hamming import encode_bytes_with_hamming
import struct
import random 


def generate_data_packet(data, header):
    session_id = os.urandom(16)  # 16 bytes for a UUID
    flag = b'DTA'  # 3 bytes
    nonce = os.urandom(12)  # 12 bytes
    aes_key = AESGCM.generate_key(bit_length=256)  # 32 bytes for AES-256
    aesgcm = AESGCM(aes_key)

    # Compress the header and data before encryption
    header_json = json.dumps(header).encode('utf-8')
    compressed_header = zlib.compress(header_json)
    compressed_data = zlib.compress(data)

    encrypted_header = aesgcm.encrypt(nonce, compressed_header, None)
    encrypted_data = aesgcm.encrypt(nonce, compressed_data, None)
    encrypted_header_length = struct.pack('!I', len(encrypted_header))

    packet_compressed = session_id + flag + nonce + encrypted_header_length + encrypted_header + encrypted_data

    # Convert packet to binary string and apply Hamming encoding
    encoded_packet_compressed = encode_bytes_with_hamming(packet_compressed)


    return len(encoded_packet_compressed)

def hamming_encoded_length(data_length):
    # Calculate the length after Hamming(7,4) encoding
    return math.ceil(data_length * 7 / 4)

def calculate_padding(data_length):
    # Calculate the number of padding bits needed to make the data length a multiple of 4
    padding_length = (4 - data_length % 4) % 4
    # Add 4 bits for encoding the padding length itself
    return padding_length + 4

def estimate_packet_size_upper_bound(header_bytes, data_bytes):
    """
    Estimate the upper bound of the total packet size based on header and data lengths.

    Args:
        header_bytes (bytes): The header data as bytes.
        data_bytes (bytes): The data to be sent as bytes.

    Returns:
        int: The estimated upper bound of the total packet size in bytes.
    """

    safety_margin = 1.1  # 10% extra space for imperfections in estimation

    header_compression_ratio = 0.95
    compression_ratio = 0.9

    # Estimate sizes after minimal compression
    estimated_compressed_header_length = int(len(header_bytes) * header_compression_ratio)
    estimated_compressed_data_length = int(len(data_bytes) * compression_ratio)

    # Calculate total length before Hamming encoding
    total_length_before_hamming = (
        16 +  # Session ID
        3 +   # Flag
        12 +  # Nonce
        4 +   # Encrypted header length field
        estimated_compressed_header_length +
        estimated_compressed_data_length
    )

    # Calculate padding size
    padding_size = calculate_padding(total_length_before_hamming)

    # Protocol overhead
    protocol_overhead = 250

    # Total length including padding and protocol overhead
    total_length_with_overhead = total_length_before_hamming + protocol_overhead

    # Calculate Hamming encoded length
    hamming_size = hamming_encoded_length(total_length_with_overhead)

    # Estimate total size
    estimated_size = (hamming_size + padding_size) * safety_margin
    return int(estimated_size)







def test_hamming_length_estimation():
    # Test data of various lengths
    test_data_lengths = [1, 4, 7, 10, 16, 32, 64, 128, 256, 512, 1024, 100000]

    for length in test_data_lengths:
        # Generate random data of the specified length
        data = os.urandom(length)

        # Estimate the Hamming encoded length
        estimated_length = hamming_encoded_length(length) + calculate_padding(length)

        # Get the actual Hamming encoded length
        encoded_data = encode_bytes_with_hamming(data)
        actual_length = len(encoded_data)

        # Print the results
        print(f"Data length: {length} bytes")
        print(f"Estimated Hamming encoded length: {estimated_length} bytes")
        print(f"Actual Hamming encoded length: {actual_length} bytes")
        print(f"Difference: {actual_length - estimated_length} bytes")
        print(f"Difference in percentage: {(actual_length - estimated_length) / estimated_length * 100:.2f}%\n")



# Example usage
if __name__ == "__main__":
    header = str({"timestamp": 1234567890, "encoding": "utf-8", "content_type": "text"})

    # Generate random binary data of length 1000
    data = os.urandom(100000000)


    
    # #random string of length 100000 in bytes
    # data = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[];|<>,./?') for _ in range(100000)).encode('utf-8')

    # Estimate the packet size
    estimated_size = estimate_packet_size_upper_bound(header, data)
    print(f"Estimated upper bound packet size: {estimated_size} bytes")
    
    # Generate the actual packet and get its size
    actual_size = generate_data_packet(data, header)
    print(f"Actual packet size: {actual_size} bytes")

    # Compare the estimated and actual sizes
    print(f"Difference: {actual_size - estimated_size} bytes")

    difference_percentage = (actual_size - estimated_size) / estimated_size * 100
    print(f"Difference in percentage: {difference_percentage:.2f}%")