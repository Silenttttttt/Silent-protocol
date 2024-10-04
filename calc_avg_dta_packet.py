from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json
import struct
import time
import math
from hamming import encode_binary_string, decode_binary_string, binary_string_to_bytes, bytes_to_binary_string


def generate_data_packet(data, header):
    session_id = os.urandom(16)  # 16 bytes for a UUID
    flag = b'DTA'  # 3 bytes
    nonce = os.urandom(12)  # 12 bytes
    aes_key = AESGCM.generate_key(bit_length=256)  # 32 bytes for AES-256
    aesgcm = AESGCM(aes_key)

    header_json = json.dumps(header).encode('utf-8')
    encrypted_header = aesgcm.encrypt(nonce, header_json, None)
    encrypted_data = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
    encrypted_header_length = struct.pack('!I', len(encrypted_header))

    packet = session_id + flag + nonce + encrypted_header_length + encrypted_header + encrypted_data

    # Convert packet to binary string and apply Hamming encoding
    encoded_packet = encode_binary_string(bytes_to_binary_string(packet))

    return len(binary_string_to_bytes(encoded_packet))

def hamming_encoded_length(data_length):
    # Calculate the length after Hamming(7,4) encoding
    return math.ceil(data_length * 7 / 4)

def calculate_padding(data_length):
    # Calculate the number of padding bits needed to make the data length a multiple of 4
    padding_length = (4 - data_length % 4) % 4
    # Add 4 bits for encoding the padding length itself
    return padding_length + 4

def simulate_packet_sizes():
    header_sizes = [50, 100, 200]  # Different header sizes in bytes
    data_sizes = [100, 500, 1000, 5000, 10000]  # Different data sizes in bytes
    num_trials = 10  # Number of trials for averaging

    total_overhead = 0
    total_packets = 0

    for header_size in header_sizes:
        for data_size in data_sizes:
            header = {
                "timestamp": int(time.time()),
                "encoding": 'utf-8',
                "content_type": 'application/json',
                "extra": "x" * (header_size - 50)  # Adjust header size
            }
            data = "x" * data_size  # Simulate data of given size

            for _ in range(num_trials):
                packet_size = generate_data_packet(data, header)
                estimated_size = header_size + data_size
                overhead = packet_size - estimated_size
                total_overhead += overhead
                total_packets += 1

    average_overhead = total_overhead / total_packets
    print(f"Average overhead per packet: {average_overhead:.2f} bytes")

    return average_overhead

#average_overhead = simulate_packet_sizes()

def estimate_packet_size(header_length, data_length, average_overhead):
    """
    Estimate the total packet size based on header and data lengths.

    Args:
        header_length (int): The length of the header in bytes.
        data_length (int): The length of the data in bytes.
        average_overhead (float): The average overhead for the packet.

    Returns:
        int: The estimated total packet size in bytes.
    """
    hamming_size = hamming_encoded_length(data_length)
    padding_size = calculate_padding(data_length)
    estimated_size = header_length + hamming_size + padding_size + average_overhead
    return int(estimated_size)

# Example usage

average_overhead = 112

header_length = 100  # Example header length in bytes
data_length = 1024  # Example data length in bytes
estimated_packet_size = estimate_packet_size(header_length, data_length, average_overhead)
packet_size = generate_data_packet("a"*data_length, {"timestamp": int(time.time()), "encoding": 'utf-8', "content_type": 'application/json', "extra": "x" * (header_length - 50)})

print(f"Estimated packet size: {estimated_packet_size} bytes")
print(f"Actual packet size: {packet_size} bytes")