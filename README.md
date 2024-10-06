# SilentProtocol

SilentProtocol is a flexible, TCP-based, bidirectional communication protocol designed to facilitate secure and reliable data exchange without predefined server or client roles. This project leverages modern cryptographic techniques and error correction methods to ensure data integrity and confidentiality.

## Work in progres
**This protocol is very work in progress**


## Features

- **Bidirectional Communication**: Supports flexible roles, allowing any node to initiate communication.
- **Elliptic Curve Cryptography (ECC)**: Utilizes ECC for secure key exchange, providing robust security with efficient key sizes.
- **AES-GCM Encryption**: Ensures data confidentiality and integrity with authenticated encryption.
- **Hamming Code**: Implements error detection and correction to enhance data reliability during transmission.
- **Session Management**: Establishes and maintains secure sessions with automatic expiration handling.

## Technologies Used

- **Elliptic Curve Cryptography (ECC)**
- **AES-GCM Encryption**
- **Hamming Code for Error Correction**
- **Python Sockets for TCP Communication** (future)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Silenttttttt/silent-protocol.git
   cd silentprotocol
   ```

2. Install the required dependencies:
   ```bash
   pip install cryptography
   ```
## Usage

To run the example usage of SilentProtocol, execute the following command:

```bash
python silent_protocol/protocol.py
```

This will demonstrate the handshake and message exchange process between two nodes using the SilentProtocol.

## How It Works

1. **Handshake Process**:
   - A node initiates a handshake by sending its public key.
   - The receiving node responds with its public key and an encrypted session ID.
   - The initiating node completes the handshake by deriving a shared session key.

2. **Message Exchange**:
   - The initiating node encrypts a request using the session key and sends it.
   - The receiving node decrypts the request, processes it, and sends an encrypted response.
   - The initiating node decrypts the response to retrieve the message.

## Project Structure

- `protocol.py`: Contains the implementation of the SilentProtocol class and example usage.
- `hamming.py`: Provides functions for encoding and decoding binary strings using Hamming code.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests, or create your own fork to improve the project.

## Packets Type and Structure

# Everything should be type bytes

| Flag | Packet Type | Description | Structure |
|------|-------------|-------------|-----------|
| HPW  | Initiator PoW Request | Sent by the initiator (Node A) to request a PoW challenge, includes Node A's public key and packet size limit. | `public_key_bytes_A + HPW_FLAG + packet_size_limit` |
| HPR  | Responder PoW Challenge | Sent by the responder (Node B), includes Node A's public key, nonce, and difficulty level for the PoW challenge. | `public_key_bytes_A + nonce + HPR_FLAG + difficulty` |
| HSK  | Handshake Request | Sent by the initiator (Node A) after solving the PoW, includes Node A's public key and proof of work solution. | `public_key_bytes_A + HANDSHAKE_FLAG + proof_bytes` |
| HSR  | Handshake Response | Sent by the responder (Node B), includes Node B's public key, session ID, and encrypted session data. | `public_key_bytes_B + HANDSHAKE_RESPONSE_FLAG + nonce + encrypted_handshake_data + packet_size_limit` |
| DTA  | Data Packet | Used for sending encrypted data between nodes, includes session ID, nonce, and encrypted payload. | `session_id + DATA_FLAG + nonce + encrypted_header_length + encrypted_header + encrypted_data` |
| RTN  | Response Packet | Used for sending encrypted responses, includes session ID, nonce, and encrypted payload. | `session_id + RESPONSE_FLAG + nonce + encrypted_header_length + encrypted_header + encrypted_data` |

### Encrypted Header Information

The encrypted header in both Data and Response packets contains the following critical information:

- **Timestamp:** The time at which the packet was created, used for validating the freshness of the data.
- **Encoding:** Specifies the character encoding used for the data, typically 'utf-8'.
- **Content Type:** Describes the type of content being transmitted, such as 'application/json'.
- **Response Code (required for response packet):** Used in response packets to indicate the status of the response (e.g., HTTP-like status codes).

### Explanation:

- **HPW (Handshake Proof of Work):**
  - **Initiator PoW Request:** Contains Node A's public key, the HPW flag, and the packet size limit.
  - **Responder PoW Challenge (HPR):** Contains Node A's public key, a nonce, the HPR flag, and the difficulty level as a byte.

- **HSK (Handshake):**
  - **Handshake Request:** Contains Node A's public key, the handshake flag, and the proof of work solution.

- **HSR (Handshake Response):**
  - **Handshake Response:** Contains Node B's public key, the handshake response flag, a nonce, encrypted session data, and the packet size limit.

- **DTA (Data):**
  - **Data Packet:** Contains the session ID, data flag, nonce, encrypted header length, encrypted header, and encrypted data. The encrypted header includes metadata like timestamp, encoding, and content type.

- **RTN (Response):**
  - **Response Packet:** Similar to the data packet, but used for responses, containing the session ID, response flag, nonce, encrypted header length, encrypted header, and encrypted data. The encrypted header may also include a response code.

This table and explanation provide a comprehensive view of the packet structures, including the critical metadata contained within the encrypted headers. This information is crucial for correctly processing and interpreting the data exchanged using the SilentProtocol.



## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This project is intended for educational purposes only. It is not recommended for use in production environments.

