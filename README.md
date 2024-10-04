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

Contributions are welcome! Feel free to open issues or submit pull requests to improve the project.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This project is intended for educational purposes only. It is not recommended for use in production environments.

