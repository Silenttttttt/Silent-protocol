# SilentProtocol

SilentProtocol is a TCP-based, bidirectional communication protocol designed to facilitate secure and reliable data exchange without predefined server or client roles. This project leverages modern cryptographic techniques and error correction methods to ensure data integrity and confidentiality.

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

