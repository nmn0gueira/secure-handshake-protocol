# Secure Handshake Protocol

This repository contains an implementation of a secure handshake protocol designed to establish a secure connection between two parties. This protocol works with secure datagram sockets from the dstp package. After completing the handshake, it enables secure message exchange using the datagram-based secure transport protocol. Inspired by TLS, this protocol aims to ensure confidentiality, integrity, and authentication in communications.


## Overview of Protocols
### Secure Handshake Protocol (SHP)
The secure handshake protocol consists of the following steps:
1. **Client Hello**: The client sends a user identifier to the server.
2. **Server Hello**: The server responds with three random numbers. The first two will be the salt and number of iterations used by the password-based encryption scheme in the following step. The third number is just a nonce used to prevent replay attacks.
3. **Client Request**: The client sends their request and public Diffie-Hellman number along with other necessary information encrypted with a password-based encryption scheme. The client additionally sends a digital signature of this information along with a MAC of the whole message.
4. **Server Response**: The server verifies the client's signature and MAC, and if valid, responds with its own Diffie-Hellman number encrypted with the client's public key and a digital signature of the response. The server also includes a MAC of the entire message.
5. **Synchronization**: The client verifies the server's signature and MAC, and if valid, both parties can now communicate securely using the established Diffie-Hellman key and agreed-upon cipher suite.

#### Cryptographic Algorithms
SHP uses the following cryptographic algorithms:
- **Diffie-Hellman Key Exchange**: For establishing a shared secret secret between the client and server. This secret is used as a basis for deriving parameters for the following communication (e.g., session key). 
- **Elliptic Curve Digital Signature Algorithm (ECDSA)**: For signing and verifying messages exchanged during the handshake.
- **Password-Based Encryption (PBE)**: For encrypting the client's request. The scheme uses AES in CBC mode with 196 bit keys and derives the key from the password using PBKDF2 with HMAC-SHA256 (Bouncy Castle implementation-specific).
- **Message Authentication Code (MAC)**: For ensuring the integrity and authenticity of messages exchanged during the handshake. The protocol uses HMAC with SHA-256 for this purpose.
- **Elliptic Curve Integrated Encryption Scheme (ECIES)**: For encrypting the server's response to the client.

### Datagram-based Secure Transport Protocol (DSTP)
After the handshake is completed, the protocol uses the datagram-based secure transport protocol for secure message exchange. DSTP is designed to work with the SHP and provides the following features:
- **Confidentiality**: Messages exchanged after the handshake are encrypted using the shared secret key established during the handshake.
- **Integrity**: Each message is accompanied by a MAC or a hash to ensure its integrity. The choice of integrity check depends on the cipher suite agreed upon during the handshake and shapes the message format.

#### Additional Information
For more details on the cryptographic algorithms, check the provided crypto configuration files in `src/test/resources/test-configs`.

The socket implementation provided can also be used with a static crypto configuration file `cryptoconfig.txt` agreed upon by both parties, although this is a remaining feature of a previous version of the project.


## About
This project was developed as part of the Computer Networks and Systems Security (2024/25) course at FCT-UNL. The code is provided for educational purposes only and should not be used in any real-world applications.
