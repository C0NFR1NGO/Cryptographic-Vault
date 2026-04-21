\# Python Local Cryptographic Vault



A robust, object-oriented software utility for securely encrypting, obscuring, and shredding local files using modern cryptographic standards, written in Python.



\## Overview



This project digitally constructs a secure vault for sensitive local files. Rather than relying on a single master password or simple text encoding, this tool treats every file as an isolated entity. It handles advanced cryptographic operations including PBKDF2HMAC key stretching, custom binary payload packing for metadata concealment, and secure disk shredding to prevent digital forensic recovery. 



\## Features



\* \*\*Per-File Isolation:\*\* Built with a decentralized security approach. There is no master password; every file is encrypted independently using unique credentials.

\* \*\*Military-Grade Cryptography:\*\* Utilizes the exact mathematical implementations of AES-128 in CBC mode, authenticated with SHA256 HMAC signatures to prevent tampering.

\* \*\*Metadata Concealment:\*\* Implements a custom Type-Length-Value (TLV) binary protocol to pack the original filename and extension directly into the encrypted payload, completely obscuring the file type and intent from outside observers.

\* \*\*Secure Shredding:\*\* Replicates the physical destruction of documents by overwriting the original file's location with cryptographically secure random noise (`os.urandom`) before unlinking it from the drive.

\* \*\*Unique Salting:\*\* Generates a unique 16-byte cryptographic salt for every encryption pass, ensuring identical files yield completely different ciphertexts and neutralizing pre-computed rainbow table attacks.



\## Project Structure



The codebase is encapsulated within a modular, Object-Oriented script (`vault.py`) for easy deployment and maintenance:



\* `Vault::\_\_init\_\_`: Orchestrates the core vault settings, establishing the 600,000 iteration work-factor to mathematically throttle brute-force attempts.

\* `Vault::\_derive\_key`: Handles the PBKDF2HMAC cryptographic math to convert human-readable passwords and raw salts into secure 32-byte AES keys.

\* `Vault::lock`: Manages the metadata packing, data scrambling (encryption), and the secure destruction (shredding) of the source file.

\* `Vault::unlock`: Reverses the binary protocol, verifying HMAC signatures before unpacking the original metadata and perfectly restoring the file.

\* `main()`: The entry point providing an interactive, user-friendly command-line interface with automatic string-stripping for drag-and-drop file support.



\## Installation \& Execution



To run the project, ensure you have a standard Python 3.7+ environment installed. You will also need the industry-standard `cryptography` package. Run the following commands in the directory containing your source file:



```bash

\# Install the required cryptographic dependency

pip install cryptography



\# Launch the interactive vault interface

python vault.py

