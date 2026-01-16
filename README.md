# Data-security-and-integrity-cryptographic-API-services

1. Overview

This system is a FastAPI-based backend application designed to provide cryptographic security services. It facilitates key generation (RSA, EC, Ed25519), user session management, and digital signatures for PDF files.

The project consists of three main files:
- main.py: The entry point to run the server.
- api.py: The core server logic handling API requests, data storage, and session validation.
- client.py: A client-side utility script for generating cryptographic keys and signing data locally.

2. System Prerequisites
Before running the code, ensure Python is installed and install the required libraries:

pip install fastapi uvicorn cryptography multipart

3. How to Run the Server (Backend)
- The main.py and api.py files work together to launch the API server.
- Ensure main.py and api.py are in the same directory.
- Open your terminal/command prompt in that directory.
Run the following command:

pip install uv

uv run main.py

The server will start at http://0.0.0.0:8080.

Upon initialization, the server automatically creates necessary data directories:
- data/pubkeys: Stores user public keys.
- data/messages: Stores encrypted messages.
- data/pdfs: Stores PDF files.
- data/sessions: Stores active session data.

4. How to Use the Client (Key Generator)
The client.py file acts as a client-side tool to generate keys and simulate signatures.

Run the script to generate Key Pairs (Private & Public Keys):

uv run client.py

This script will:
- Create a keys/ directory.
- Generate private (_priv.pem) and public (_pub.pem) key files for RSA, EC, or Ed25519 algorithms.
- Simulate signing a PDF hash using the generated private key.

5. Data Storage Structure
The system manages files automatically using the following structure:

keys/ (Created by client.py):
- Contains user private keys (Keep these text-secure).
- data/ (Created by api.py):
- Contains central server data. To reset the server (remove all users), you can clear the contents of this folder.

6. Key API Endpoints
Based on the api.py code, the server provides the following functionalities:
- Authentication: Login and session token generation.
- Delete User: Deletes user data and their public key (can only be performed by the account owner).
- Stats: View server statistics (total users, messages, PDF files, and active sessions).
