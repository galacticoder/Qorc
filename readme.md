# End-to-End Encrypted Chat Site

# ATTENTION: THIS READ ME FILE IS CURRENTLY OUTDATED I WILL UPDATE THIS LATER TO REFLECT CHANGES BUT FOR NOW IS OUTDATED INFORMATION

This is my end2end encrypted chat app. I originally made 2 different versions in c++ but was very limited, So i decided to make it into a site and not use c++.


### Prerequisites

*   Node.js (LTS version recommended)
*   pnpm (or npm/yarn)

## Installation and Setup

To quickly get the application running, you can use the provided bash script:

1.  **Navigate to the project root directory:**
    ```bash
    cd end2end-chat-site
    ```
2.  **Run the start server script:**
    ```bash
    ./startServer.sh
    ```
3.  **Run the start client script in another terminal:**
    ```bash
     ./startClient.sh
    ```
    
5.  **Access the application:**
    Once the script has finished, open your web browser and navigate to `http://localhost:5173` (or the address indicated by the script if different).

## Usage

1.  **Register/Login:** After opening the application in your browser, register a new account or log in with existing credentials.
2.  **Start Chatting:** Once logged in, you can start sending end-to-end encrypted messages and files to other users.
3.  **File Sharing:** Use the integrated file sharing feature to securely exchange files.

### Key Features

*   **End-to-End Encryption:** All messages and files are encrypted on the sender's device and can only be decrypted by the intended recipient, ensuring privacy and confidentiality.
*   **Real-time Communication:** Utilizes WebSockets for instant message delivery and real-time chat experience.
*   **User Authentication:** Secure user registration and login system.
*   **File Sharing:** Securely share files within the chat.
*   **Responsive Design:** A user-friendly interface that adapts to various screen sizes.



### Encryption Details

This application employs a hybrid encryption scheme to ensure robust end-to-end security:

*   **RSA-OAEP (4096-bit):** Used for asymmetric encryption, primarily for securely exchanging AES keys between users. This ensures that the symmetric key used for message encryption is transmitted confidentially.
*   **AES-GCM (256-bit):** Used for symmetric encryption of the actual chat messages. AES-GCM provides both confidentiality and authenticity (integrity) of the data.
*   **Key Derivation (Argon2):** Passwords are not stored directly. Instead, Argon2 is used to derive strong cryptographic keys from user passwords, adding a significant layer of protection against brute-force attacks.
*   **Secure Key Exchange:** A unique AES key is generated for each message or session and is encrypted using the recipient's RSA public key before transmission. This ensures forward secrecy to some extent, as compromising one AES key does not compromise past or future communications.

### Security Measures

*   **End-to-End Encryption:** Messages are encrypted on the sender's device and decrypted only on the recipient's device. The server never has access to the plaintext messages.
*   **Strong Cryptographic Algorithms:** Utilizes industry-standard and robust cryptographic algorithms (RSA-4096, AES-256 GCM, SHA-512) to protect data confidentiality and integrity.
*   **Salted Key Derivation:** Argon2 with a unique salt for each user makes it computationally infeasible to reverse engineer passwords from derived keys.
*   **Secure WebSocket Communication:** All communication between the client and server, including metadata, is handled over secure WebSockets.
*   **No Plaintext Storage:** User messages are never stored in plaintext on the server.
*   **Servers Require Passwords:** Users need to enter the correct server password to enter.

### How Safe Is It?

The application is designed with a strong focus on security and privacy:

*   **Confidentiality:** Messages are unreadable by anyone other than the intended recipient, including the server administrators.
*   **Integrity:** AES-GCM ensures that messages have not been tampered with during transit.
*   **Authentication:** Users are authenticated, and cryptographic keys are managed to ensure that only authorized users can participate in conversations.


### Technologies Used

**Frontend:**
*   **React:** A JavaScript library for building user interfaces.
*   **TypeScript:** A typed superset of JavaScript that compiles to plain JavaScript.
*   **Vite:** A fast build tool that provides a lightning-fast development experience.
*   **Tailwind CSS:** A utility-first CSS framework for rapidly building custom designs.
*   **Radix UI:** A collection of unstyled, accessible UI components for building high-quality design systems.
*   **Zod:** A TypeScript-first schema declaration and validation library.
*   **React Router DOM:** Declarative routing for React.

**Backend:**
*   **Node.js:** A JavaScript runtime built on Chrome's V8 JavaScript engine.
*   **WebSocket (ws library):** For real-time, bidirectional communication between client and server.
*   **Argon2:** For secure password hashing.

**Cryptography:**
*   **Web Cryptography API:** Browser-native cryptographic operations.
*   **pako:** Zlib port to javascript for compression/decompression.


## Security Features

### Rate Limiting System ✅
A **privacy-first rate limiting system** has been implemented that protects against:
- **Connection flooding** - Prevents rapid connection attempts
- **Authentication brute force** - Limits login attempts per connection  
- **Message spam** - Prevents message flooding by authenticated users
- **Resource exhaustion** - Protects server resources from abuse

**Key Privacy Features:**
- **No IP tracking** - The server doesn't collect or store client IP addresses
- **Connection-based limits** - Rate limits are applied per WebSocket connection
- **User-based limits** - After authentication, limits are applied per username
- **Minimal data collection** - Only essential rate limiting data is stored

### Future Security Plans
I'm fully focused on security and will continue to add:
- Enhanced authentication mechanisms
- Advanced threat detection
- Improved encryption protocols
- Security monitoring and alerting 


## Contributing

Contributions or ideas are welcome. Please feel free to submit a pull request or open an issue if you find bugs or have suggestions for improvements.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.
