# Simple Chat Protocol (SCP) Implementation

This project implements a Simple Chat Protocol (SCP) for real-time text-based communication between two parties over a network. The protocol provides basic chat functionality, including presence detection, message exchange, and connection management. The SCP operates at the application layer of the OSI model, using TCP as the transport layer protocol to ensure reliable, ordered delivery of messages.

## Features

- Message exchange between client and server.
- Presence detection.
- Properly formatted SCP headers.
- Message acknowledgment.
- Goodbye acknowledgment.
- Client disconnection handling.

## Files

- `client.Dockerfile`: Dockerfile for the client program.
- `server.Dockerfile`: Dockerfile for the server program.
- `docker-compose.yml`: Docker Compose file for running the client and server containers.
- `CMakeLists.txt`: CMake configuration file for building the project.
- `README.md`: Project documentation.
- `src`: Directory containing the source code files.
  - `client.c`: The client program that connects to the server and exchanges messages.
  - `server.c`: The server program that listens for incoming connections and handles multiple clients.
  - `common`: Code & headers shared between the server & client.

## Developing with Docker
### Client
With compose: `docker compose run --rm --build client`
Or without: `docker run --rm -it $(docker build -q -f client.Dockerfile .)`

### Server
With compose: `docker compose run --rm --build --name mytestserver server`
Or without: `docker run --name mytestserver --rm -it $(docker build -q -f server.Dockerfile .)`

In both examples, `mytestserver` is the hostname (domain) of the running server container, accessible from other containers.
To find the Server IP, run `docker inspect mytestserver` & look for this
```json
 "Networks": {
                "cs4389-chat-project_chat-network": {
                    "IPAddress": "xxx.xx.x.x",
                }
              }
```

## Developing with Cmake
### Prerequisites

- GCC compiler.
  - Ubuntu: `sudo apt install build-essential`
  - Macos: `xcode-select --install`
- Cmake
  - Ubuntu: `sudo apt install cmake`
  - Macos: `brew install cmake`
- OpenSSL library.
  - Ubuntu: `sudo apt install libssl-dev`
  - Macos: `brew install openssl`
- POSIX-compliant operating system (e.g., Linux, macOS).

### Compilation
Configure the project using CMake & compile the source files:
```bash
cmake -B build -S . && cmake --build build
```

### Running
- `./build/server` to run the server.
- `./build/client` to run the client.


## Usage
### Server
You will be prompted to enter a port number and a server ID. The default port is `4390`, and the default server ID is `default_server`.

Example output:

```
Enter port (default 4390): 4390
Enter server ID (default default_server): chat_server
Server ID: chat_server
Server listening on port 4390
New connection established
Bob connected
New connection established
Sarah connected
Received encrypted message: 6e290aabb120872ab25a804e2c7f61bae522e87077499fa30c2521f53617f8fb
Decrypted message([Sarah]): Hi. Nice to meet you. I'm Sarah
Received MESSAGE from client
Received encrypted message: 6d9795a7f064d415f9ee146c82cf940d679eb43dbda3ebba8beb92c82fe8b09e
Decrypted message([Bob]): Hi Sarah. I'm Bob. How are you?
Received MESSAGE from client
Received encrypted message: 173976dd6ac120e9bfa7973ef1f0729186eee50dd9ed296563a22fb3035c6e5b
Decrypted message([Sarah]): I'm doing good. And you?
Received MESSAGE from client
Received encrypted message: 173976dd6ac120e9bfa7973ef1f072918e73fbd413df71513db80ffacc48b57f7f6bd5fcba743e1ddbbcaaf349474e0b
Decrypted message([Bob]): I'm doing good. Thanks for asking!
Received MESSAGE from client
Received encrypted message: a8d107e652122f5f4f4b10539466747a
Decrypted message([Sarah]): You are welcome
Received MESSAGE from client
Received encrypted message: cc20fb1775bca0c6334046891f2155c1
Decrypted message([Sarah]): Goodbye
Received GOODBYE from client
Received encrypted message: cc20fb1775bca0c6334046891f2155c1
Decrypted message([Bob]): Goodbye
Received GOODBYE from client
```

### Client
You will be prompted to enter the server address, port number, and connection ID. The default server address is `127.0.0.1` (localhost), and the default port is `4390`.

Example output (Client 1 - Bob):

```
Is the server address an IP or domain? (ip/domain): ip
Enter server address (default server): xxx.xx.x.x
Enter port (default 4390): 4390
Enter connection ID: Bob
Enter message: Hi Sarah. I'm Bob. How are you?
Original message: Hi Sarah. I'm Bob. How are you?
Encrypted message: 6d9795a7f064d415f9ee146c82cf940d679eb43dbda3ebba8beb92c82fe8b09e
[20:57:15] Server: Message delivered
Enter message: I'm doing good. Thanks for asking!
Original message: I'm doing good. Thanks for asking!
Encrypted message: 173976dd6ac120e9bfa7973ef1f072918e73fbd413df71513db80ffacc48b57f7f6bd5fcba743e1ddbbcaaf349474e0b
[20:58:20] Server: Message delivered
Enter message: exit
Original message: Goodbye
Encrypted message: cc20fb1775bca0c6334046891f2155c1
[20:58:34] Server: Goodbye acknowledged
```
Example output (Client 2 - Sarah):

```
Is the server address an IP or domain? (ip/domain): ip
Enter server address (default server): xxx.x.x.x
Enter port (default 4390): 4390
Enter connection ID: Sarah
Enter message: Hi. Nice to meet you. I'm Sarah
Original message: Hi. Nice to meet you. I'm Sarah
Encrypted message: 6e290aabb120872ab25a804e2c7f61bae522e87077499fa30c2521f53617f8fb
[20:56:59] Server: Message delivered
Enter message: I'm doing good. And you?
Original message: I'm doing good. And you?
Encrypted message: 173976dd6ac120e9bfa7973ef1f0729186eee50dd9ed296563a22fb3035c6e5b
[20:58:04] Server: Message delivered
Enter message: You are welcome
Original message: You are welcome
Encrypted message: a8d107e652122f5f4f4b10539466747a
[20:58:27] Server: Message delivered
Enter message: exit
Original message: Goodbye
Encrypted message: cc20fb1775bca0c6334046891f2155c1
[20:58:31] Server: Goodbye acknowledged
```

## Protocol Details

- **Protocol Version**: 1
- **Message Types**:
  - `0`: HELLO
  - `1`: MESSAGE
  - `2`: MESSAGE_ACK
  - `3`: GOODBYE
  - `4`: GOODBYE_ACK
- **Header Fields**:
  - `version` (4 bits)
  - `msg_type` (4 bits)
  - `seq_num` (16 bits)
  - `timestamp` (32 bits)
  - `sender_id` (32 bits)
  - `recipient_id` (32 bits)
  - `payload_length` (16 bits)

## Notes

- Ensure the server is running before starting the client.
- Ensure at least two clients are running, so you can chat between them. The clients will be able to see each other's messages, and the server will see the messages and acknowledgments from the client.
- To exit a client, type ".exit" as your message. This will send a GOODBYE message to the server, wait for the
  GOODBYE_ACK, and then close the connection.
- The server sends a MESSAGE_ACK for each message received from a client, which is displayed as "Message delivered" on the client side.
- When a client sends a GOODBYE message, the server responds with a GOODBYE_ACK, which is displayed as "Goodbye acknowledged" on the client side before the connection is closed.
