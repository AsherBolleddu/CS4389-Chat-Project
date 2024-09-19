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

- `server.c`: The server program that listens for incoming connections and handles multiple clients.
- `client.c`: The client program that connects to the server and exchanges messages.

## Prerequisites

- GCC compiler.
  - Ubuntu: `sudo apt install build-essential`
- POSIX-compliant operating system (e.g., Linux, macOS).

## Compilation

### Install OpenSSL
Macos: `brew install openssl`
Ubuntu: `sudo apt install libssl-dev`

### Check the installation path
brew --prefix openssl   
Ex: /opt/homebrew/opt/openssl@3

### Server

To compile the server program, open a terminal and run:

```sh
# gcc server.c -o server.out -lpthread
gcc server.c -o server -I/{installation_path}/include -L/{installation_path}/lib -lssl -lcrypto -pthread
```

### Client

To compile the client program, open a terminal and run:

```sh
# gcc client.c -o client.out -lpthread
gcc client.c -o client -I/{installation_path}/include -L/{installation_path}/lib -lssl -lcrypto -pthread
```

## Execution

### Running the Server

To run the server program, execute the following command in the terminal:

```sh
./server.out
```

You will be prompted to enter a port number and a server ID. The default port is `4390`, and the default server ID is `default_server`.

Example output:

```
Enter port (default 4390): 4390
Enter server ID (default default_server): chat_server
Server ID: chat_server
Server listening on port 4390
New connection established
Alice connected
New connection established
Bob connected
[14:30:15] Alice: Hello, everyone!
[14:30:30] Bob: Hi Alice, nice to meet you!
```

### Running the Client

To run the client program, execute the following command in the terminal:

```sh
./client.out
```

You will be prompted to enter the server address, port number, and connection ID. The default server address is `127.0.0.1` (localhost), and the default port is `4390`.

Example output (Client 1 - Alice):

```
Is the server address an IP or domain? (ip/domain): ip
Enter server address (default 127.0.0.1): 127.0.0.1
Enter port (default 4390): 4390
Enter connection ID: Alice
Enter message: Hello, everyone!
[14:30:15] Server: Message delivered
[14:30:30] Bob: Hi Alice, nice to meet you!
Enter message: How are you doing, Bob?
[14:30:35] Server: Message delivered
[14:31:00] Bob: I'm doing great, thanks for asking!
Enter message: exit
[14:31:30] Server: Goodbye acknowledged
```

Example output (Client 2 - Bob):

```
Is the server address an IP or domain? (ip/domain): ip
Enter server address (default 127.0.0.1): 127.0.0.1
Enter port (default 4390): 4390
Enter connection ID: Bob
[14:30:15] Alice: Hello, everyone!
Enter message: Hi Alice, nice to meet you!
[14:30:30] Server: Message delivered
[14:30:35] Alice: How are you doing, Bob?
Enter message: I'm doing great, thanks for asking!
[14:31:00] Server: Message delivered
[14:31:30] Alice has left the chat
Enter message: exit
[14:32:00] Server: Goodbye acknowledged
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
- To exit a client, type "exit" as your message. This will send a GOODBYE message to the server, wait for the GOODBYE_ACK, and then close the connection.
- The server sends a MESSAGE_ACK for each message received from a client, which is displayed as "Message delivered" on the client side.
- When a client sends a GOODBYE message, the server responds with a GOODBYE_ACK, which is displayed as "Goodbye acknowledged" on the client side before the connection is closed.
