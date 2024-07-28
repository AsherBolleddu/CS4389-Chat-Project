---

# Simple Chat Protocol (SCP) Implementation

This project implements a Simple Chat Protocol (SCP) for real-time text-based communication between two parties over a network. The protocol provides basic chat functionality, including presence detection, message exchange, and connection management. The SCP operates at the application layer of the OSI model, using TCP as the transport layer protocol to ensure reliable, ordered delivery of messages.

## Features

- Message exchange between client and server.
- Presence detection.
- Properly formatted SCP headers.
- Message acknowledgment.
- Client disconnection handling.

## Files

- `server.c`: The server program that listens for incoming connections and handles multiple clients.
- `client.c`: The client program that connects to the server and exchanges messages.

## Prerequisites

- GCC compiler.
- POSIX-compliant operating system (e.g., Linux, macOS).

## Compilation

### Server

To compile the server program, open a terminal and run:

```sh
gcc server.c -o server.out -lpthread
```

### Client

To compile the client program, open a terminal and run:

```sh
gcc client.c -o client.out
```

## Execution

### Running the Server

To run the server program, execute the following command in the terminal:

```sh
./server.out
```

You will be prompted to enter a port number and a server ID. The default port is `4390`, and the default server ID is `default_server`.

### Running the Client

To run the client program, execute the following command in the terminal:

```sh
./client.out
```

You will be prompted to enter the server address, port number, and connection ID. The default server address is `127.0.0.1` (localhost), and the default port is `4390`.

### Example Interaction

1. **Start the server**:

   ```
   $ ./server.out
   Enter port (default 4390): 4390
   Enter server ID (default default_server): my_server
   Server ID: my_server
   Server listening on port 4390
   ```

2. **Start the client**:

   ```
   $ ./client.out
   Enter server address (default 127.0.0.1): 127.0.0.1
   Enter port (default 4390): 4390
   Enter connection ID: client1
   ```

3. **Client sends a message**:

   ```
   Enter message: Hello, server!
   ```

4. **Server receives the message and responds**:

   ```
   New connection established
   client1 connected
   [14:07:55] client1: Hello, server!
   ```

5. **Client receives the response**:

   ```
   [14:07:55] Server: hello from server
   ```

6. **Client exits**:

   ```
   Enter message: exit
   ```

7. **Server logs the disconnection**:
   ```
   client1 disconnected
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
- Multiple clients can connect to the server and communicate simultaneously.
