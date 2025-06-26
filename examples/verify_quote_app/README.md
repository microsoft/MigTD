# MigTD Quote Verification App with Networking

This application demonstrates MigTD quote verification with added networking capabilities, allowing two instances to communicate and exchange quotes and verification results.

## Features

- **Standalone Mode**: Original quote verification functionality
- **Server Mode**: Listens for connections and processes quote verification requests
- **Client Mode**: Connects to servers to send/receive quotes and verification results
- **Cross-machine Communication**: Works between different machines and on the same machine
- **Asynchronous Networking**: Uses Tokio for efficient async I/O

## Build

```bash
cd examples/verify_quote_app
cargo build --release
```

## Usage

### 1. Standalone Mode (Original Behavior)

Run the original quote verification demonstration:

```bash
./target/release/verify_quote_app standalone
```

### 2. Server Mode

Start a server that can verify quotes sent by clients:

```bash
# Listen on default port 8080
./target/release/verify_quote_app server

# Listen on specific port and address
./target/release/verify_quote_app server --port 9000 --bind 0.0.0.0
```

### 3. Client Mode

Connect to a server to exchange quotes:

```bash
# Send your quote to server for verification
./target/release/verify_quote_app client --send-quote

# Request server's quote and verify it locally
./target/release/verify_quote_app client --request-quote

# Do both operations
./target/release/verify_quote_app client --send-quote --request-quote

# Connect to specific server
./target/release/verify_quote_app client --server 192.168.1.100 --port 9000 --send-quote
```

## Network Protocol

The application uses a simple JSON-based protocol over TCP:

- **Message Format**: 4-byte length prefix + JSON payload
- **Message Types**:
  - `Ping/Pong`: Connection testing
  - `QuoteRequest/QuoteResponse`: Request and receive quotes
  - `VerifyQuote`: Send quote for verification
  - `VerificationResult`: Return verification results

## Example Usage Scenarios

### Same Machine Communication

Terminal 1 (Server):
```bash
./target/release/verify_quote_app server --port 8080
```

Terminal 2 (Client):
```bash
./target/release/verify_quote_app client --send-quote --request-quote
```

### Cross-Machine Communication

Machine A (Server):
```bash
./target/release/verify_quote_app server --bind 0.0.0.0 --port 8080
```

Machine B (Client):
```bash
./target/release/verify_quote_app client --server <machine-a-ip> --port 8080 --send-quote
```

### Bidirectional Verification

Each machine can run both server and client to verify each other's quotes:

Machine A:
```bash
# Terminal 1: Run server
./target/release/verify_quote_app server --port 8080

# Terminal 2: Connect to Machine B as client
./target/release/verify_quote_app client --server <machine-b-ip> --port 8081 --send-quote
```

Machine B:
```bash
# Terminal 1: Run server
./target/release/verify_quote_app server --port 8081

# Terminal 2: Connect to Machine A as client
./target/release/verify_quote_app client --server <machine-a-ip> --port 8080 --send-quote
```

## Command Line Options

### Server Mode
- `--port, -p`: Port to listen on (default: 8080)
- `--bind, -b`: Bind address (default: 127.0.0.1)

### Client Mode  
- `--server, -s`: Server address to connect to (default: 127.0.0.1)
- `--port, -p`: Server port to connect to (default: 8080)
- `--send-quote`: Send your quote to server for verification
- `--request-quote`: Request server's quote and verify it locally

## Security Considerations

- The current implementation uses sample/mock quotes for demonstration
- In production, replace with real quote generation and verification
- Consider adding TLS encryption for network communication
- Implement proper authentication and authorization
- Validate all network inputs thoroughly

## Dependencies

- `tokio`: Async runtime for networking
- `serde`: Serialization for network messages  
- `serde_json`: JSON encoding/decoding
- `clap`: Command line argument parsing
- `hex`: Hexadecimal encoding for display

## Hardware Requirements

Same as the original application:
1. Intel processor with SGX/TDX support
2. Linux kernel with SGX/TDX drivers
3. BIOS with SGX/TDX enabled
4. libservtd_attest.a properly compiled and linked

## Network Requirements

- TCP connectivity between machines
- Firewall rules allowing traffic on chosen ports
- For cross-machine: machines must be on same network or have routing configured
