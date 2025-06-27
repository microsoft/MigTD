# MigTD Quote Verification App with Networking

This application demonstrates MigTD quote verification with added networking capabilities, allowing two instances to communicate and exchange quotes and verification results.

## Quick Start

```bash
# Build the application
cd examples/verify_quote_app
cargo build --release

# Run standalone mode (requires sudo for TPM access)
sudo ./target/release/verify_quote_app standalone

# Or run network modes (no sudo required)
./target/release/verify_quote_app server
./target/release/verify_quote_app client --send-quote
```

**⚠️ Important**: Standalone and Azure modes require `sudo` for TPM access. Server/Client modes do not require elevated privileges.

## Features

- **Standalone Mode**: Original quote verification functionality with real collateral support
- **Server Mode**: Listens for connections and processes quote verification requests
- **Client Mode**: Connects to servers to send/receive quotes and verification results
- **Cross-machine Communication**: Works between different machines and on the same machine
- **Asynchronous Networking**: Uses Tokio for efficient async I/O
- **Real Collateral Support**: Uses real collateral.bin and quote.bin files from mikbras/tdtools
- **Azure TDX Integration**: Full support for Azure TDX CVM attestation via az-tdx-vtpm crate

## Build

```bash
cd examples/verify_quote_app
cargo build --release
```

## Usage

### 1. Standalone Mode (Original Behavior)

Run the original quote verification demonstration:

```bash
# Note: Standalone mode requires sudo for TPM access
sudo ./target/release/verify_quote_app standalone
```

**⚠️ Important**: Standalone mode requires `sudo` privileges because it needs direct access to the TPM (Trusted Platform Module) device for real attestation operations.

### 4. Azure TDX Mode

Run Azure TDX CVM demonstration (also requires sudo for TPM access):

```bash
# Note: Azure TDX mode also requires sudo for TPM access
sudo ./target/release/verify_quote_app azure
```

This mode demonstrates real Azure TDX attestation features using the az-tdx-vtpm crate.

## Real Collateral and Quote Files

The application now includes real collateral and quote files from the [mikbras/tdtools](https://github.com/mikbras/tdtools) repository:

- **collateral.bin** (13,543 bytes): Real Intel TDX collateral data including certificates, CRLs, and TCB information
- **quote.bin** (5,006 bytes): Real TDX quote for verification testing
- **samples/**: Directory containing additional collateral files in various formats

The application automatically detects and uses these files in the following priority order:

1. **Azure TDX vTPM**: Real-time attestation data from Azure TDX CVM (requires sudo)
2. **Real collateral/quote files**: Static real files from mikbras/tdtools
3. **Mock data**: Fallback mock data for testing when real files are not available

### File Loading Paths

The application searches for files in this order:
- `./collateral.bin` and `./quote.bin` (current directory)
- `../collateral.bin` and `../quote.bin` (parent directory)
- `/tmp/collateral.bin` and `/tmp/quote.bin` (temp directory)
- `samples/collateral.bin` and `samples/quote.bin` (samples directory)

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

- **Standalone mode requires sudo**: TPM access for real attestation requires elevated privileges
- The current implementation uses real Azure TDX attestation via az-tdx-vtpm crate
- In production, consider adding TLS encryption for network communication
- Implement proper authentication and authorization
- Validate all network inputs thoroughly
- Only run with sudo when necessary (standalone mode) - network modes don't require elevated privileges

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

**For standalone mode only**:
- Direct TPM access (requires sudo)
- Azure TDX CVM environment for full attestation features

## Network Requirements

- TCP connectivity between machines
- Firewall rules allowing traffic on chosen ports
- For cross-machine: machines must be on same network or have routing configured
