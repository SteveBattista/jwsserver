# JWS Server

A Rust-based HTTP server for signing JSON objects using JSON Web Signatures (JWS) with RSA asymmetric cryptography.

## Features

- **JSON Signing**: Sign JSON objects using JWS with RS512 algorithm
- **Signature Verification**: Verify JWS signatures against JSON payloads
- **RSA Key Management**: Automatic generation and storage of RSA keypairs
- **Web Demo Interface**: Interactive HTML page for testing signing and verification
- **RESTful API**: Clean HTTP endpoints for integration

## Prerequisites

- Rust 1.70+ with Cargo
- Modern web browser for the demo interface

## Installation

1. Clone or download this project
2. Navigate to the project directory
3. Build and run:

```bash
cargo run
```

The server will start on `http://127.0.0.1:5000`

## API Endpoints

### POST /sign

Signs a JSON object and returns the JWS along with the public key.

**Request:**

```json
{
  "foo": "bar",
  "data": "example"
}
```

**Response:**

```json
{
  "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9...",
  "json": {"foo": "bar", "data": "example"},
  "public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

### POST /verify

Verifies a JWS signature against a JSON payload using a public key.

**Request:**

```json
{
  "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9...",
  "json": {"foo": "bar", "data": "example"},
  "public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

**Response:**

```json
{
  "valid": true,
  "error": null
}
```

### GET /demo

Serves the interactive HTML demo page for testing the signing and verification functionality.

## Usage

### Web Demo

1. Start the server with `cargo run`
2. Open `http://127.0.0.1:5000/demo` in your browser
3. Enter JSON in the text area and click "Sign JSON"
4. Use "Check JWS" to verify the signature

### Programmatic Usage

Use the `/sign` and `/verify` endpoints with HTTP POST requests as shown in the API documentation above.

## Key Management

- RSA keypairs are automatically generated on first run
- Private key is stored in `private_key.pem`
- Public key is stored in `public_key.pem`
- Keys are 4096-bit RSA keys for enhanced security

## Security Features

- RS512 algorithm (RSA with SHA-512)
- 4096-bit RSA keys
- Automatic key generation and validation
- Signature verification includes payload matching
- Graceful handling of missing `exp` claims

## Configuration

The server runs on `127.0.0.1:5000` by default. To change the address or port, modify the `main()` function in `src/main.rs`.

## Dependencies

- **axum**: Modern async HTTP server framework
- **jsonwebtoken**: JWS/JWT creation and verification
- **rsa**: RSA cryptography operations
- **serde**: JSON serialization/deserialization
- **tokio**: Async runtime

## License

This project is provided as-is for educational and development purposes.
