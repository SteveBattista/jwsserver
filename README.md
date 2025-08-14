# JWS Server

A Rust-based HTTP server that signs JSON payloads as JSON Web Signatures (JWS) and verifies them. It uses RSA keys stored as PEM files and exposes simple REST endpoints plus a small web demo.

## Features

- Sign arbitrary JSON into a compact JWS
- Verify a JWS against the original JSON and a provided public key
- Auto-generate RSA keypair on first run (4096-bit)
- Simple web demo at /demo
- Returns public key with each signature
- Verification tolerates missing `exp` claim by returning valid with a warning

## Quick start

```bash
# Run the server (dev)
cargo run
```

Then open <http://127.0.0.1:5000/demo> in your browser.

## API

### POST /sign

Signs a JSON object and returns the JWS, the original JSON, and the public key used.

Request body (any JSON object):

```json
{ "foo": "bar" }
```

Response:

```json
{
  "jws": "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9...",
  "json": { "foo": "bar" },
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
}
```

### POST /verify

Verifies a JWS using the provided public key and compares the decoded payload to the provided JSON.

Request body:

```json
{
  "jws": "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9...",
  "json": { "foo": "bar" },
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
}
```

Response (success):

```json
{ "valid": true, "error": null }
```

Response (payload mismatch):

```json
{ "valid": false, "error": "Payload does not match" }
```

Response (missing exp claim tolerated):

```json
{ "valid": true, "error": "Signature valid, but 'exp' claim is missing or not checked." }
```

### GET /demo

Serves the interactive HTML demo page.

### GET /well-known/public.pem

Serves the current public key in PEM format for signature verification.

**Response:**

```text
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA...
-----END PUBLIC KEY-----
```

## Keys and algorithms

- On first run, a 4096-bit RSA keypair is generated and saved to:
  - private_key.pem
  - public_key.pem
- Current signing algorithm: RS512 (RSA with SHA-512)
- The public key is returned by /sign so clients can verify.
- The public key is also available at /well-known/public.pem for automated discovery.

## Demo usage

1. Open /demo
2. Enter JSON and click "Sign JSON"
3. The page shows the JWS, original JSON, and the public key
4. Click "Check JWS" to verify using the returned public key

## Troubleshooting

- Signature is invalid
  - Ensure the public_key.pem matches the private_key.pem used to sign
  - Re-run, re-sign, and then verify using the public key returned by /sign or from /well-known/public.pem
- Network error or JSON errors
  - Check server logs and ensure the request/response bodies are valid JSON

## Development

- Rust edition: 2024
- Notable dependencies: axum, tokio, jsonwebtoken, serde, rsa

## License

Provided as-is for educational and development use.
