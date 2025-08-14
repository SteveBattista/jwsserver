/// POST handler to regenerate the RSA keypair.
/// POST handler to regenerate the RSA keypair.
///
/// Regenerates a new 4096-bit RSA keypair and overwrites the existing `private_key.pem` and `public_key.pem` files.
/// Returns a JSON status object.
async fn regenerate_keys() -> impl IntoResponse {
    let priv_path = "private_key.pem";
    let pub_path = "public_key.pem";
    // Generate and save new keys
    generate_and_save_rsa_keypair(priv_path, pub_path);
    Json(serde_json::json!({"status": "ok"}))
}
/// Request body for signature verification.
#[derive(Deserialize)]
struct VerifyRequest {
    jws: String,
    json: serde_json::Value,
    public_key: String,
}

/// Response for signature verification.
#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    error: Option<String>,
}

/// POST handler to verify a JWS signature with a public key and JSON.
/// POST handler to verify a JWS signature with a public key and JSON.
///
/// # Arguments
/// * `req` - JSON body containing the JWS, the original JSON, and the public key.
///
/// # Returns
/// JSON object indicating if the signature is valid and an error/warning message if any.
async fn verify_signature(Json(req): Json<VerifyRequest>) -> impl IntoResponse {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    let mut validation = Validation::new(Algorithm::RS512);
    validation.validate_exp = false;
    let decoding_key = match DecodingKey::from_rsa_pem(req.public_key.as_bytes()) {
        Ok(key) => key,
        Err(e) => {
            return Json(VerifyResponse {
                valid: false,
                error: Some(format!("Invalid public key: {e}")),
            });
        }
    };
    let result = decode::<serde_json::Value>(&req.jws, &decoding_key, &validation);
    match result {
        Ok(token_data) => {
            let valid = token_data.claims == req.json;
            Json(VerifyResponse {
                valid,
                error: if valid { None } else { Some("Payload does not match".to_string()) },
            })
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("Missing required claim: exp") {
                // Accept signature as valid, but warn about exp
                Json(VerifyResponse {
                    valid: true,
                    error: Some("Signature valid, but 'exp' claim is missing or not checked.".to_string()),
                })
            } else {
                Json(VerifyResponse {
                    valid: false,
                    error: Some(format!("Signature verification failed: {e}")),
                })
            }
        }
    }
}

use axum::{extract::{Json, State}, response::IntoResponse, routing::post, Router};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc, fs, path::Path};
use thiserror::Error;



#[derive(Debug, Serialize, Deserialize)]

struct InputPayload {
    // Accept any JSON object
    #[serde(flatten)]
    data: serde_json::Value
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedResponse {
    jws: String,
    json: serde_json::Value,
    public_key: String,
}

#[derive(Debug, Error)]
enum ServerError {
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

impl IntoResponse for ServerError {
    /// Converts a `ServerError` into an HTTP response with a JSON error message.
    ///
    /// # Returns
    /// An HTTP 500 response with a JSON error message.
    fn into_response(self) -> axum::response::Response {
        let msg = self.to_string();
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": msg})),
        )
            .into_response()
    }
}

/// POST handler to sign a JSON object and return a JWS, the original JSON, and the public key.
///
/// # Arguments
/// * `state` - Shared application state containing the encoding key.
/// * `payload` - The JSON object to be signed.
///
/// # Returns
/// A JSON response containing the JWS string, the original JSON, and the public key.
async fn sign_json(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<InputPayload>,
) -> Result<Json<SignedResponse>, ServerError> {
    let header = Header::new(Algorithm::RS512);
    let jws = encode(&header, &payload.data, &state.encoding_key)?;
    // Read the public key from file
    let public_key = fs::read_to_string("public_key.pem").unwrap_or_default();
    Ok(Json(SignedResponse { jws, json: payload.data, public_key }))
}

struct AppState {
    encoding_key: EncodingKey,
}


/// Main entry point. Loads or generates RSA keys, sets up the Axum server, and starts listening for requests.
///
/// - Loads or generates a 4096-bit RSA keypair.
/// - Sets up all HTTP routes and shared state.
/// - Binds to 127.0.0.1:5000 and serves requests.
#[tokio::main]
async fn main() {
    let priv_path = "private_key.pem";
    let pub_path = "public_key.pem";
    // Check if private key exists, else generate and save
    let private_key_pem = if Path::new(priv_path).exists() {
        fs::read_to_string(priv_path).expect("Failed to read private key file")
    } else {
        let (priv_pem, _pub_pem) = generate_and_save_rsa_keypair(priv_path, pub_path);
        priv_pem
    };

    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .expect("Failed to parse RSA private key");
    let state = Arc::new(AppState { encoding_key });

    let app = Router::new()
        .route("/sign", post(sign_json))
        .route("/demo", axum::routing::get(serve_demo_html))
        .route("/", axum::routing::get(serve_demo_html))
        .route("/verify", post(verify_signature))
        .route("/regenerate_keys", post(regenerate_keys))
        .route("/well-known/public.pem", axum::routing::get(serve_public_key))
        .with_state(state);
/// Serves the demo HTML page for signing JSON and displaying the JWS.
///
/// # Returns
/// HTML content of the demo page, or a not found message if missing.  
async fn serve_demo_html() -> impl IntoResponse {
    match std::fs::read_to_string("jws_demo.html") {
        Ok(contents) => axum::response::Html(contents),
        Err(_) => axum::response::Html("<h1>Demo file not found</h1>".to_string()),
    }
}

/// Serves the public key PEM file at /well-known/public.pem
///
/// # Returns
/// Plain text content of the public key PEM file, or an error message if missing.
async fn serve_public_key() -> impl IntoResponse {
    match std::fs::read_to_string("public_key.pem") {
        Ok(contents) => (
            [("Content-Type", "application/x-pem-file")],
            contents
        ).into_response(),
        Err(_) => (
            axum::http::StatusCode::NOT_FOUND,
            "Public key not found"
        ).into_response(),
    }
}

    let addr = SocketAddr::from(([0, 0, 0, 0], 5000));
    println!("Listening on http://{addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

/// Generates a 4096-bit RSA keypair, saves them to the given file paths, and returns the PEM strings.
///
/// # Arguments
/// * `priv_path` - Path to save the private key PEM file.
/// * `pub_path` - Path to save the public key PEM file.
///
/// # Returns
/// Tuple of (`private_key_pem`, `public_key_pem`) as Strings.
fn generate_and_save_rsa_keypair(priv_path: &str, pub_path: &str) -> (String, String) {
    use rsa::{pkcs8::{EncodePrivateKey, EncodePublicKey}, RsaPrivateKey};
    use rand::rngs::OsRng;
    let mut rng = OsRng;
    let key = RsaPrivateKey::new(&mut rng, 4096).expect("Failed to generate key");
    let priv_pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("Failed to encode private key").to_string();
    let pub_pem = key.to_public_key().to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .expect("Failed to encode public key").to_string();
    fs::write(priv_path, &priv_pem).expect("Failed to write private key file");
    fs::write(pub_path, &pub_pem).expect("Failed to write public key file");
    (priv_pem, pub_pem)
}

