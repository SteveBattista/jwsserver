
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
    jws: String
}

#[derive(Debug, Error)]
enum ServerError {
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> axum::response::Response {
        let msg = self.to_string();
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": msg})),
        )
            .into_response()
    }
}

async fn sign_json(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<InputPayload>,
) -> Result<Json<SignedResponse>, ServerError> {
    let header = Header::new(Algorithm::RS256);
    let jws = encode(&header, &payload.data, &state.encoding_key)?;
    Ok(Json(SignedResponse { jws }))
}

struct AppState {
    encoding_key: EncodingKey,
}


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
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 5000));
    println!("Listening on http://{}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

/// Generate a 2048-bit RSA keypair, save to priv/pub files, and return (priv_pem, pub_pem)
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

