//! Deterministic local-regtest Manager/VAA HTTP service.
//!
//! This binary embeds known private keys and MUST NOT be exposed to a public
//! network or used with funds outside an isolated Dogecoin regtest.

use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use doge_local_ops::wormhole::manager::{
    LocalManagerService, LocalWithdrawalRegistration, SignedVaaResponse, VaaKey,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
#[command(
    name = "local-manager-service",
    about = "LOCAL REGTEST ONLY: synthesize UTX0 VAAs and deterministic manager signatures"
)]
struct Args {
    /// Listen address. Keep this loopback-only unless the surrounding network is isolated.
    #[arg(long, default_value = "127.0.0.1:7071")]
    listen: SocketAddr,
}

type SharedState = Arc<RwLock<LocalManagerService>>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegisterWithdrawalRequest {
    emitter_chain: u16,
    emitter_address_hex: String,
    sequence: u64,
    payload_hex: String,
}

#[derive(Debug, Serialize)]
struct RegisterWithdrawalResponse {
    sequence: u64,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let state = Arc::new(RwLock::new(LocalManagerService::default()));
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind local manager service to {}", args.listen))?;

    eprintln!(
        "LOCAL REGTEST ONLY: manager service listening on http://{}",
        listener.local_addr()?
    );
    axum::serve(listener, app(state))
        .await
        .context("serve local manager HTTP API")
}

fn app(state: SharedState) -> Router {
    Router::new()
        .route("/api/v1/withdrawals", post(register_withdrawal))
        .route(
            "/v1/manager/signed_vaa/{chain}/{emitter}/{sequence}",
            get(get_manager_signatures),
        )
        .route(
            "/v1/signed_vaa/{chain}/{emitter}/{sequence}",
            get(get_signed_vaa),
        )
        .with_state(state)
}

async fn register_withdrawal(
    State(state): State<SharedState>,
    Json(request): Json<RegisterWithdrawalRequest>,
) -> Response {
    let registration = match decode_registration(request) {
        Ok(registration) => registration,
        Err(error) => return api_error(StatusCode::BAD_REQUEST, error),
    };
    let sequence = registration.key.sequence;

    let mut service = match state.write() {
        Ok(service) => service,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                anyhow!("local manager state lock poisoned"),
            )
        }
    };
    match service.register(registration) {
        Ok(_) => (
            StatusCode::OK,
            Json(RegisterWithdrawalResponse { sequence }),
        )
            .into_response(),
        Err(error) if error.to_string().starts_with("conflicting payload") => {
            api_error(StatusCode::CONFLICT, error)
        }
        Err(error) => api_error(StatusCode::BAD_REQUEST, error),
    }
}

async fn get_manager_signatures(
    State(state): State<SharedState>,
    Path((chain, emitter, sequence)): Path<(u16, String, u64)>,
) -> Response {
    let key = match decode_key(chain, &emitter, sequence) {
        Ok(key) => key,
        Err(error) => return api_error(StatusCode::BAD_REQUEST, error),
    };
    let service = match state.read() {
        Ok(service) => service,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                anyhow!("local manager state lock poisoned"),
            )
        }
    };
    match service.get(&key) {
        Some(withdrawal) => Json(withdrawal.manager_signatures.response()).into_response(),
        None => api_error(
            StatusCode::NOT_FOUND,
            anyhow!("withdrawal is not registered"),
        ),
    }
}

async fn get_signed_vaa(
    State(state): State<SharedState>,
    Path((chain, emitter, sequence)): Path<(u16, String, u64)>,
) -> Response {
    let key = match decode_key(chain, &emitter, sequence) {
        Ok(key) => key,
        Err(error) => return api_error(StatusCode::BAD_REQUEST, error),
    };
    let service = match state.read() {
        Ok(service) => service,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                anyhow!("local manager state lock poisoned"),
            )
        }
    };
    match service.get(&key) {
        Some(withdrawal) => Json(SignedVaaResponse::new(&withdrawal.signed_vaa)).into_response(),
        None => api_error(
            StatusCode::NOT_FOUND,
            anyhow!("withdrawal is not registered"),
        ),
    }
}

fn decode_registration(request: RegisterWithdrawalRequest) -> Result<LocalWithdrawalRegistration> {
    let key = decode_key(
        request.emitter_chain,
        &request.emitter_address_hex,
        request.sequence,
    )?;
    let payload = decode_hex("payloadHex", &request.payload_hex)?;
    Ok(LocalWithdrawalRegistration { key, payload })
}

fn decode_key(chain: u16, emitter_hex: &str, sequence: u64) -> Result<VaaKey> {
    let emitter = decode_hex("emitterAddressHex", emitter_hex)?;
    let emitter_address: [u8; 32] = emitter.try_into().map_err(|bytes: Vec<u8>| {
        anyhow!(
            "emitterAddressHex must decode to 32 bytes, got {}",
            bytes.len()
        )
    })?;
    Ok(VaaKey {
        emitter_chain: chain,
        emitter_address,
        sequence,
    })
}

fn decode_hex(field: &str, value: &str) -> Result<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|error| anyhow!("invalid {field}: {error}"))
}

fn api_error(status: StatusCode, error: anyhow::Error) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: error.to_string(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use base64::{engine::general_purpose, Engine as _};
    use doge_local_ops::wormhole::{
        manager::{
            fetch_manager_signatures, fetch_signed_vaa, local_regtest_manager_set,
            parse_manager_signatures, parse_vaa, verify_manager_signature,
        },
        redeem::build_redeem_script,
        tx::UnsignedTransaction,
        utx0::{Utx0Input, Utx0Output, Utx0UnlockPayload, UtxoAddressType},
    };
    use serde_json::Value;
    use tower::ServiceExt;

    fn payload() -> Vec<u8> {
        Utx0UnlockPayload {
            destination_chain: 65,
            delegated_manager_set_index: 0,
            inputs: vec![Utx0Input {
                original_recipient_address: [0x11; 32],
                transaction_id: [0x22; 32],
                vout: 3,
            }],
            outputs: vec![Utx0Output {
                amount: 1_000_000,
                address_type: UtxoAddressType::P2pkh,
                address: vec![0x33; 20],
            }],
        }
        .serialize()
        .unwrap()
    }

    fn registration_body(payload: &[u8]) -> String {
        serde_json::json!({
            "emitterChain": 1,
            "emitterAddressHex": hex::encode([0x44; 32]),
            "sequence": 17,
            "payloadHex": hex::encode(payload),
        })
        .to_string()
    }

    async fn body_json(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn api_returns_parseable_vaa_and_verifiable_signatures() {
        let app = app(Arc::new(RwLock::new(LocalManagerService::default())));
        let payload_bytes = payload();
        let register = app
            .clone()
            .oneshot(
                Request::post("/api/v1/withdrawals")
                    .header("content-type", "application/json")
                    .body(Body::from(registration_body(&payload_bytes)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(register.status(), StatusCode::OK);
        assert_eq!(body_json(register).await["sequence"], 17);

        let emitter_hex = hex::encode([0x44; 32]);
        let vaa_response = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/signed_vaa/1/{emitter_hex}/17"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(vaa_response.status(), StatusCode::OK);
        let vaa_json = body_json(vaa_response).await;
        let vaa = general_purpose::STANDARD
            .decode(vaa_json["vaaBytes"].as_str().unwrap())
            .unwrap();
        let parsed = parse_vaa(&vaa).unwrap();
        assert_eq!(parsed.payload, payload_bytes);

        let manager_response = app
            .oneshot(
                Request::get(format!("/v1/manager/signed_vaa/1/{emitter_hex}/17"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(manager_response.status(), StatusCode::OK);
        let manager_json = body_json(manager_response).await;
        let signatures = parse_manager_signatures(&manager_json.to_string()).unwrap();

        let payload = Utx0UnlockPayload::parse(&parsed.payload).unwrap();
        let manager_set = local_regtest_manager_set();
        let scripts = payload
            .inputs
            .iter()
            .map(|input| {
                build_redeem_script(
                    parsed.emitter_chain,
                    &parsed.emitter_address,
                    &input.original_recipient_address,
                    manager_set.m,
                    &manager_set.pubkeys,
                )
            })
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let tx = UnsignedTransaction::from_utx0(&payload, scripts).unwrap();
        for signer in signatures.signatures {
            for (input_index, signature) in signer.input_signatures.iter().enumerate() {
                assert!(verify_manager_signature(
                    &manager_set.pubkeys[signer.signer_index as usize],
                    &tx.sighash_all(input_index).unwrap(),
                    signature,
                )
                .unwrap());
            }
        }
    }

    #[tokio::test]
    async fn live_server_is_compatible_with_existing_fetch_clients() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app(Arc::new(RwLock::new(LocalManagerService::default()))),
            )
            .await
            .unwrap();
        });
        let base_url = format!("http://{address}");
        let client = reqwest::Client::new();
        let payload_bytes = payload();

        let registration = client
            .post(format!("{base_url}/api/v1/withdrawals"))
            .header("content-type", "application/json")
            .body(registration_body(&payload_bytes))
            .send()
            .await
            .unwrap();
        assert_eq!(registration.status(), StatusCode::OK);

        let emitter = [0x44; 32];
        let signatures = fetch_manager_signatures(&client, &base_url, 1, &emitter, 17)
            .await
            .unwrap();
        let vaa = fetch_signed_vaa(&client, &base_url, 1, &emitter, 17)
            .await
            .unwrap();
        assert_eq!(parse_vaa(&vaa).unwrap().payload, payload_bytes);
        assert!(signatures.is_complete);
        assert_eq!(signatures.signatures.len(), 5);

        server.abort();
    }
    #[tokio::test]
    async fn duplicate_conflicting_registration_is_rejected() {
        let app = app(Arc::new(RwLock::new(LocalManagerService::default())));
        let payload_bytes = payload();
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/api/v1/withdrawals")
                        .header("content-type", "application/json")
                        .body(Body::from(registration_body(&payload_bytes)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let mut conflicting = payload_bytes;
        let last = conflicting.len() - 1;
        conflicting[last] ^= 1;
        let response = app
            .oneshot(
                Request::post("/api/v1/withdrawals")
                    .header("content-type", "application/json")
                    .body(Body::from(registration_body(&conflicting)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}
