//! Deterministic local-regtest Manager/VAA HTTP service.
//!
//! Operators submit the outputs-only UTX0 payload together with selected
//! custody inputs, transaction outputs, and the exact unsigned transaction.
//! The service validates and signs that operator-built transaction with the
//! deterministic local 5-of-7 Manager set.

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
use serde::{Deserialize, Serialize};

use crate::wormhole::{
    manager::{
        LocalManagerService, LocalSigningInput, LocalWithdrawalRegistration, SignedVaaResponse,
        VaaKey,
    },
    tx::TransactionOutput,
    utx0::UtxoAddressType,
};

#[derive(Debug, Parser)]
#[command(
    name = "local-manager-service",
    about = "LOCAL REGTEST ONLY: validate and sign operator-built Dogecoin withdrawals"
)]
pub struct Args {
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
    unsigned_transaction_hex: String,
    inputs: Vec<SigningInputRequest>,
    outputs: Vec<SigningOutputRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SigningInputRequest {
    original_recipient_address_hex: String,
    transaction_id_hex: String,
    vout: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SigningOutputRequest {
    amount: u64,
    address_type: u32,
    address_hex: String,
}

#[derive(Debug, Serialize)]
struct RegisterWithdrawalResponse {
    sequence: u64,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

pub async fn run(args: Args) -> Result<()> {
    let state = Arc::new(RwLock::new(LocalManagerService::default()));
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind local Manager service to {}", args.listen))?;
    eprintln!(
        "LOCAL REGTEST ONLY: Manager service listening on http://{}",
        listener.local_addr()?
    );
    axum::serve(listener, app(state))
        .await
        .context("serve local Manager HTTP API")
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
                anyhow!("local Manager state lock poisoned"),
            )
        }
    };
    match service.register(registration) {
        Ok(_) => (
            StatusCode::OK,
            Json(RegisterWithdrawalResponse { sequence }),
        )
            .into_response(),
        Err(error) if error.to_string().starts_with("conflicting") => {
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
                anyhow!("local Manager state lock poisoned"),
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
                anyhow!("local Manager state lock poisoned"),
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
    let inputs = request
        .inputs
        .into_iter()
        .enumerate()
        .map(|(index, input)| {
            Ok(LocalSigningInput {
                original_recipient_address: decode_fixed(
                    &format!("inputs[{index}].originalRecipientAddressHex"),
                    &input.original_recipient_address_hex,
                )?,
                transaction_id: decode_fixed(
                    &format!("inputs[{index}].transactionIdHex"),
                    &input.transaction_id_hex,
                )?,
                vout: input.vout,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let outputs = request
        .outputs
        .into_iter()
        .enumerate()
        .map(|(index, output)| {
            Ok(TransactionOutput {
                amount: output.amount,
                address_type: UtxoAddressType::from_u32(output.address_type)?,
                address: decode_fixed(
                    &format!("outputs[{index}].addressHex"),
                    &output.address_hex,
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(LocalWithdrawalRegistration {
        key,
        payload: decode_hex("payloadHex", &request.payload_hex)?,
        unsigned_transaction: decode_hex(
            "unsignedTransactionHex",
            &request.unsigned_transaction_hex,
        )?,
        inputs,
        outputs,
    })
}

fn decode_key(chain: u16, emitter_hex: &str, sequence: u64) -> Result<VaaKey> {
    Ok(VaaKey {
        emitter_chain: chain,
        emitter_address: decode_fixed("emitterAddressHex", emitter_hex)?,
        sequence,
    })
}

fn decode_fixed<const N: usize>(field: &str, value: &str) -> Result<[u8; N]> {
    let bytes = decode_hex(field, value)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("{field} must decode to {N} bytes, got {}", bytes.len()))
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
        http::Request,
    };
    use base64::{engine::general_purpose, Engine as _};
    use tower::ServiceExt;

    use crate::wormhole::{
        manager::{
            fetch_manager_signatures, fetch_signed_vaa, local_regtest_manager_set, parse_vaa,
            verify_manager_signature,
        },
        redeem::build_redeem_script,
        tx::{SelectedUtxo, TransactionOutput, UnsignedTransaction},
        utx0::{Utx0Output, Utx0UnlockPayload, UtxoAddressType},
    };

    fn fixture() -> (Vec<u8>, UnsignedTransaction, serde_json::Value) {
        let payload = Utx0UnlockPayload {
            destination_chain: 65,
            delegated_manager_set_index: 0,
            outputs: vec![Utx0Output {
                amount: 1_000_000,
                address_type: UtxoAddressType::P2pkh,
                address: [0x33; 20],
            }],
        }
        .serialize()
        .unwrap();
        let manager_set = local_regtest_manager_set();
        let recipient = [0x11; 32];
        let transaction_id = [0x22; 32];
        let transaction = UnsignedTransaction::new(
            vec![SelectedUtxo {
                transaction_id,
                vout: 3,
                redeem_script: build_redeem_script(
                    1,
                    &[0x44; 32],
                    &recipient,
                    manager_set.m,
                    &manager_set.pubkeys,
                )
                .unwrap(),
            }],
            vec![TransactionOutput {
                amount: 1_000_000,
                address_type: UtxoAddressType::P2pkh,
                address: [0x33; 20],
            }],
        )
        .unwrap();
        let body = serde_json::json!({
            "emitterChain": 1,
            "emitterAddressHex": hex::encode([0x44; 32]),
            "sequence": 17,
            "payloadHex": hex::encode(&payload),
            "unsignedTransactionHex": hex::encode(transaction.serialize()),
            "inputs": [{
                "originalRecipientAddressHex": hex::encode(recipient),
                "transactionIdHex": hex::encode(transaction_id),
                "vout": 3,
            }],
            "outputs": [{
                "amount": 1_000_000,
                "addressType": 0,
                "addressHex": hex::encode([0x33; 20]),
            }],
        });
        (payload, transaction, body)
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn api_signs_operator_built_transaction() {
        let app = app(Arc::new(RwLock::new(LocalManagerService::default())));
        let (_, transaction, body) = fixture();
        let register = app
            .clone()
            .oneshot(
                Request::post("/api/v1/withdrawals")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(register.status(), StatusCode::OK);

        let emitter_hex = hex::encode([0x44; 32]);
        let response = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/manager/signed_vaa/1/{emitter_hex}/17"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let manager = body_json(response).await;
        assert_eq!(manager["isComplete"], true);
        assert_eq!(manager["signatures"].as_array().unwrap().len(), 5);

        let vaa_response = app
            .oneshot(
                Request::get(format!("/v1/signed_vaa/1/{emitter_hex}/17"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let vaa = general_purpose::STANDARD
            .decode(body_json(vaa_response).await["vaaBytes"].as_str().unwrap())
            .unwrap();
        assert_eq!(parse_vaa(&vaa).unwrap().sequence, 17);
        assert_eq!(transaction.input_count(), 1);
    }

    #[tokio::test]
    async fn live_fetch_clients_receive_verifiable_signatures() {
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
        let (_, transaction, body) = fixture();
        assert!(client
            .post(format!("{base_url}/api/v1/withdrawals"))
            .json(&body)
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
        let emitter = [0x44; 32];
        let signatures = fetch_manager_signatures(&client, &base_url, 1, &emitter, 17)
            .await
            .unwrap();
        assert!(signatures.is_complete);
        assert_eq!(signatures.signatures.len(), 5);
        let vaa = fetch_signed_vaa(&client, &base_url, 1, &emitter, 17)
            .await
            .unwrap();
        assert_eq!(parse_vaa(&vaa).unwrap().sequence, 17);

        let manager_set = local_regtest_manager_set();
        for signer in signatures.signatures {
            assert!(verify_manager_signature(
                &manager_set.pubkeys[signer.signer_index as usize],
                &transaction.sighash_all(0).unwrap(),
                &signer.input_signatures[0],
            )
            .unwrap());
        }
        server.abort();
    }

    #[tokio::test]
    async fn rejects_transaction_that_does_not_match_authorized_outputs() {
        let (_, _, mut body) = fixture();
        body["outputs"][0]["amount"] = serde_json::json!(2_000_000);
        let response = app(Arc::new(RwLock::new(LocalManagerService::default())))
            .oneshot(
                Request::post("/api/v1/withdrawals")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
