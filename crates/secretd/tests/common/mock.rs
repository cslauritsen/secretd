#![allow(dead_code)]
//! Mock ntfy/webhook receiver and mock OIDC provider (local issuer with a
//! test JWKS).  The RSA keys under `keys/` are throwaway test keys.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ------------------------------------------------------------------ ntfy

#[derive(Debug, Clone)]
pub struct Received {
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Received {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[derive(Default)]
pub struct NtfyState {
    pub received: Mutex<Vec<Received>>,
    /// Respond 500 to this many requests before succeeding (u32::MAX = always).
    pub fail_first: Mutex<u32>,
}

pub struct MockNtfy {
    pub url: String,
    pub state: Arc<NtfyState>,
}

impl MockNtfy {
    pub async fn start(fail_first: u32) -> MockNtfy {
        let state = Arc::new(NtfyState {
            received: Mutex::new(Vec::new()),
            fail_first: Mutex::new(fail_first),
        });
        async fn handler(
            State(st): State<Arc<NtfyState>>,
            headers: HeaderMap,
            body: axum::body::Bytes,
        ) -> impl IntoResponse {
            let hm = headers
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            st.received.lock().unwrap().push(Received {
                headers: hm,
                body: body.to_vec(),
            });
            let mut f = st.fail_first.lock().unwrap();
            if *f > 0 {
                if *f != u32::MAX {
                    *f -= 1;
                }
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
            StatusCode::OK
        }
        let app = Router::new()
            .route("/secretd-alerts", post(handler))
            .with_state(state.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(l, app).await.unwrap();
        });
        MockNtfy {
            url: format!("http://{addr}/secretd-alerts"),
            state,
        }
    }

    pub fn received(&self) -> Vec<Received> {
        self.state.received.lock().unwrap().clone()
    }
}

// ------------------------------------------------------------------ OIDC

pub const KEY_A: &str = include_str!("keys/key_a.pem");
pub const KEY_B: &str = include_str!("keys/key_b.pem");
pub const JWK_A: &str = include_str!("keys/jwk_a.json");
pub const CLIENT_ID: &str = "client-abc";

/// What the mock token endpoint returns for one authorization code.
#[derive(Clone)]
pub struct Plan {
    pub claims: Value,
    /// Sign with key B (not in the JWKS) instead of key A.
    pub bad_signature: bool,
}

#[derive(Default)]
pub struct OidcState {
    pub issuer: Mutex<String>,
    pub plans: Mutex<HashMap<String, Plan>>,
    pub token_requests: Mutex<Vec<HashMap<String, String>>>,
    pub discoveries: Mutex<u32>,
}

pub struct MockOidc {
    pub issuer: String,
    pub state: Arc<OidcState>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

impl MockOidc {
    pub async fn start() -> MockOidc {
        let state = Arc::new(OidcState::default());
        async fn discovery(State(st): State<Arc<OidcState>>) -> Json<Value> {
            *st.discoveries.lock().unwrap() += 1;
            let iss = st.issuer.lock().unwrap().clone();
            Json(json!({
                "issuer": iss,
                "authorization_endpoint": format!("{iss}/authorize"),
                "token_endpoint": format!("{iss}/token"),
                "jwks_uri": format!("{iss}/jwks"),
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            }))
        }
        async fn jwks() -> Json<Value> {
            let jwk: Value = serde_json::from_str(JWK_A).unwrap();
            Json(json!({ "keys": [jwk] }))
        }
        async fn token(
            State(st): State<Arc<OidcState>>,
            Form(form): Form<HashMap<String, String>>,
        ) -> impl IntoResponse {
            st.token_requests.lock().unwrap().push(form.clone());
            let code = form.get("code").cloned().unwrap_or_default();
            let plan = st.plans.lock().unwrap().get(&code).cloned();
            let Some(plan) = plan else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "invalid_grant"})),
                );
            };
            let pem = if plan.bad_signature { KEY_B } else { KEY_A };
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
            header.kid = Some("test-key-1".into());
            let jwt = jsonwebtoken::encode(
                &header,
                &plan.claims,
                &jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
            )
            .unwrap();
            (
                StatusCode::OK,
                Json(json!({
                    "access_token": "mock-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "id_token": jwt,
                })),
            )
        }
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .with_state(state.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", l.local_addr().unwrap());
        *state.issuer.lock().unwrap() = issuer.clone();
        tokio::spawn(async move {
            axum::serve(l, app).await.unwrap();
        });
        MockOidc { issuer, state }
    }

    /// Default good claims for `nonce`.
    pub fn claims(&self, nonce: &str) -> Value {
        json!({
            "iss": self.issuer,
            "sub": "1234567890",
            "aud": CLIENT_ID,
            "exp": now() + 600,
            "iat": now(),
            "nonce": nonce,
            "email": "owner@example.com",
            "email_verified": true,
            "amr": ["pwd", "hwk"],
        })
    }

    pub fn plan(&self, code: &str, claims: Value, bad_signature: bool) {
        self.state.plans.lock().unwrap().insert(
            code.to_string(),
            Plan {
                claims,
                bad_signature,
            },
        );
    }

    pub fn last_token_request(&self) -> HashMap<String, String> {
        self.state
            .token_requests
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap()
    }
}
