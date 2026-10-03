//! Google OIDC (authorization code + PKCE) using the `openidconnect` crate.
//!
//! Provider metadata (including the JWKS) is discovered lazily and refreshed
//! periodically and after a verification failure (key rotation).  No Google
//! access or refresh token is kept: only the verified ID token claims we need
//! (`email`, `amr`) leave this module.

use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreIdToken, CoreProviderMetadata};
use openidconnect::reqwest as oreqwest;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use secret_proto::config::OidcCfg;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

/// Why a login attempt failed. Never shown to the browser in detail.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OidcError {
    #[error("identity provider unavailable")]
    Provider,
    #[error("token exchange failed")]
    Exchange,
    #[error("no id token returned")]
    NoIdToken,
    #[error("id token verification failed")]
    Verification,
    #[error("email claim missing")]
    NoEmail,
    #[error("email not verified")]
    EmailUnverified,
    #[error("email not on allowlist")]
    NotAllowed,
}

/// A started login: where to send the browser, and the values to remember.
pub struct AuthRequest {
    pub url: String,
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: Zeroizing<String>,
}

/// Result of a successful, fully validated login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub email: String,
    pub amr: Option<String>,
}

pub struct OidcClient {
    cfg: OidcCfg,
    client_secret: Zeroizing<String>,
    http: oreqwest::Client,
    meta: Mutex<Option<(Instant, CoreProviderMetadata)>>,
}

const META_TTL: Duration = Duration::from_secs(3600);
const META_MIN_REFRESH: Duration = Duration::from_secs(30);

impl OidcClient {
    pub fn new(cfg: OidcCfg, client_secret: Zeroizing<String>) -> anyhow::Result<Self> {
        let http = oreqwest::Client::builder()
            // Following redirects would open the client up to SSRF.
            .redirect(oreqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(OidcClient {
            cfg,
            client_secret,
            http,
            meta: Mutex::new(None),
        })
    }

    async fn metadata(&self, force: bool) -> Result<CoreProviderMetadata, OidcError> {
        let mut g = self.meta.lock().await;
        if let Some((at, m)) = g.as_ref() {
            let age = at.elapsed();
            if age < META_TTL && !(force && age >= META_MIN_REFRESH) {
                return Ok(m.clone());
            }
        }
        let issuer = IssuerUrl::new(self.cfg.issuer.clone()).map_err(|_| OidcError::Provider)?;
        match CoreProviderMetadata::discover_async(issuer, &self.http).await {
            Ok(m) => {
                *g = Some((Instant::now(), m.clone()));
                Ok(m)
            }
            Err(e) => {
                tracing::error!("OIDC discovery failed: {e}");
                // Keep serving a stale document rather than locking the owner out.
                g.as_ref()
                    .map(|(_, m)| m.clone())
                    .ok_or(OidcError::Provider)
            }
        }
    }

    fn client(
        &self,
        meta: CoreProviderMetadata,
    ) -> Result<
        CoreClient<
            openidconnect::EndpointSet,
            openidconnect::EndpointNotSet,
            openidconnect::EndpointNotSet,
            openidconnect::EndpointNotSet,
            openidconnect::EndpointMaybeSet,
            openidconnect::EndpointMaybeSet,
        >,
        OidcError,
    > {
        let redirect =
            RedirectUrl::new(self.cfg.redirect_url.clone()).map_err(|_| OidcError::Provider)?;
        Ok(CoreClient::from_provider_metadata(
            meta,
            ClientId::new(self.cfg.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.as_str().to_owned())),
        )
        .set_redirect_uri(redirect))
    }

    /// Build the authorization request: code flow with PKCE (S256), `state`
    /// and `nonce`, scopes `openid email`. No `prompt` or `max_age`, and no
    /// offline access.
    pub async fn start(&self) -> Result<AuthRequest, OidcError> {
        let client = self.client(self.metadata(false).await?)?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".to_string()))
            .set_pkce_challenge(challenge)
            .url();
        Ok(AuthRequest {
            url: url.to_string(),
            state: state.secret().clone(),
            nonce: nonce.secret().clone(),
            pkce_verifier: Zeroizing::new(verifier.secret().clone()),
        })
    }

    /// Exchange the code and fully validate the ID token (signature via JWKS,
    /// `iss`, `aud`, `exp`, `nonce`), then check `email_verified` and the
    /// owner allowlist.
    pub async fn complete(
        &self,
        code: &str,
        pkce_verifier: &str,
        nonce: &str,
    ) -> Result<Identity, OidcError> {
        let client = self.client(self.metadata(false).await?)?;
        let resp = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .map_err(|_| OidcError::Exchange)?
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_string()))
            .request_async(&self.http)
            .await
            .map_err(|e| {
                tracing::warn!("token exchange failed: {}", token_err_kind(&e));
                OidcError::Exchange
            })?;
        let id_token: CoreIdToken = resp.id_token().ok_or(OidcError::NoIdToken)?.clone();
        // Access/refresh tokens are dropped here.
        drop(resp);
        let nonce = Nonce::new(nonce.to_string());

        let mut result = {
            let verifier = client.id_token_verifier();
            id_token.claims(&verifier, &nonce).map(claims_identity)
        };
        if result.is_err() {
            // Possibly a rotated signing key: refresh metadata once and retry.
            if let Ok(fresh) = self.metadata(true).await {
                let client = self.client(fresh)?;
                let verifier = client.id_token_verifier();
                result = id_token.claims(&verifier, &nonce).map(claims_identity);
            }
        }
        let (email, verified, amr) = result.map_err(|e| {
            tracing::warn!("id token rejected: {e}");
            OidcError::Verification
        })?;
        let email = email.ok_or(OidcError::NoEmail)?;
        if verified != Some(true) {
            return Err(OidcError::EmailUnverified);
        }
        let lower = email.to_lowercase();
        if !self.cfg.owner_emails.contains(&lower) {
            return Err(OidcError::NotAllowed);
        }
        Ok(Identity { email: lower, amr })
    }
}

type Extracted = (Option<String>, Option<bool>, Option<String>);

fn claims_identity(c: &openidconnect::core::CoreIdTokenClaims) -> Extracted {
    let amr = c.auth_method_refs().map(|v| {
        v.iter()
            .map(|a| a.as_str().to_string())
            .collect::<Vec<_>>()
            .join(",")
    });
    (
        c.email().map(|e| e.as_str().to_string()),
        c.email_verified(),
        amr,
    )
}

fn token_err_kind<E: std::error::Error, T: openidconnect::ErrorResponse>(
    e: &openidconnect::RequestTokenError<E, T>,
) -> &'static str {
    match e {
        openidconnect::RequestTokenError::ServerResponse(_) => "server response",
        openidconnect::RequestTokenError::Request(_) => "request",
        openidconnect::RequestTokenError::Parse(_, _) => "parse",
        openidconnect::RequestTokenError::Other(_) => "other",
    }
}
