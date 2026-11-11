//! Email account management (human session only, see policy.rs). Reading and
//! sending mail goes through the generic `/providers/email/...` routes.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::Deserialize;
use vasya_channel_email::{AccountInfo, MailConfig};

use crate::auth::UserId;
use crate::context::ServerContext;
use crate::error::ApiError;
use crate::providers::{ensure_enabled, provider_error};

const ID: &str = "email";

#[derive(Deserialize)]
pub struct AddAccount {
    pub email: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for AddAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddAccount")
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

fn provider(ctx: &ServerContext) -> Result<&Arc<vasya_channel_email::EmailProvider>, ApiError> {
    ensure_enabled(ctx, ID)?;
    ctx.email
        .as_ref()
        .ok_or_else(|| ApiError::NotImplemented("email provider is not available".into()))
}

pub async fn add_account(
    State(ctx): State<Arc<ServerContext>>,
    Extension(user): Extension<UserId>,
    Json(req): Json<AddAccount>,
) -> Result<Json<AccountInfo>, ApiError> {
    let config = MailConfig {
        email: req.email.trim().to_lowercase(),
        imap_host: req.imap_host.trim().to_string(),
        imap_port: req.imap_port,
        smtp_host: req.smtp_host.trim().to_string(),
        smtp_port: req.smtp_port,
        username: req.username,
        password: req.password,
    };
    provider(&ctx)?
        .add(&user.0, config)
        .await
        .map(Json)
        .map_err(provider_error)
}

pub async fn list_accounts(
    State(ctx): State<Arc<ServerContext>>,
    Extension(user): Extension<UserId>,
) -> Result<Json<Vec<AccountInfo>>, ApiError> {
    provider(&ctx)?
        .accounts(&user.0)
        .map(Json)
        .map_err(provider_error)
}

pub async fn delete_account(
    State(ctx): State<Arc<ServerContext>>,
    Extension(user): Extension<UserId>,
    Path(acc): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    provider(&ctx)?
        .remove(&user.0, &acc)
        .map_err(provider_error)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
