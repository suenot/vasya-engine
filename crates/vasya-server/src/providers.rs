//! Runtime provider discovery and enablement endpoints.
//!
//! Switching a provider off affects every user of this server, so enable and
//! disable are admin-only (and human-session-only, see policy.rs). Disabling
//! never deletes sessions or data; it only makes the provider's routes answer
//! `404 provider_disabled`. The disabled list survives restarts in
//! `<data_dir>/providers.json`.

use std::path::Path as FsPath;
use std::sync::Arc;

use anyhow::Context;
use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use vasya_channel::{Caller, ProviderError, RegistryError};

use crate::{auth::UserId, context::ServerContext, error::ApiError};

const STATE_FILE: &str = "providers.json";

#[derive(Default, Serialize, Deserialize)]
struct ProvidersState {
    #[serde(default)]
    disabled: Vec<String>,
}

/// Disabled provider ids saved by a previous run (empty when no file yet).
pub fn load_disabled(data_dir: &FsPath) -> anyhow::Result<Vec<String>> {
    let path = data_dir.join(STATE_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => Ok(serde_json::from_slice::<ProvidersState>(&bytes)
            .with_context(|| format!("invalid {}", path.display()))?
            .disabled),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn save_disabled(ctx: &ServerContext) -> Result<(), ApiError> {
    let state = ProvidersState {
        disabled: ctx.providers.disabled_ids(),
    };
    let path = ctx.data_dir.join(STATE_FILE);
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(&state).map_err(|e| ApiError::Internal(e.to_string()))?;
    std::fs::write(&tmp, bytes)
        .and_then(|_| std::fs::rename(&tmp, &path))
        .map_err(|e| ApiError::Internal(format!("failed to save provider state: {e}")))
}

/// 404 `provider_disabled` / `provider_unknown` for routes of provider `id`.
pub(crate) fn ensure_enabled(ctx: &ServerContext, id: &str) -> Result<(), ApiError> {
    ctx.providers.ensure_enabled(id).map_err(registry_error)
}

pub async fn list(State(ctx): State<Arc<ServerContext>>) -> Json<Vec<vasya_channel::ProviderInfo>> {
    Json(ctx.providers.list())
}

/// The caller's own accounts on provider `id`.
pub async fn accounts(
    State(ctx): State<Arc<ServerContext>>,
    Extension(user): Extension<UserId>,
    Path(id): Path<String>,
) -> Result<Json<Vec<vasya_channel::AccountId>>, ApiError> {
    let provider = ctx.providers.get(&id).map_err(registry_error)?;
    provider
        .list_accounts(&Caller::new(user.0))
        .await
        .map(Json)
        .map_err(provider_error)
}

pub async fn enable(
    State(ctx): State<Arc<ServerContext>>,
    Extension(user): Extension<UserId>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    change(&ctx, &user, &id, true)
}

pub async fn disable(
    State(ctx): State<Arc<ServerContext>>,
    Extension(user): Extension<UserId>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    change(&ctx, &user, &id, false)
}

fn change(
    ctx: &ServerContext,
    user: &UserId,
    id: &str,
    enabled: bool,
) -> Result<Json<Value>, ApiError> {
    if !ctx.is_admin(&user.0) {
        return Err(ApiError::Forbidden(
            "Only a server admin can enable or disable providers".into(),
        ));
    }
    let result = if enabled {
        ctx.providers.enable(id)
    } else {
        ctx.providers.disable(id)
    };
    result.map_err(registry_error)?;
    save_disabled(ctx)?;
    Ok(Json(json!({ "id": id, "enabled": enabled })))
}

pub(crate) fn registry_error(e: RegistryError) -> ApiError {
    match e {
        RegistryError::Unknown { id, known } => ApiError::ProviderNotFound {
            code: "provider_unknown",
            id,
            known,
        },
        RegistryError::Disabled { id } => ApiError::ProviderNotFound {
            code: "provider_disabled",
            id,
            known: vec![],
        },
    }
}

pub(crate) fn provider_error(e: ProviderError) -> ApiError {
    match e {
        ProviderError::Unsupported(m) => ApiError::NotImplemented(m),
        ProviderError::InvalidInput(m) => ApiError::BadRequest(m),
        ProviderError::NotFound(m) => ApiError::NotFound(m),
        ProviderError::Forbidden(m) => ApiError::Forbidden(m),
        ProviderError::Other(m) => ApiError::Internal(m),
    }
}
