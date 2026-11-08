//! Telegram behind the provider-neutral `ChannelProvider` trait.
//!
//! The adapter reuses the same `*_op` functions the REST routes call, so the
//! chat cache, peer resolution, rate limiting and account-ownership checks are
//! shared rather than duplicated. Authentication stays on the existing
//! `/telegram/login/*` routes for now.

use std::sync::{Arc, Weak};

use async_trait::async_trait;
use vasya_channel::{
    AccountId, Caller, Capabilities, ChannelProvider, Chat, ChatId, Message, MessageId, Outgoing,
    Page, ProviderError, ProviderId,
};

use crate::auth::UserId;
use crate::context::ServerContext;
use crate::dto;
use crate::error::ApiError;
use crate::routes::{chats, messages};

pub const TELEGRAM: &str = "telegram";

/// Holds a weak handle: the context owns the registry that owns this adapter.
pub struct TelegramProvider {
    ctx: Weak<ServerContext>,
}

impl TelegramProvider {
    pub fn new(ctx: Weak<ServerContext>) -> Self {
        Self { ctx }
    }

    fn ctx(&self) -> Result<Arc<ServerContext>, ProviderError> {
        self.ctx
            .upgrade()
            .ok_or_else(|| ProviderError::Other("server is shutting down".into()))
    }
}

fn user(caller: &Caller) -> UserId {
    UserId(caller.user_id.clone())
}

fn chat_id(chat: &ChatId) -> Result<i64, ProviderError> {
    chat.0
        .parse()
        .map_err(|_| ProviderError::InvalidInput(format!("invalid Telegram chat id: {chat}")))
}

fn to_chat(c: dto::Chat) -> Chat {
    Chat {
        id: ChatId(c.id.to_string()),
        title: c.title,
        username: c.username,
    }
}

fn to_message(m: dto::Message) -> Message {
    Message {
        id: MessageId(m.id.to_string()),
        chat_id: ChatId(m.chat_id.to_string()),
        text: m.text,
        timestamp: m.date,
    }
}

impl From<ApiError> for ProviderError {
    fn from(e: ApiError) -> Self {
        match e {
            ApiError::BadRequest(m) => ProviderError::InvalidInput(m),
            ApiError::NotFound(m) => ProviderError::NotFound(m),
            ApiError::Forbidden(m) => ProviderError::Forbidden(m),
            ApiError::NotImplemented(m) => ProviderError::Unsupported(m),
            other => ProviderError::Other(other.to_string()),
        }
    }
}

#[async_trait]
impl ChannelProvider for TelegramProvider {
    fn id(&self) -> ProviderId {
        TELEGRAM.into()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::HISTORY
            | Capabilities::SEND
            | Capabilities::EDIT
            | Capabilities::DELETE
            | Capabilities::REACTIONS
            | Capabilities::VOICE
            | Capabilities::TYPING
            | Capabilities::READ_RECEIPTS
            | Capabilities::FOLDERS
            | Capabilities::CALLS
            | Capabilities::LIVE_UPDATES
            | Capabilities::THREADS
    }

    /// Only the caller's own accounts, never other users' on a shared server.
    async fn list_accounts(&self, caller: &Caller) -> Result<Vec<AccountId>, ProviderError> {
        let ctx = self.ctx()?;
        Ok(ctx
            .accounts
            .list_for(&caller.user_id)
            .into_iter()
            .map(AccountId)
            .collect())
    }

    async fn list_chats(
        &self,
        caller: &Caller,
        acct: &AccountId,
        page: Page,
    ) -> Result<Vec<Chat>, ProviderError> {
        let ctx = self.ctx()?;
        let all = chats::list_chats_op(&ctx, &user(caller), &acct.0, false).await?;
        let start = match &page.offset_id {
            Some(after) => all
                .iter()
                .position(|c| c.id.to_string() == *after)
                .map_or(all.len(), |i| i + 1),
            None => 0,
        };
        Ok(all
            .into_iter()
            .skip(start)
            .take(page.limit)
            .map(to_chat)
            .collect())
    }

    async fn history(
        &self,
        caller: &Caller,
        acct: &AccountId,
        chat: &ChatId,
        page: Page,
    ) -> Result<Vec<Message>, ProviderError> {
        let ctx = self.ctx()?;
        let offset = page
            .offset_id
            .as_deref()
            .map(|s| {
                s.parse::<i32>()
                    .map_err(|_| ProviderError::InvalidInput(format!("invalid message id: {s}")))
            })
            .transpose()?;
        let msgs = messages::get_messages_op(
            &ctx,
            &user(caller),
            &acct.0,
            chat_id(chat)?,
            offset,
            Some(page.limit),
            None,
        )
        .await?;
        Ok(msgs.into_iter().map(to_message).collect())
    }

    async fn send(
        &self,
        caller: &Caller,
        acct: &AccountId,
        chat: &ChatId,
        outgoing: Outgoing,
    ) -> Result<Message, ProviderError> {
        let ctx = self.ctx()?;
        let Outgoing::Text { text } = outgoing;
        let sent =
            messages::send_message_op(&ctx, &user(caller), &acct.0, chat_id(chat)?, text, None)
                .await?;
        Ok(to_message(sent))
    }
}
