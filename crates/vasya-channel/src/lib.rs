//! Provider-neutral channel types and provider registry.
use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, RwLock},
};

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Capabilities: u16 {
        const HISTORY = 1 << 0;
        const SEND = 1 << 1;
        const EDIT = 1 << 2;
        const DELETE = 1 << 3;
        const REACTIONS = 1 << 4;
        const VOICE = 1 << 5;
        const TYPING = 1 << 6;
        const READ_RECEIPTS = 1 << 7;
        const FOLDERS = 1 << 8;
        const CALLS = 1 << 9;
        const LIVE_UPDATES = 1 << 10;
        const THREADS = 1 << 11;
    }
}
impl Capabilities {
    pub fn name_list(self) -> Vec<&'static str> {
        [
            (Self::HISTORY, "history"),
            (Self::SEND, "send"),
            (Self::EDIT, "edit"),
            (Self::DELETE, "delete"),
            (Self::REACTIONS, "reactions"),
            (Self::VOICE, "voice"),
            (Self::TYPING, "typing"),
            (Self::READ_RECEIPTS, "read_receipts"),
            (Self::FOLDERS, "folders"),
            (Self::CALLS, "calls"),
            (Self::LIVE_UPDATES, "live_updates"),
            (Self::THREADS, "threads"),
        ]
        .into_iter()
        .filter_map(|(flag, name)| self.contains(flag).then_some(name))
        .collect()
    }
}
impl Serialize for Capabilities {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.name_list().serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Capabilities {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let names = Vec::<String>::deserialize(deserializer)?;
        let mut flags = Self::empty();
        for name in names {
            flags |= match name.as_str() {
                "history" => Self::HISTORY,
                "send" => Self::SEND,
                "edit" => Self::EDIT,
                "delete" => Self::DELETE,
                "reactions" => Self::REACTIONS,
                "voice" => Self::VOICE,
                "typing" => Self::TYPING,
                "read_receipts" => Self::READ_RECEIPTS,
                "folders" => Self::FOLDERS,
                "calls" => Self::CALLS,
                "live_updates" => Self::LIVE_UPDATES,
                "threads" => Self::THREADS,
                _ => {
                    return Err(serde::de::Error::custom(format!(
                        "unknown capability: {name}"
                    )))
                }
            };
        }
        Ok(flags)
    }
}

macro_rules! string_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);
        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }
        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}
string_id!(ProviderId);
string_id!(AccountId);
string_id!(ChatId);
string_id!(MessageId);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    pub limit: usize,
    pub offset_id: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chat {
    pub id: ChatId,
    pub title: String,
    pub username: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub id: MessageId,
    pub chat_id: ChatId,
    pub text: Option<String>,
    pub timestamp: i64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outgoing {
    Text { text: String },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelEvent {
    pub account_id: AccountId,
    pub chat_id: Option<ChatId>,
    pub kind: String,
    pub payload: serde_json::Value,
}

pub fn format_id(provider: &ProviderId, account: &AccountId, chat: &ChatId) -> String {
    format!("{}:{}:{}", provider.0, account.0, chat.0)
}
pub fn parse_id(value: &str) -> Result<(ProviderId, AccountId, ChatId), IdParseError> {
    let mut parts = value.splitn(3, ':');
    let (Some(provider), Some(account), Some(chat)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(IdParseError);
    };
    if provider.is_empty() || account.is_empty() || chat.is_empty() {
        return Err(IdParseError);
    }
    Ok((provider.into(), account.into(), chat.into()))
}
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("expected provider:account:chat id")]
pub struct IdParseError;

/// Who is asking. Providers that host several users' accounts (the server)
/// must check that `user_id` owns the account before touching it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub user_id: String,
}
impl Caller {
    pub fn new(user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("provider error: {0}")]
    Other(String),
}
#[async_trait]
pub trait ChannelProvider: Send + Sync {
    fn id(&self) -> ProviderId;
    fn capabilities(&self) -> Capabilities;
    /// Authentication remains on provider-specific routes for this migration step.
    async fn list_accounts(&self, caller: &Caller) -> Result<Vec<AccountId>, ProviderError>;
    async fn list_chats(
        &self,
        caller: &Caller,
        acct: &AccountId,
        page: Page,
    ) -> Result<Vec<Chat>, ProviderError>;
    async fn history(
        &self,
        caller: &Caller,
        acct: &AccountId,
        chat: &ChatId,
        page: Page,
    ) -> Result<Vec<Message>, ProviderError>;
    async fn send(
        &self,
        caller: &Caller,
        acct: &AccountId,
        chat: &ChatId,
        outgoing: Outgoing,
    ) -> Result<Message, ProviderError>;
    async fn shutdown(&self) -> Result<(), ProviderError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderInfo {
    pub id: String,
    pub enabled: bool,
    pub capabilities: Capabilities,
}
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("unknown provider '{id}' (known: {known:?})")]
    Unknown { id: String, known: Vec<String> },
    #[error("provider '{id}' is disabled")]
    Disabled { id: String },
}
#[derive(Default)]
pub struct ProviderRegistry {
    providers: RwLock<ProviderMap>,
}
type ProviderMap = HashMap<String, (Arc<dyn ChannelProvider>, bool)>;
impl ProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register(&self, provider: Arc<dyn ChannelProvider>, enabled: bool) {
        self.providers
            .write()
            .unwrap()
            .insert(provider.id().0, (provider, enabled));
    }
    pub fn enable(&self, id: &str) -> Result<(), RegistryError> {
        self.set_enabled(id, true)
    }
    pub fn disable(&self, id: &str) -> Result<(), RegistryError> {
        self.set_enabled(id, false)
    }
    fn set_enabled(&self, id: &str, enabled: bool) -> Result<(), RegistryError> {
        let mut map = self.providers.write().unwrap();
        let Some((_, current)) = map.get_mut(id) else {
            return Err(unknown(id, &map));
        };
        *current = enabled;
        Ok(())
    }
    pub fn get(&self, id: &str) -> Result<Arc<dyn ChannelProvider>, RegistryError> {
        let map = self.providers.read().unwrap();
        match map.get(id) {
            Some((p, true)) => Ok(p.clone()),
            Some(_) => Err(RegistryError::Disabled { id: id.into() }),
            None => Err(unknown(id, &map)),
        }
    }
    /// Ok when the provider is registered and enabled, without cloning it.
    pub fn ensure_enabled(&self, id: &str) -> Result<(), RegistryError> {
        self.get(id).map(|_| ())
    }
    /// Ids of registered providers that are switched off.
    pub fn disabled_ids(&self) -> Vec<String> {
        let mut v: Vec<_> = self
            .providers
            .read()
            .unwrap()
            .iter()
            .filter(|(_, (_, e))| !*e)
            .map(|(id, _)| id.clone())
            .collect();
        v.sort();
        v
    }
    pub fn list(&self) -> Vec<ProviderInfo> {
        let mut v: Vec<_> = self
            .providers
            .read()
            .unwrap()
            .iter()
            .map(|(id, (p, e))| ProviderInfo {
                id: id.clone(),
                enabled: *e,
                capabilities: p.capabilities(),
            })
            .collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }
}
fn unknown(id: &str, map: &ProviderMap) -> RegistryError {
    let mut known: Vec<_> = map.keys().cloned().collect();
    known.sort();
    RegistryError::Unknown {
        id: id.into(),
        known,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake;
    #[async_trait]
    impl ChannelProvider for Fake {
        fn id(&self) -> ProviderId {
            "fake".into()
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities::HISTORY
        }
        async fn list_accounts(&self, _: &Caller) -> Result<Vec<AccountId>, ProviderError> {
            Ok(vec![])
        }
        async fn list_chats(
            &self,
            _: &Caller,
            _: &AccountId,
            _: Page,
        ) -> Result<Vec<Chat>, ProviderError> {
            Ok(vec![])
        }
        async fn history(
            &self,
            _: &Caller,
            _: &AccountId,
            _: &ChatId,
            _: Page,
        ) -> Result<Vec<Message>, ProviderError> {
            Ok(vec![])
        }
        async fn send(
            &self,
            _: &Caller,
            _: &AccountId,
            _: &ChatId,
            _: Outgoing,
        ) -> Result<Message, ProviderError> {
            Err(ProviderError::Unsupported("send".into()))
        }
    }
    #[test]
    fn registry_enable_disable_and_unknown() {
        let r = ProviderRegistry::new();
        r.register(Arc::new(Fake), false);
        assert!(matches!(r.get("fake"), Err(RegistryError::Disabled { .. })));
        r.enable("fake").unwrap();
        assert!(r.get("fake").is_ok());
        r.disable("fake").unwrap();
        assert!(matches!(r.get("fake"), Err(RegistryError::Disabled { .. })));
        assert!(
            matches!(r.get("missing"),Err(RegistryError::Unknown{known,..}) if known==vec!["fake"])
        );
        assert!(!r.list()[0].enabled);
    }
    #[test]
    fn namespaced_ids_round_trip() {
        let p = ProviderId::from("telegram");
        let a = AccountId::from("acct");
        let c = ChatId::from("-100:42");
        let id = format_id(&p, &a, &c);
        assert_eq!(id, "telegram:acct:-100:42");
        assert_eq!(parse_id(&id).unwrap(), (p, a, c));
        assert!(parse_id("telegram:acct").is_err());
        assert!(parse_id("telegram::chat").is_err());
    }
}
