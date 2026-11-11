//! Email (IMAP + SMTP) behind the provider-neutral `ChannelProvider` trait.
//!
//! A chat is one correspondent address. Account configs (with the password)
//! live in a [`ConfigStore`]; the server supplies an encrypted one.

mod backend;
pub use backend::ImapSmtpBackend;

use async_trait::async_trait;
use std::{collections::HashSet, net::IpAddr};
use vasya_channel::{
    AccountId, Caller, Capabilities, ChannelProvider, Chat, ChatId, Message, MessageId, Outgoing,
    Page, ProviderError, ProviderId,
};

const LIMIT_TEXT: usize = 64 * 1024;
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct MailConfig {
    pub email: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
}
impl std::fmt::Debug for MailConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailConfig")
            .field("email", &self.email)
            .field("imap_host", &self.imap_host)
            .field("imap_port", &self.imap_port)
            .field("smtp_host", &self.smtp_host)
            .field("smtp_port", &self.smtp_port)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}
#[derive(Clone, Debug)]
pub struct Envelope {
    pub mailbox: String,
    pub uid: u32,
    pub date: i64,
    pub from: String,
    pub from_name: Option<String>,
    pub to: Vec<String>,
    pub to_names: Vec<Option<String>>,
    pub subject: Option<String>,
}
#[derive(Clone, Debug)]
pub struct RawMail {
    pub bytes: Vec<u8>,
}
#[async_trait]
pub trait MailBackend: Send + Sync {
    async fn verify(&self, c: &MailConfig) -> Result<(), String>;
    async fn envelopes(&self, c: &MailConfig, limit: usize) -> Result<Vec<Envelope>, String>;
    async fn fetch(&self, c: &MailConfig, mailbox: &str, uid: u32) -> Result<RawMail, String>;
    async fn send(&self, c: &MailConfig, to: &str, text: &str) -> Result<(), String>;
}
/// Where account configs are kept. The server implements it on top of
/// per-user encrypted files; tests use [`MemoryStore`].
pub trait ConfigStore: Send + Sync {
    fn save(&self, user: &str, id: &str, c: &MailConfig) -> Result<(), String>;
    fn load(&self, user: &str, id: &str) -> Result<Option<MailConfig>, String>;
    /// Ids and addresses of the user's accounts.
    fn list(&self, user: &str) -> Result<Vec<(String, String)>, String>;
    fn delete(&self, user: &str, id: &str) -> Result<bool, String>;
}

/// In-memory store (tests, ephemeral use).
#[derive(Default)]
pub struct MemoryStore(std::sync::Mutex<std::collections::HashMap<(String, String), MailConfig>>);
impl ConfigStore for MemoryStore {
    fn save(&self, user: &str, id: &str, c: &MailConfig) -> Result<(), String> {
        self.0
            .lock()
            .unwrap()
            .insert((user.into(), id.into()), c.clone());
        Ok(())
    }
    fn load(&self, user: &str, id: &str) -> Result<Option<MailConfig>, String> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(&(user.to_string(), id.to_string()))
            .cloned())
    }
    fn list(&self, user: &str) -> Result<Vec<(String, String)>, String> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|((u, _), _)| u == user)
            .map(|((_, id), c)| (id.clone(), c.email.clone()))
            .collect())
    }
    fn delete(&self, user: &str, id: &str) -> Result<bool, String> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .remove(&(user.to_string(), id.to_string()))
            .is_some())
    }
}

/// An account as shown to its owner (never the password).
#[derive(Clone, Debug, serde::Serialize)]
pub struct AccountInfo {
    pub account_id: String,
    pub email: String,
}

pub struct EmailProvider {
    backend: std::sync::Arc<dyn MailBackend>,
    store: std::sync::Arc<dyn ConfigStore>,
}

fn invalid(msg: &str) -> ProviderError {
    ProviderError::InvalidInput(msg.into())
}
fn store_err(_: String) -> ProviderError {
    ProviderError::Other("email account storage failed".into())
}

impl MailConfig {
    /// Shape checks only (no network). Hosts are checked when connecting.
    pub fn validate(&self) -> Result<(), ProviderError> {
        let ok_text = |s: &str, max: usize| {
            !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
        };
        if !ok_text(&self.email, 254) || self.email.parse::<lettre::Address>().is_err() {
            return Err(invalid("invalid email address"));
        }
        if !ok_text(&self.username, 254) {
            return Err(invalid("invalid username"));
        }
        if !ok_text(&self.password, 1024) {
            return Err(invalid("invalid password"));
        }
        for host in [&self.imap_host, &self.smtp_host] {
            if !ok_text(host, 253) || host.contains(['/', ' ', '@', ':']) {
                return Err(invalid("invalid mail server host"));
            }
        }
        if self.imap_port == 0 || self.smtp_port == 0 {
            return Err(invalid("invalid mail server port"));
        }
        Ok(())
    }
}

impl EmailProvider {
    pub fn new(
        backend: std::sync::Arc<dyn MailBackend>,
        store: std::sync::Arc<dyn ConfigStore>,
    ) -> Self {
        Self { backend, store }
    }
    /// Verify the credentials against the servers, then store the account.
    pub async fn add(&self, user: &str, c: MailConfig) -> Result<AccountInfo, ProviderError> {
        c.validate()?;
        self.backend
            .verify(&c)
            .await
            .map_err(ProviderError::InvalidInput)?;
        let id = uuid::Uuid::new_v4().to_string();
        self.store.save(user, &id, &c).map_err(store_err)?;
        Ok(AccountInfo {
            account_id: id,
            email: c.email,
        })
    }
    pub fn accounts(&self, user: &str) -> Result<Vec<AccountInfo>, ProviderError> {
        Ok(self
            .store
            .list(user)
            .map_err(store_err)?
            .into_iter()
            .map(|(account_id, email)| AccountInfo { account_id, email })
            .collect())
    }
    pub fn remove(&self, user: &str, id: &str) -> Result<(), ProviderError> {
        match self.store.delete(user, id).map_err(store_err)? {
            true => Ok(()),
            false => Err(ProviderError::NotFound("email account not found".into())),
        }
    }
    fn config(&self, caller: &Caller, id: &AccountId) -> Result<MailConfig, ProviderError> {
        self.store
            .load(&caller.user_id, &id.0)
            .map_err(store_err)?
            .ok_or_else(|| ProviderError::NotFound("email account not found".into()))
    }
}
#[async_trait]
impl ChannelProvider for EmailProvider {
    fn id(&self) -> ProviderId {
        "email".into()
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities::HISTORY | Capabilities::SEND | Capabilities::THREADS
    }
    async fn list_accounts(&self, c: &Caller) -> Result<Vec<AccountId>, ProviderError> {
        Ok(self
            .accounts(&c.user_id)?
            .into_iter()
            .map(|a| AccountId(a.account_id))
            .collect())
    }
    async fn list_chats(
        &self,
        caller: &Caller,
        acct: &AccountId,
        page: Page,
    ) -> Result<Vec<Chat>, ProviderError> {
        let cfg = self.config(caller, acct)?;
        let env = self
            .backend
            .envelopes(&cfg, 500)
            .await
            .map_err(ProviderError::Other)?;
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for e in env {
            let (address, name) = counterpart(&cfg.email, &e);
            let id = address.to_lowercase();
            if seen.insert(id.clone()) {
                out.push(Chat {
                    id: ChatId(id.clone()),
                    title: name.filter(|s| !s.is_empty()).unwrap_or_else(|| id.clone()),
                    username: None,
                });
            }
        }
        Ok(page_items(out, page, None))
    }
    async fn history(
        &self,
        caller: &Caller,
        acct: &AccountId,
        chat: &ChatId,
        page: Page,
    ) -> Result<Vec<Message>, ProviderError> {
        let cfg = self.config(caller, acct)?;
        let env = self
            .backend
            .envelopes(&cfg, 1000)
            .await
            .map_err(ProviderError::Other)?;
        let mut selected = env
            .into_iter()
            .filter(|e| counterpart(&cfg.email, e).0.eq_ignore_ascii_case(&chat.0))
            .collect::<Vec<_>>();
        selected.sort_by_key(|e| std::cmp::Reverse(e.date));
        let start = page
            .offset_id
            .as_deref()
            .and_then(|s| {
                selected
                    .iter()
                    .position(|e| format!("{}:{}", e.mailbox, e.uid) == s)
            })
            .map_or(0, |i| i + 1);
        let mut out = Vec::new();
        for e in selected.into_iter().skip(start).take(page.limit) {
            let raw = self
                .backend
                .fetch(&cfg, &e.mailbox, e.uid)
                .await
                .map_err(ProviderError::Other)?;
            let text = extract_text(&raw.bytes);
            out.push(Message {
                id: MessageId(format!("{}:{}", e.mailbox, e.uid)),
                chat_id: chat.clone(),
                text,
                timestamp: e.date,
            });
        }
        Ok(out)
    }
    async fn send(
        &self,
        caller: &Caller,
        acct: &AccountId,
        chat: &ChatId,
        outgoing: Outgoing,
    ) -> Result<Message, ProviderError> {
        let cfg = self.config(caller, acct)?;
        let Outgoing::Text { text } = outgoing;
        if chat.0.parse::<lettre::Address>().is_err() {
            return Err(invalid("chat id must be an email address"));
        }
        self.backend
            .send(&cfg, &chat.0, &text)
            .await
            .map_err(ProviderError::Other)?;
        Ok(Message {
            id: MessageId(format!("Sent:{}", uuid::Uuid::new_v4())),
            chat_id: chat.clone(),
            text: Some(text),
            timestamp: chrono_now(),
        })
    }
}
fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn counterpart(email: &str, e: &Envelope) -> (String, Option<String>) {
    if e.from.eq_ignore_ascii_case(email) {
        for (i, to) in e.to.iter().enumerate() {
            if !to.eq_ignore_ascii_case(email) {
                return (to.clone(), e.to_names.get(i).cloned().flatten());
            }
        }
    }
    (e.from.clone(), e.from_name.clone())
}
fn page_items<T>(v: Vec<T>, p: Page, _unused: Option<()>) -> Vec<T> {
    v.into_iter()
        .skip(
            p.offset_id
                .as_ref()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0),
        )
        .take(p.limit)
        .collect()
}
pub fn extract_text(raw: &[u8]) -> Option<String> {
    let m = mail_parser::MessageParser::default().parse(raw)?;
    let mut value = m.body_text(0).map(|s| s.into_owned());
    if value.is_none() {
        value = m.body_html(0).map(|s| strip_html(&s));
    }
    value.map(|s| {
        if s.len() > LIMIT_TEXT {
            let mut n = LIMIT_TEXT;
            while !s.is_char_boundary(n) {
                n -= 1;
            }
            s[..n].to_owned()
        } else {
            s
        }
    })
}
fn strip_html(s: &str) -> String {
    let (mut out, mut tag) = (String::new(), false);
    for c in s.chars() {
        match c {
            '<' => tag = true,
            '>' => tag = false,
            _ if !tag => out.push(c),
            _ => {}
        }
    }
    out
}
pub fn address_is_forbidden(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_unspecified()
                || a.octets()[0] == 0
        }
        IpAddr::V6(a) => {
            a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || a.is_unique_local()
                || a.is_unicast_link_local()
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct FakeBackend(Vec<Envelope>);
    #[async_trait]
    impl MailBackend for FakeBackend {
        async fn verify(&self, _: &MailConfig) -> Result<(), String> {
            Ok(())
        }
        async fn envelopes(&self, _: &MailConfig, _: usize) -> Result<Vec<Envelope>, String> {
            Ok(self.0.clone())
        }
        async fn fetch(&self, _: &MailConfig, _: &str, _: u32) -> Result<RawMail, String> {
            Ok(RawMail {
                bytes: b"From: sender@example.com\r\nContent-Type: text/plain\r\n\r\nbody".to_vec(),
            })
        }
        async fn send(&self, _: &MailConfig, _: &str, _: &str) -> Result<(), String> {
            Ok(())
        }
    }
    fn envelope(mailbox: &str, uid: u32, date: i64, from: &str, to: &str) -> Envelope {
        Envelope {
            mailbox: mailbox.into(),
            uid,
            date,
            from: from.into(),
            from_name: None,
            to: vec![to.into()],
            to_names: vec![None],
            subject: None,
        }
    }
    fn config() -> MailConfig {
        MailConfig {
            email: "me@example.com".into(),
            imap_host: "mail.example.com".into(),
            imap_port: 993,
            smtp_host: "mail.example.com".into(),
            smtp_port: 465,
            username: "me".into(),
            password: "secret".into(),
        }
    }

    #[tokio::test]
    async fn groups_chats_and_paginates_history_by_uid() {
        let backend = Arc::new(FakeBackend(vec![
            envelope("INBOX", 4, 40, "a@example.com", "me@example.com"),
            envelope("Sent", 9, 30, "me@example.com", "B@example.com"),
            envelope("INBOX", 2, 20, "a@example.com", "me@example.com"),
        ]));
        let provider = EmailProvider::new(backend, Arc::new(MemoryStore::default()));
        let acct_id = provider.add("u", config()).await.unwrap().account_id;
        let caller = Caller::new("u");
        let chats = provider
            .list_chats(
                &caller,
                &AccountId(acct_id.clone()),
                Page {
                    limit: 50,
                    offset_id: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            chats.iter().map(|c| c.id.0.as_str()).collect::<Vec<_>>(),
            ["a@example.com", "b@example.com"]
        );
        let history = provider
            .history(
                &caller,
                &AccountId(acct_id.clone()),
                &ChatId("a@example.com".into()),
                Page {
                    limit: 1,
                    offset_id: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(history[0].id.0, "INBOX:4");
        let next = provider
            .history(
                &caller,
                &AccountId(acct_id.clone()),
                &ChatId("a@example.com".into()),
                Page {
                    limit: 1,
                    offset_id: Some("INBOX:4".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(next[0].id.0, "INBOX:2");
    }
    #[test]
    fn extracts_plain_html_and_truncates() {
        assert_eq!(
            extract_text(b"Content-Type: text/plain\r\n\r\nhello").as_deref(),
            Some("hello")
        );
        assert_eq!(
            extract_text(b"Content-Type: text/html\r\n\r\n<p>hello</p>").as_deref(),
            Some("hello\n")
        );
        let raw = format!(
            "Content-Type: text/plain\r\n\r\n{}",
            "x".repeat(LIMIT_TEXT + 1)
        );
        assert_eq!(extract_text(raw.as_bytes()).unwrap().len(), LIMIT_TEXT);
    }
    #[test]
    fn rejects_local_ip_ranges_and_redacts_password_debug() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(address_is_forbidden(ip.parse().unwrap()), "{ip}");
        }
        assert!(!format!("{:?}", config()).contains("secret"));
    }

    #[tokio::test]
    async fn accounts_are_isolated_per_user_and_never_expose_password() {
        let provider = EmailProvider::new(
            Arc::new(FakeBackend(vec![])),
            Arc::new(MemoryStore::default()),
        );
        let id = provider.add("alice", config()).await.unwrap().account_id;
        assert!(provider.accounts("bob").unwrap().is_empty());
        assert!(provider.remove("bob", &id).is_err());
        let page = Page {
            limit: 10,
            offset_id: None,
        };
        let err = provider
            .list_chats(&Caller::new("bob"), &AccountId(id.clone()), page)
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::NotFound(_)));
        let listed = serde_json::to_string(&provider.accounts("alice").unwrap()).unwrap();
        assert!(!listed.contains("secret") && listed.contains("me@example.com"));
        provider.remove("alice", &id).unwrap();
        assert!(provider.accounts("alice").unwrap().is_empty());
    }

    #[test]
    fn validates_config_shape() {
        assert!(config().validate().is_ok());
        let bad = |f: fn(&mut MailConfig)| {
            let mut c = config();
            f(&mut c);
            c.validate().is_err()
        };
        assert!(bad(|c| c.email = "nope".into()));
        assert!(bad(|c| c.imap_port = 0));
        assert!(bad(|c| c.smtp_host = "a b".into()));
        assert!(bad(|c| c.imap_host = "host/path".into()));
        assert!(bad(|c| c.password = String::new()));
        assert!(bad(|c| c.username = "x\ny".into()));
    }

    #[tokio::test]
    async fn send_rejects_non_address_chat() {
        let provider = EmailProvider::new(
            Arc::new(FakeBackend(vec![])),
            Arc::new(MemoryStore::default()),
        );
        let id = provider.add("u", config()).await.unwrap().account_id;
        let err = provider
            .send(
                &Caller::new("u"),
                &AccountId(id),
                &ChatId("not an address".into()),
                Outgoing::Text { text: "hi".into() },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::InvalidInput(_)));
    }
}
