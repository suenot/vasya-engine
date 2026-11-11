//! Real IMAP/SMTP backend: TLS is mandatory (implicit TLS on 993/465, STARTTLS
//! otherwise, never plaintext), hosts are resolved once and the connection is
//! pinned to the checked address (no DNS rebinding between check and connect),
//! and every network step has a timeout.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::TryStreamExt;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::{address_is_forbidden, Envelope, MailBackend, MailConfig, RawMail};

const STEP_TIMEOUT: Duration = Duration::from_secs(20);
const OP_TIMEOUT: Duration = Duration::from_secs(90);
/// Largest message prefix fetched (bytes).
const MAX_BODY: usize = 512 * 1024;

type Tls13 = tokio_rustls::client::TlsStream<TcpStream>;

pub struct ImapSmtpBackend {
    /// Accept loopback/private hosts (embedded desktop mode only).
    allow_local: bool,
    tls: TlsConnector,
}

impl ImapSmtpBackend {
    pub fn new(allow_local: bool) -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            allow_local,
            tls: TlsConnector::from(Arc::new(config)),
        }
    }

    /// Resolve `host` and keep only addresses the guard allows.
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        let addrs: Vec<SocketAddr> =
            tokio::time::timeout(STEP_TIMEOUT, tokio::net::lookup_host((host, port)))
                .await
                .map_err(|_| "host resolution timed out".to_string())?
                .map_err(|_| "host could not be resolved".to_string())?
                .collect();
        let allowed: Vec<SocketAddr> = addrs
            .into_iter()
            .filter(|a| self.allow_local || !address_is_forbidden(a.ip()))
            .collect();
        if allowed.is_empty() {
            return Err("private or local mail hosts are not allowed".into());
        }
        Ok(allowed)
    }

    async fn tcp(&self, host: &str, port: u16) -> Result<(TcpStream, IpAddr), String> {
        let addrs = self.resolve(host, port).await?;
        for addr in addrs {
            if let Ok(Ok(s)) = tokio::time::timeout(STEP_TIMEOUT, TcpStream::connect(addr)).await {
                return Ok((s, addr.ip()));
            }
        }
        Err("could not connect to the mail server".into())
    }

    async fn wrap(&self, host: &str, stream: TcpStream) -> Result<Tls13, String> {
        let name =
            ServerName::try_from(host.to_string()).map_err(|_| "invalid host name".to_string())?;
        tokio::time::timeout(STEP_TIMEOUT, self.tls.connect(name, stream))
            .await
            .map_err(|_| "TLS handshake timed out".to_string())?
            .map_err(|_| "TLS handshake failed (certificate not trusted?)".to_string())
    }

    async fn imap(&self, c: &MailConfig) -> Result<async_imap::Session<Tls13>, String> {
        let (tcp, _) = self.tcp(&c.imap_host, c.imap_port).await?;
        let client = if c.imap_port == 993 {
            let mut client = async_imap::Client::new(self.wrap(&c.imap_host, tcp).await?);
            greeting(&mut client).await?;
            client
        } else {
            // STARTTLS: greeting, upgrade, then a fresh client on the TLS stream.
            let mut plain = async_imap::Client::new(tcp);
            greeting(&mut plain).await?;
            tokio::time::timeout(
                STEP_TIMEOUT,
                plain.run_command_and_check_ok("STARTTLS", None),
            )
            .await
            .map_err(|_| "STARTTLS timed out".to_string())?
            .map_err(|_| "server refused STARTTLS (TLS is required)".to_string())?;
            async_imap::Client::new(self.wrap(&c.imap_host, plain.into_inner()).await?)
        };
        tokio::time::timeout(STEP_TIMEOUT, client.login(&c.username, &c.password))
            .await
            .map_err(|_| "IMAP login timed out".to_string())?
            .map_err(|_| "IMAP login failed".to_string())
    }

    fn smtp(
        &self,
        c: &MailConfig,
        ip: IpAddr,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
        let params =
            TlsParameters::new(c.smtp_host.clone()).map_err(|_| "invalid SMTP host".to_string())?;
        let tls = if c.smtp_port == 465 {
            Tls::Wrapper(params)
        } else {
            Tls::Required(params)
        };
        Ok(
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(ip.to_string())
                .port(c.smtp_port)
                .tls(tls)
                .credentials(Credentials::new(c.username.clone(), c.password.clone()))
                .timeout(Some(STEP_TIMEOUT))
                .build(),
        )
    }

    async fn smtp_for(&self, c: &MailConfig) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
        let addrs = self.resolve(&c.smtp_host, c.smtp_port).await?;
        self.smtp(c, addrs[0].ip())
    }
}

async fn greeting(
    client: &mut async_imap::Client<
        impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::fmt::Debug + Send,
    >,
) -> Result<(), String> {
    tokio::time::timeout(STEP_TIMEOUT, client.read_response())
        .await
        .map_err(|_| "IMAP greeting timed out".to_string())?
        .ok_or_else(|| "IMAP server closed the connection".to_string())?
        .map_err(|_| "IMAP greeting failed".to_string())?;
    Ok(())
}

fn first_addr(
    list: Option<&Vec<async_imap::imap_proto::Address<'_>>>,
) -> Vec<(String, Option<String>)> {
    let utf8 = |b: &Option<std::borrow::Cow<'_, [u8]>>| {
        b.as_ref().map(|v| String::from_utf8_lossy(v).into_owned())
    };
    list.map(|v| {
        v.iter()
            .filter_map(|a| {
                let mailbox = utf8(&a.mailbox)?;
                let host = utf8(&a.host)?;
                Some((
                    format!("{mailbox}@{host}"),
                    utf8(&a.name).filter(|s| !s.is_empty()),
                ))
            })
            .collect()
    })
    .unwrap_or_default()
}

#[async_trait]
impl MailBackend for ImapSmtpBackend {
    async fn verify(&self, c: &MailConfig) -> Result<(), String> {
        tokio::time::timeout(OP_TIMEOUT, async {
            let mut session = self.imap(c).await?;
            let _ = session.logout().await;
            let smtp = self.smtp_for(c).await?;
            match smtp.test_connection().await {
                Ok(true) => Ok(()),
                _ => Err("SMTP login failed".to_string()),
            }
        })
        .await
        .map_err(|_| "mail server did not answer in time".to_string())?
    }

    async fn envelopes(&self, c: &MailConfig, limit: usize) -> Result<Vec<Envelope>, String> {
        tokio::time::timeout(OP_TIMEOUT, async {
            let mut session = self.imap(c).await?;
            // INBOX plus the SPECIAL-USE \Sent folder (fallback: "Sent").
            let mut sent = None;
            {
                let names: Vec<_> = session
                    .list(Some(""), Some("*"))
                    .await
                    .map_err(|_| "could not list mailboxes".to_string())?
                    .try_collect()
                    .await
                    .map_err(|_| "could not list mailboxes".to_string())?;
                for n in &names {
                    if n.attributes()
                        .iter()
                        .any(|a| matches!(a, async_imap::types::NameAttribute::Sent))
                    {
                        sent = Some(n.name().to_string());
                        break;
                    }
                }
                if sent.is_none() && names.iter().any(|n| n.name() == "Sent") {
                    sent = Some("Sent".to_string());
                }
            }
            let mut boxes = vec!["INBOX".to_string()];
            boxes.extend(sent);
            let mut out = Vec::new();
            for mailbox in boxes {
                let Ok(info) = session.examine(&mailbox).await else {
                    continue;
                };
                if info.exists == 0 {
                    continue;
                }
                let first = info.exists.saturating_sub(limit as u32 - 1).max(1);
                let fetches: Vec<_> = session
                    .fetch(
                        format!("{first}:{}", info.exists),
                        "(UID INTERNALDATE ENVELOPE)",
                    )
                    .await
                    .map_err(|_| "could not read mailbox".to_string())?
                    .try_collect()
                    .await
                    .map_err(|_| "could not read mailbox".to_string())?;
                for f in fetches {
                    let (Some(uid), Some(env)) = (f.uid, f.envelope()) else {
                        continue;
                    };
                    let from = first_addr(env.from.as_ref());
                    let Some((from_addr, from_name)) = from.into_iter().next() else {
                        continue;
                    };
                    let to = first_addr(env.to.as_ref());
                    out.push(Envelope {
                        mailbox: mailbox.clone(),
                        uid,
                        date: f.internal_date().map(|d| d.timestamp()).unwrap_or(0),
                        from: from_addr,
                        from_name,
                        to_names: to.iter().map(|t| t.1.clone()).collect(),
                        to: to.into_iter().map(|t| t.0).collect(),
                        subject: env
                            .subject
                            .as_ref()
                            .map(|s| String::from_utf8_lossy(s).into_owned()),
                    });
                }
            }
            let _ = session.logout().await;
            Ok(out)
        })
        .await
        .map_err(|_| "mail server did not answer in time".to_string())?
    }

    async fn fetch(&self, c: &MailConfig, mailbox: &str, uid: u32) -> Result<RawMail, String> {
        tokio::time::timeout(OP_TIMEOUT, async {
            let mut session = self.imap(c).await?;
            session
                .examine(mailbox)
                .await
                .map_err(|_| "mailbox not found".to_string())?;
            // BODY.PEEK never sets \Seen; the partial range caps huge messages.
            let fetches: Vec<_> = session
                .uid_fetch(uid.to_string(), format!("BODY.PEEK[]<0.{MAX_BODY}>"))
                .await
                .map_err(|_| "could not read message".to_string())?
                .try_collect()
                .await
                .map_err(|_| "could not read message".to_string())?;
            let _ = session.logout().await;
            let bytes = fetches
                .iter()
                .find_map(|f| f.body())
                .ok_or_else(|| "message not found".to_string())?
                .to_vec();
            Ok(RawMail { bytes })
        })
        .await
        .map_err(|_| "mail server did not answer in time".to_string())?
    }

    async fn send(&self, c: &MailConfig, to: &str, text: &str) -> Result<(), String> {
        let from: Mailbox = c
            .email
            .parse()
            .map_err(|_| "invalid sender address".to_string())?;
        let to: Mailbox = to
            .parse()
            .map_err(|_| "invalid recipient address".to_string())?;
        let message = Message::builder()
            .from(from)
            .to(to)
            .subject("(no subject)")
            .body(text.to_string())
            .map_err(|_| "could not build message".to_string())?;
        tokio::time::timeout(OP_TIMEOUT, async {
            self.smtp_for(c)
                .await?
                .send(message)
                .await
                .map(|_| ())
                .map_err(|_| "SMTP send failed".to_string())
        })
        .await
        .map_err(|_| "mail server did not answer in time".to_string())?
    }
}
