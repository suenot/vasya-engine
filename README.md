# vasya-engine

The single source of truth for the Vasya messenger engine, shared by every client:

- `crates/vasya-channel`: provider-neutral `ChannelProvider` trait, `Capabilities`, normalized chat/message types and the `ProviderRegistry` (enable/disable at runtime, sessions kept).
- `crates/vasya-core`: Tauri-free Telegram engine (grammers): sessions, updates, media, STT, translation.
- `crates/vasya-server`: REST / GraphQL / SSE API over the core (library and standalone binary). Hosts the Telegram `ChannelProvider` adapter and `/api/v1/providers` (list, accounts, admin-only enable/disable, saved in `providers.json`).
- `vendor/grammers-session`: patched grammers-session (channel-id range fix).

Used by [vasyaapp](https://github.com/suenot/vasyaapp) (Tauri + web) and
[vasyaapp-native](https://github.com/suenot/vasyaapp-native) (GPUI, Iced) as a git
dependency pinned to a tag. Fix a bug here once and every client gets it.

## Use it

```toml
[dependencies]
vasya-core = { git = "https://github.com/suenot/vasya-engine", tag = "v0.1.0" }

[patch.crates-io]
grammers-session = { git = "https://github.com/suenot/vasya-engine", tag = "v0.1.0" }
```

## Check

```sh
cargo test --workspace
```

Next step: the `vasya-channel` provider contract (Telegram, Email, WhatsApp as
pluggable modules). Design: `docs/provider-modules.md` in the vasya-workspace repo.
