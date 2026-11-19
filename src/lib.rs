//! secure-file-share: a small self-hosted service for sharing one file with
//! one link. Stateless (Postgres holds every byte), zero-knowledge for
//! browser uploads (the key lives in the URL fragment and never reaches
//! this process), MIT-licensed.

pub mod config;
pub mod control;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod handlers;
pub mod import;
pub mod metrics;
pub mod router;
pub mod state;
pub mod sweep;
