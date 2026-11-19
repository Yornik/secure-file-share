//! All configuration arrives as environment variables and is read exactly
//! once, at startup. There is no config file on purpose: the deployment is
//! one stateless container plus a database, and every tunable has a default
//! an operator only overrides on purpose.

use std::{env, net::SocketAddr, time::Duration};

/// Everything the running binary needs. Cloned into the application state;
/// cheap, it is all small strings and numbers.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub metrics_addr: SocketAddr,
    pub database_url: String,
    /// Directory on a persistent volume where ciphertext blobs live: one
    /// `<id>.sfs` file per share. The database holds only bookkeeping, so
    /// the blob ceiling is the volume, not what is healthy for a database.
    pub data_dir: String,
    pub admin_token: String,
    pub base_url: String,
    /// Hard ceiling on stored ciphertext per share, browser upload and URL
    /// import alike. Enforced frame by frame, not by trusting Content-Length.
    pub max_upload_bytes: u64,
    /// Ceiling for the plaintext pulled in by a URL import. Separate from the
    /// upload limit because an import reads the whole file through this
    /// process's memory before it is stored.
    pub import_max_bytes: u64,
    /// Default lifetime for a new share, in days, when the request does not
    /// ask for one explicitly.
    pub default_ttl_days: u64,
    /// Ceiling on any requested lifetime, in days.
    pub max_ttl_days: u64,
    pub sweep_interval: Duration,
}

impl Config {
    /// Read the environment and report every problem in one pass, so an
    /// operator fixes the whole deployment on one look at the logs instead of
    /// one variable per restart.
    // Reads as one block on purpose: every variable of the deployment, in
    // the order they appear in the README table. Splitting it into helpers
    // would spread the one-glance validation across four functions.
    #[allow(clippy::too_many_lines)]
    pub fn from_env() -> Result<Self, Vec<String>> {
        let mut errors = Vec::new();

        let listen_addr = parse_addr(
            env::var("SFS_LISTEN_ADDR"),
            "SFS_LISTEN_ADDR",
            "0.0.0.0:8080",
            &mut errors,
        );
        let metrics_addr = parse_addr(
            env::var("SFS_METRICS_ADDR"),
            "SFS_METRICS_ADDR",
            "0.0.0.0:9090",
            &mut errors,
        );
        let database_url = required("DATABASE_URL", &mut errors);
        let data_dir = optional("SFS_DATA_DIR", "/var/lib/secure-file-share");
        let admin_token = required("SFS_ADMIN_TOKEN", &mut errors);
        if let Some(token) = admin_token.as_deref()
            && token.len() < 16
        {
            errors.push(format!(
                "SFS_ADMIN_TOKEN is {len} characters; 16 minimum, so tokens are never guessable",
                len = token.len()
            ));
        }
        let base_url = required("SFS_BASE_URL", &mut errors);
        if let Some(url) = base_url.as_deref()
            && !(url.starts_with("http://") || url.starts_with("https://"))
        {
            errors.push("SFS_BASE_URL must start with http:// or https:// (it is used to build share links)".to_owned());
        }

        // 2 GiB, not 512 MiB: the blobs live on a volume now, so the ceiling
        // is what the volume and the browser can carry, not what a database
        // row should be asked to hold. An operator raises or lowers it on
        // purpose.
        let max_upload_bytes = parse_u64(
            env::var("SFS_MAX_UPLOAD_BYTES"),
            "SFS_MAX_UPLOAD_BYTES",
            2 * 1024 * 1024 * 1024,
            &mut errors,
        );
        let import_max_bytes = parse_u64(
            env::var("SFS_IMPORT_MAX_BYTES"),
            "SFS_IMPORT_MAX_BYTES",
            2 * 1024 * 1024 * 1024,
            &mut errors,
        );
        let default_ttl_days = parse_u64(
            env::var("SFS_DEFAULT_TTL_DAYS"),
            "SFS_DEFAULT_TTL_DAYS",
            7,
            &mut errors,
        );
        let max_ttl_days = parse_u64(
            env::var("SFS_MAX_TTL_DAYS"),
            "SFS_MAX_TTL_DAYS",
            90,
            &mut errors,
        );
        let sweep_secs = parse_u64(
            env::var("SFS_SWEEP_SECS"),
            "SFS_SWEEP_SECS",
            3600,
            &mut errors,
        );

        if default_ttl_days.is_some_and(|d| d == 0) {
            errors.push("SFS_DEFAULT_TTL_DAYS must be at least 1; a share that expires instantly cannot be downloaded".to_owned());
        }
        if let (Some(default), Some(max)) = (default_ttl_days, max_ttl_days)
            && default > max
        {
            errors.push("SFS_DEFAULT_TTL_DAYS is larger than SFS_MAX_TTL_DAYS".to_owned());
        }

        match (
            listen_addr,
            metrics_addr,
            database_url,
            data_dir,
            admin_token,
            base_url,
            max_upload_bytes,
            import_max_bytes,
            default_ttl_days,
            max_ttl_days,
            sweep_secs,
        ) {
            (
                Some(listen_addr),
                Some(metrics_addr),
                Some(database_url),
                data_dir,
                Some(admin_token),
                Some(base_url),
                Some(max_upload_bytes),
                Some(import_max_bytes),
                Some(default_ttl_days),
                Some(max_ttl_days),
                Some(sweep_secs),
            ) if errors.is_empty() => Ok(Self {
                listen_addr,
                metrics_addr,
                database_url,
                data_dir,
                admin_token,
                base_url: base_url.trim_end_matches('/').to_owned(),
                max_upload_bytes,
                import_max_bytes,
                default_ttl_days,
                max_ttl_days,
                sweep_interval: Duration::from_secs(sweep_secs),
            }),
            _ => Err(errors),
        }
    }
}

fn required(name: &str, errors: &mut Vec<String>) -> Option<String> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => {
            errors.push(format!("{name} is required"));
            None
        }
    }
}

/// A variable with a default: empty means the default, not an error.
fn optional(name: &str, default: &str) -> String {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => default.to_owned(),
    }
}

fn parse_addr(
    raw: Result<String, env::VarError>,
    name: &str,
    default: &str,
    errors: &mut Vec<String>,
) -> Option<SocketAddr> {
    match raw {
        Ok(value) => {
            if let Ok(addr) = value.parse::<SocketAddr>() {
                Some(addr)
            } else {
                errors.push(format!(
                    "{name} is not a socket address (expected like {default})"
                ));
                None
            }
        }
        Err(_) => default.parse::<SocketAddr>().ok(),
    }
}

fn parse_u64(
    raw: Result<String, env::VarError>,
    name: &str,
    default: u64,
    errors: &mut Vec<String>,
) -> Option<u64> {
    match raw {
        Ok(value) => match value.parse::<u64>() {
            Ok(parsed) if parsed > 0 => Some(parsed),
            _ => {
                errors.push(format!("{name} must be a positive integer"));
                None
            }
        },
        Err(_) => Some(default),
    }
}
