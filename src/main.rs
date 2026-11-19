//! Startup: read the environment, connect, migrate, start the
//! listeners. Anything misconfigured stops here with one log line per
//! problem, not mid-flight with a mystery. The web port and the metrics
//! port always run; the control plane runs only when its token exists.

use std::{process::exit, sync::Arc, time::Duration};

use secure_file_share::{
    config::Config,
    control, import, metrics, router,
    state::{AppState, Metrics},
    sweep,
};

// Startup reads as one block on purpose: an operator debugging a pod
// follows the sequence top to bottom — config, database, volume,
// listeners — in the order the log lines will appear. Splitting it
// into helpers would scatter that one glance across four functions.
#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(errors) => {
            for error in errors {
                log::error!("{error}");
            }
            exit(1);
        }
    };

    // The pool is deliberately small: one replica does everything this
    // service does, and unused capacity is just a second thing to fail.
    let pool = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => pool,
        Err(error) => {
            log::error!("cannot reach the database: {error}");
            exit(1);
        }
    };
    if let Err(error) = sqlx::migrate!("./migrations").run(&pool).await {
        log::error!("migrations failed: {error}");
        exit(1);
    }
    log::info!("database ready, schema current");

    // The volume directory: create it, then prove it is writable before
    // anything can half-work. A read-only volume is a startup error, not a
    // first-upload surprise.
    if let Err(error) = tokio::fs::create_dir_all(&config.data_dir).await {
        log::error!("cannot create {}: {error}", config.data_dir);
        exit(1);
    }
    let probe = std::path::Path::new(&config.data_dir).join(".write-probe");
    if let Err(error) = tokio::fs::write(&probe, b"probe").await {
        log::error!("cannot write in {}: {error}", config.data_dir);
        exit(1);
    }
    let _ = tokio::fs::remove_file(&probe).await;
    log::info!("blob directory ready: {}", config.data_dir);

    // One shared client for URL imports: connection pooling, a redirect
    // cap, and one place where a future timeout policy would live. The
    // client carries the import guard: its resolver answers only with
    // public addresses unless the operator opted in.
    let http = import::http_client(config.import_allow_private_urls);

    // One instance of the counters, shared by the handlers and the
    // sweeper: the metrics listener is the only window into both.
    let metrics = Arc::new(Metrics::default());
    let state = AppState {
        config: config.clone(),
        pool: pool.clone(),
        metrics: metrics.clone(),
        http,
    };

    tokio::spawn(sweep::run(
        pool.clone(),
        metrics,
        config.data_dir.clone(),
        config.sweep_interval,
    ));

    // Metrics on their own listener, on purpose: the main port faces the
    // internet, and this build_info names the commit behind the running
    // image. Nothing outside the cluster routes to this port.
    match tokio::net::TcpListener::bind(config.metrics_addr).await {
        Ok(listener) => {
            let router = metrics::metrics_router(state.clone());
            tokio::spawn(async move {
                if let Err(error) = axum::serve(listener, router).await {
                    log::error!("metrics listener failed: {error}");
                }
            });
            log::info!("metrics listening on {}", config.metrics_addr);
        }
        Err(error) => {
            log::error!("cannot bind {}: {error}", config.metrics_addr);
            exit(1);
        }
    }

    // The control plane: the only door that deletes a share, so it never
    // rides the public listener. Its own port, its own token, and nothing
    // outside the cluster routes to it — an operator reaches it with a
    // port-forward. No token configured, no door.
    if config.control_token.is_empty() {
        // One info line, not a warning: leaving the control plane off is
        // a valid deployment; the operator who wants the door sets the
        // token and it starts.
        log::info!("control plane disabled: SFS_CONTROL_TOKEN is not set");
    } else {
        match tokio::net::TcpListener::bind(config.control_addr).await {
            Ok(listener) => {
                let router = control::control_router(state.clone());
                tokio::spawn(async move {
                    if let Err(error) = axum::serve(listener, router).await {
                        log::error!("control listener failed: {error}");
                    }
                });
                log::info!("control plane listening on {}", config.control_addr);
            }
            Err(error) => {
                log::error!("cannot bind {}: {}", config.control_addr, error);
                exit(1);
            }
        }
    }

    let listener = match tokio::net::TcpListener::bind(config.listen_addr).await {
        Ok(listener) => listener,
        Err(error) => {
            log::error!("cannot bind {}: {error}", config.listen_addr);
            exit(1);
        }
    };
    log::info!("listening on {}", config.listen_addr);
    let server = axum::serve(listener, router::app(state));
    if let Err(error) = server.with_graceful_shutdown(shutdown_signal()).await {
        log::error!("server failed: {error}");
        exit(1);
    }
    log::info!("shutdown complete");
}

/// Kubernetes sends SIGTERM and gives the pod a grace period; drain it
/// instead of vanishing mid-download.
async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            log::warn!("ctrl_c handler failed");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => log::warn!("SIGTERM handler failed: {error}"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
