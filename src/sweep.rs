//! The expiry sweeper. Expiry is enforced on every read (`expires_at >
//! now()` in every claim and every metadata query); this task only reclaims
//! storage, so an hourly pass is plenty.

use std::time::Duration;

use sqlx::PgPool;

/// Delete everything past its usefulness:
/// - shares past `expires_at`;
/// - burn-after-reading shares that were claimed but whose stream was
///   dropped before the burn delete ran (the claim set
///   `last_downloaded_at`; give it an hour before calling it abandoned).
pub async fn run(pool: PgPool, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        match sqlx::query(
            "DELETE FROM shares WHERE expires_at < now() \
             OR (one_time AND downloads > 0 \
                 AND last_downloaded_at < now() - interval '1 hour')",
        )
        .execute(&pool)
        .await
        {
            Ok(result) => {
                if result.rows_affected() > 0 {
                    log::info!("sweeper removed {} shares", result.rows_affected());
                }
            }
            Err(error) => log::error!("sweeper failed: {error}"),
        }
    }
}
