//! The reclamation sweeper. Expiry is enforced on every read (`expires_at >
//! now()` in every claim and every metadata query); this task only reclaims
//! storage — a blob file and a bookkeeping row — so an hourly pass is
//! plenty.

use std::{path::Path, time::Duration};

use sqlx::PgPool;

/// Delete everything past its usefulness:
/// - bookkeeping rows past `expires_at`, with their blob files;
/// - burn-after-reading rows claimed over an hour ago, with their blobs —
///   the claim keeps the row as a tombstone so the next opener reads 410;
/// - `.tmp-` files older than an hour: the remains of an upload that was
///   malformed or died mid-stream, which `ShareWriter` removes itself but
///   cannot if the process went down first.
pub async fn run(pool: PgPool, data_dir: String, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        let reaped = match sqlx::query_scalar::<_, String>(
            "DELETE FROM shares WHERE expires_at < now() \
             OR (one_time AND downloads > 0 \
                 AND last_downloaded_at < now() - interval '1 hour') \
             RETURNING id",
        )
        .fetch_all(&pool)
        .await
        {
            Ok(ids) => ids,
            Err(error) => {
                log::error!("sweeper query failed: {error}");
                Vec::new()
            }
        };
        for id in &reaped {
            if let Err(error) =
                tokio::fs::remove_file(Path::new(&data_dir).join(format!("{id}.sfs"))).await
            {
                log::warn!("sweeper could not remove the blob of {id}: {error}");
            }
        }
        if !reaped.is_empty() {
            log::info!("sweeper removed {} shares", reaped.len());
        }

        // Orphaned temporaries: an upload that never validated. Named with
        // a second random id, so only the prefix and the age identify
        // them; an hour covers both a dead stream and a dead process.
        let mut orphans = 0_u32;
        let mut listing = match tokio::fs::read_dir(&data_dir).await {
            Ok(listing) => listing,
            Err(error) => {
                log::error!("sweeper cannot read {data_dir}: {error}");
                continue;
            }
        };
        while let Ok(Some(entry)) = listing.next_entry().await {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.contains(".tmp-") {
                continue;
            }
            let too_old = entry
                .metadata()
                .await
                .ok()
                .and_then(|meta| meta.modified().ok())
                .is_some_and(|modified| modified.elapsed().is_ok_and(|age| age.as_secs() > 3600));
            if too_old {
                let path = entry.path();
                if tokio::fs::remove_file(&path).await.is_ok() {
                    orphans += 1;
                }
            }
        }
        if orphans > 0 {
            log::info!("sweeper removed {orphans} leftover temporary blobs");
        }
    }
}
