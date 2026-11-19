-- One row per share. The ciphertext itself lives in share_chunks; this table
-- holds only the bookkeeping the server needs to serve, count and expire a
-- share, and nothing it could decrypt: no file name, no MIME type, no hash of
-- the plaintext. An admin listing the table learns sizes and timestamps, and
-- that is all there is to learn.
CREATE TABLE shares (
    id                TEXT PRIMARY KEY,
    -- Bytes actually stored across all frames, ciphertext included.
    stored_size       BIGINT  NOT NULL,
    -- 0 until the writer commits the real count: the share row exists
    -- before its chunks do, inside the writer's transaction. A count below
    -- 2 is a stream the application refused; the constraint that matters
    -- lives in ShareWriter::finish, not here, because a CHECK would have
    -- to allow the in-transaction placeholder.
    chunk_count       INTEGER NOT NULL,
    one_time          BOOLEAN NOT NULL DEFAULT FALSE,
    downloads         INTEGER NOT NULL DEFAULT 0 CHECK (downloads >= 0),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL,
    last_downloaded_at TIMESTAMPTZ
);

-- One row per frame. A frame's data is the 12-byte AES-GCM nonce followed by
-- the ciphertext and tag; the 4-byte length prefix that frames carry on the
-- wire is not stored, it is re-added on download. seq 0 is the encrypted
-- metadata chunk (file name, MIME type, size); the last frame is the empty
-- end-of-stream marker.
CREATE TABLE share_chunks (
    share_id TEXT NOT NULL REFERENCES shares (id) ON DELETE CASCADE,
    seq      INTEGER NOT NULL CHECK (seq >= 0),
    data     BYTEA NOT NULL,
    PRIMARY KEY (share_id, seq)
);

-- The expiry sweeper scans by expires_at; without this it is a sequential scan
-- on every pass.
CREATE INDEX shares_expires_at_idx ON shares (expires_at);
