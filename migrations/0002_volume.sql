-- v0.2.0 moved the ciphertext to volume files: one <id>.sfs file per share,
-- streamed to and from disk, so a share is bounded by the volume, not by
-- what is healthy for a database to hold. The database keeps exactly what
-- it kept before minus the chunk rows: bookkeeping a claim can be decided
-- on atomically. Nothing decryptable ever lived in either place, so there
-- is no data to migrate, only a table whose contents are now on the volume
-- (and every deployment of v0.1.0 predates any production use, so no rows
-- exist to move anyway).
DROP TABLE share_chunks;

-- Described rows that no longer exist; the blob file has a size, the row
-- has stored_size.
ALTER TABLE shares DROP COLUMN chunk_count;
