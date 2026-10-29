CREATE TABLE IF NOT EXISTS build_records (
    id                 BIGSERIAL PRIMARY KEY,
    repository         TEXT NOT NULL,
    git_commit         TEXT NOT NULL,
    git_tag            TEXT NOT NULL,
    measurement        TEXT NOT NULL,
    committed_at       TIMESTAMPTZ NOT NULL,
    signed_payload     BYTEA NOT NULL,
    signature          BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT build_records_identity_unique
        UNIQUE (repository, git_commit, git_tag, measurement)
);

CREATE INDEX IF NOT EXISTS build_records_git_tag_idx
    ON build_records (git_tag);
CREATE INDEX IF NOT EXISTS build_records_measurement_idx
    ON build_records (measurement);

CREATE TABLE IF NOT EXISTS revocations (
    id                 BIGSERIAL PRIMARY KEY,
    build_record_id    BIGINT NOT NULL UNIQUE REFERENCES build_records(id) ON DELETE RESTRICT,
    reason             TEXT NOT NULL,
    revoked_at         TIMESTAMPTZ NOT NULL,
    signed_payload     BYTEA NOT NULL,
    signature          BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
