-- +goose Up
-- identities
CREATE TABLE identities (
    id BIGINT PRIMARY KEY,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    status SMALLINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NULL,

    CONSTRAINT identities_email_unique UNIQUE (email)
);

CREATE INDEX identities_email_idx ON identities (email);

-- accounts
CREATE TABLE accounts (
    id BIGINT PRIMARY KEY,
    identity_id BIGINT NOT NULL,
    provider SMALLINT NOT NULL,
    provider_account_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NULL,

    CONSTRAINT accounts_identity_fk
        FOREIGN KEY (identity_id)
        REFERENCES identities (id)
        ON DELETE CASCADE,

    CONSTRAINT accounts_provider_provider_account_id_unique
        UNIQUE (provider, provider_account_id)
);

CREATE INDEX accounts_identity_id_idx ON accounts (identity_id);

-- identity_credentials
CREATE TABLE identity_credentials (
    id BIGINT PRIMARY KEY,
    identity_id BIGINT NOT NULL,
    type SMALLINT NOT NULL,
    password_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NULL,

    CONSTRAINT identity_credentials_identity_fk
        FOREIGN KEY (identity_id)
        REFERENCES identities (id)
        ON DELETE CASCADE
);

CREATE UNIQUE INDEX identity_credentials_password_identity_type_idx
    ON identity_credentials (identity_id)
    WHERE type = 1; -- 1 is type password

-- +goose Down
DROP TABLE identity_credentials;
DROP TABLE accounts;
DROP TABLE identities;