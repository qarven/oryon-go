-- +goose Up
-- users
CREATE TABLE users (
    id BIGINT PRIMARY KEY,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    status SMALLINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NULL,

    CONSTRAINT users_email_unique UNIQUE (email)
);

CREATE INDEX users_email_idx ON users (email);

-- accounts
CREATE TABLE accounts (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    provider SMALLINT NOT NULL,
    provider_account_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NULL,

    CONSTRAINT accounts_user_fk
        FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE CASCADE,

    CONSTRAINT accounts_provider_provider_account_id_unique
        UNIQUE (provider, provider_account_id)
);

CREATE INDEX accounts_user_id_idx ON accounts (user_id);

-- credentials
CREATE TABLE credentials (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    type SMALLINT NOT NULL,
    password_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NULL,

    CONSTRAINT credentials_user_fk
        FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE CASCADE
);

CREATE UNIQUE INDEX credentials_password_user_type_idx
    ON credentials (user_id)
    WHERE type = 1; -- 1 is type password

-- +goose Down
DROP TABLE credentials;
DROP TABLE accounts;
DROP TABLE users;