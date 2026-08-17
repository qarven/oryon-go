-- +goose Up
CREATE TABLE users (
    id BIGINT PRIMARY KEY,
    status SMALLINT NOT NULL,
    name TEXT NOT NULL,
    avatar_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
COMMENT ON COLUMN users.status IS '1=active, 2=inactive, 3=locked, 4=suspended, 5=deleted';

CREATE TABLE user_emails (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);
CREATE INDEX user_emails_user_idx ON user_emails(user_id);
CREATE UNIQUE INDEX user_emails_email_idx ON user_emails(email) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX user_emails_one_primary_idx ON user_emails(user_id) WHERE is_primary = TRUE AND deleted_at IS NULL;
COMMENT ON COLUMN user_emails.is_primary IS 'User not allow two emails have is_primary=true';

CREATE TABLE user_phone_numbers (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    phone TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);
CREATE INDEX user_phone_numbers_user_idx ON user_phone_numbers(user_id);
CREATE UNIQUE INDEX user_phone_numbers_phone_idx ON user_phone_numbers(phone) WHERE deleted_at IS NULL;
COMMENT ON COLUMN user_phone_numbers.phone IS 'Phone number stored in E.164 international format (+1234567890).';

CREATE TABLE password_credentials (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password TEXT NOT NULL,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON COLUMN password_credentials.password IS 'Hash value using Argon2id (preferred) or bcrypt';

CREATE TABLE identities (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider SMALLINT NOT NULL,
    provider_subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX identities_user_idx ON identities(user_id);
CREATE UNIQUE INDEX identities_user_provider_idx ON identities(user_id, provider) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX identities_provider_subject_idx ON identities(provider, provider_subject) WHERE revoked_at IS NULL;
COMMENT ON COLUMN identities.provider IS '1=google, 2=apple, 3=github, 4=facebook, 5=microsoft';

CREATE TABLE auth_flows (
    id BIGINT PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE, -- Nullable initially if it's a registration flow
    flow_type SMALLINT NOT NULL,
    flow_state SMALLINT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    context JSONB NOT NULL DEFAULT '{}', -- Store redirect URLs, requested scopes, or selected MFA methods
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL, -- Short lived, e.g., 15 minutes
    completed_at TIMESTAMPTZ
);
CREATE INDEX auth_flows_user_idx ON auth_flows(user_id);
CREATE INDEX auth_flows_expires_idx ON auth_flows(expires_at) WHERE completed_at IS NULL;
COMMENT ON COLUMN auth_flows.flow_type IS '1=registration, 2=login, 3=recovery, 4=step_up_mfa';
COMMENT ON COLUMN auth_flows.flow_state IS '1=pending_identifier, 2=pending_password, 3=pending_mfa, 4=pending_verification, 5=completed, 6=failed';

CREATE TABLE sessions (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    ip_address INET,
    user_agent TEXT,
    mfa_verified_at TIMESTAMPTZ
);
CREATE INDEX sessions_user_idx ON sessions(user_id);
CREATE INDEX sessions_active_idx ON sessions(user_id, expires_at) WHERE revoked_at IS NULL;
COMMENT ON COLUMN sessions.token IS 'Hash value using SHA-256 of the actual session token sent to client';

CREATE TABLE refresh_tokens (
    id BIGINT PRIMARY KEY,
    session_id BIGINT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    token BYTEA NOT NULL UNIQUE,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    replaced_by BIGINT REFERENCES refresh_tokens(id),
    created_ip INET
);
CREATE INDEX refresh_tokens_session_idx ON refresh_tokens(session_id);
COMMENT ON COLUMN refresh_tokens.token IS 'Hash value using SHA-256 of the actual refresh token';

CREATE TABLE passkeys (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    name TEXT NOT NULL,
    aaguid TEXT, -- Useful for restricting allowed authenticator models
    transports TEXT[],
    device_type TEXT,
    backed_up BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX passkeys_user_idx ON passkeys(user_id);

CREATE TABLE mfa_factors (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type SMALLINT NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX mfa_factors_user_idx ON mfa_factors(user_id);
COMMENT ON COLUMN mfa_factors.type IS '1=totp, 2=sms, 3=email, 4=webauthn, 5=backup_code';

CREATE TABLE totp_factors (
    factor_id BIGINT PRIMARY KEY REFERENCES mfa_factors(id) ON DELETE CASCADE,
    secret BYTEA NOT NULL,
    algorithm SMALLINT NOT NULL DEFAULT 1,
    digits SMALLINT NOT NULL DEFAULT 6 CHECK (digits IN (6, 8)),
    period SMALLINT NOT NULL DEFAULT 30 CHECK (period > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON COLUMN totp_factors.algorithm IS '1=SHA1, 2=SHA256, 3=SHA512';
COMMENT ON COLUMN totp_factors.secret IS 'Encrypted value using AES-256-GCM or equivalent authenticated encryption';

CREATE TABLE backup_codes (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code BYTEA NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX backup_codes_user_idx ON backup_codes(user_id);
COMMENT ON COLUMN backup_codes.code IS 'Hash value using SHA-256 or bcrypt (preferred, since they are treated like passwords)';

CREATE TABLE verification_challenges (
    id BIGINT PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    flow_id BIGINT REFERENCES auth_flows(id) ON DELETE CASCADE,
    identifier TEXT NOT NULL, -- E.g., 'user@email.com' or '+1234567890' (critical for pre-registration flows)
    purpose SMALLINT NOT NULL,
    code BYTEA,
    attempts SMALLINT NOT NULL DEFAULT 0,
    max_attempts SMALLINT NOT NULL DEFAULT 3,
    ip_address INET, -- Added to mitigate brute force & rate limit abuse
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX verification_challenges_user_idx ON verification_challenges(user_id);
CREATE INDEX verification_challenges_identifier_idx ON verification_challenges(identifier, expires_at);
COMMENT ON COLUMN verification_challenges.purpose IS '1=email_verification, 2=phone_verification, 3=password_reset, 4=mfa_verification, 5=magic_link';
COMMENT ON COLUMN verification_challenges.code IS 'Hash value using SHA-256 of the OTP or Magic Link token sent';

CREATE TABLE security_events (
    id BIGINT PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX security_events_user_created_idx ON security_events(user_id, created_at DESC);
CREATE INDEX security_events_type_created_idx ON security_events(event_type, created_at DESC);
COMMENT ON COLUMN security_events.event_type IS 'Examples: user.created, email.verified, login.failed, password.changed, mfa.enabled';

-- +goose Down
DROP TABLE security_events;
DROP TABLE verification_challenges;
DROP TABLE backup_codes;
DROP TABLE totp_factors;
DROP TABLE mfa_factors;
DROP TABLE passkeys;
DROP TABLE refresh_tokens;
DROP TABLE sessions;
DROP TABLE auth_flows;
DROP TABLE identities;
DROP TABLE password_credentials;
DROP TABLE user_phone_numbers;
DROP TABLE user_emails;
DROP TABLE users;
