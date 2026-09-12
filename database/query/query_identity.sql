-- name: CreateUser :exec
INSERT INTO users (id, status, name, avatar_url, created_at, updated_at, deleted_at)
VALUES (@id, @status, @name, @avatar_url, @created_at, @updated_at, @deleted_at);

-- name: GetUserByID :one
SELECT id, status, name, username, avatar_url, created_at, updated_at, deleted_at
FROM users
WHERE id = @id
LIMIT 1;

-- name: GetUserByUsername :one
SELECT id, status, name, username, avatar_url, created_at, updated_at, deleted_at
FROM users
WHERE username = @username
LIMIT 1;

-- name: CreateUserEmail :exec
INSERT INTO user_emails (id, user_id, email, is_primary, created_at, verified_at, deleted_at)
VALUES (@id, @user_id, @email, @is_primary, @created_at, @verified_at, @deleted_at);

-- name: GetUserEmailByEmail :one
SELECT id, user_id, email, is_primary, created_at, verified_at, deleted_at
FROM user_emails
WHERE lower(email) = lower(@email) AND deleted_at IS NULL
LIMIT 1;

-- name: GetPrimaryUserEmailByUserID :one
SELECT id, user_id, email, is_primary, created_at, verified_at, deleted_at
FROM user_emails
WHERE user_id = @user_id AND is_primary = true AND deleted_at IS NULL
LIMIT 1;

-- name: CreateUserPhoneNumber :exec
INSERT INTO user_phone_numbers (id, user_id, phone, created_at, verified_at, deleted_at)
VALUES (@id, @user_id, @phone, @created_at, @verified_at, @deleted_at);

-- name: GetUserPhoneByPhone :one
SELECT id, user_id, phone, created_at, verified_at, deleted_at
FROM user_phone_numbers
WHERE phone = @phone AND deleted_at IS NULL
LIMIT 1;

-- name: CreatePasswordCredential :exec
INSERT INTO password_credentials (user_id, password, password_changed_at, created_at, updated_at)
VALUES (@user_id, @password, @password_changed_at, @created_at, @updated_at);

-- name: GetPasswordCredentialByUserID :one
SELECT user_id, password, password_changed_at, created_at, updated_at
FROM password_credentials
WHERE user_id = @user_id
LIMIT 1;

-- name: GetAuthFlowByID :one
SELECT id, user_id, flow_type, flow_state, ip_address, user_agent, context, created_at, expires_at, completed_at
FROM auth_flows
WHERE id = @id
LIMIT 1;

-- name: CreateAuthFlow :exec
INSERT INTO auth_flows (id, user_id, flow_type, flow_state, ip_address, user_agent, context, created_at, expires_at, completed_at)
VALUES (@id, @user_id, @flow_type, @flow_state, @ip_address, @user_agent, @context, @created_at, @expires_at, @completed_at);

-- name: CreateSession :exec
INSERT INTO sessions (id, user_id, token, created_at, expires_at, last_seen_at, ip_address, user_agent, mfa_verified_at)
VALUES (@id, @user_id, @token, @created_at, @expires_at, @last_seen_at, @ip_address, @user_agent, @mfa_verified_at);

-- name: GetSessionByID :one
SELECT id, user_id, token, created_at, expires_at, last_seen_at, revoked_at, ip_address, user_agent, mfa_verified_at
FROM sessions
WHERE id = @id
LIMIT 1;

-- name: UpdateSession :exec
UPDATE sessions SET last_seen_at = @last_seen_at, mfa_verified_at = @mfa_verified_at, revoked_at = @revoked_at, expires_at = @expires_at
WHERE id = @id;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, session_id, token, issued_at, expires_at, created_ip)
VALUES (@id, @session_id, @token, @issued_at, @expires_at, @created_ip);

-- name: GetRefreshTokenByHash :one
SELECT id, session_id, token, issued_at, expires_at, revoked_at, replaced_by, created_ip
FROM refresh_tokens
WHERE token = @token
LIMIT 1;

-- name: UpdateRefreshToken :exec
UPDATE refresh_tokens SET revoked_at = @revoked_at, replaced_by = @replaced_by WHERE id = @id;

-- name: GetTotpFactorByFactorID :one
SELECT factor_id, secret, algorithm, digits, period, created_at
FROM totp_factors
WHERE factor_id = @factor_id
LIMIT 1;

-- name: UpdateMfaFactorLastUsedAt :exec
UPDATE mfa_factors SET last_used_at = @last_used_at WHERE id = @id;

-- name: MarkBackupCodeUsed :exec
UPDATE backup_codes SET used_at = @used_at WHERE id = @id;

-- name: UpdateAuthFlow :exec
UPDATE auth_flows SET flow_state = @flow_state, completed_at = @completed_at WHERE id = @id;

-- name: ListMfaFactorsByUserID :many
SELECT id, user_id, type, name, created_at, verified_at, last_used_at, revoked_at
FROM mfa_factors
WHERE user_id = @user_id
ORDER BY created_at;

-- name: ListMfaFactorsByUserIDActive :many
SELECT id, user_id, type, name, created_at, verified_at, last_used_at, revoked_at
FROM mfa_factors
WHERE user_id = @user_id AND revoked_at IS NULL
ORDER BY created_at;

-- name: ListBackupCodesByUserID :many
SELECT id, user_id, code, used_at, created_at
FROM backup_codes
WHERE user_id = @user_id
ORDER BY created_at;

-- name: CreateSecurityEvent :exec
INSERT INTO security_events (id, user_id, event_type, ip_address, user_agent, metadata, created_at)
VALUES (@id, @user_id, @event_type, @ip_address, @user_agent, @metadata, @created_at);

-- name: CreateVerificationChallenge :exec
INSERT INTO verification_challenges (id, user_id, flow_id, identifier, purpose, code, attempts, max_attempts, ip_address, expires_at, consumed_at, created_at)
VALUES (@id, @user_id, @flow_id, @identifier, @purpose, @code, @attempts, @max_attempts, @ip_address, @expires_at, @consumed_at, @created_at);

-- name: GetVerificationChallengeByID :one
SELECT id, user_id, flow_id, identifier, purpose, code, attempts, max_attempts, ip_address, expires_at, consumed_at, created_at
FROM verification_challenges
WHERE id = @id
LIMIT 1;

-- name: ListPendingVerificationChallengesByIdentifier :many
SELECT id, user_id, flow_id, identifier, purpose, code, attempts, max_attempts, ip_address, expires_at, consumed_at, created_at
FROM verification_challenges
WHERE identifier = @identifier
  AND purpose = @purpose
  AND consumed_at IS NULL
  AND expires_at > NOW()
ORDER BY created_at DESC;

-- name: UpdateVerificationChallenge :exec
UPDATE verification_challenges SET attempts = @attempts, consumed_at = @consumed_at WHERE id = @id;

-- name: ConsumeSiblingChallenges :exec
UPDATE verification_challenges SET consumed_at = @consumed_at
WHERE identifier = @identifier
  AND purpose = @purpose
  AND consumed_at IS NULL
  AND id != @except_id;

-- name: DeleteExpiredVerificationChallenges :exec
DELETE FROM verification_challenges WHERE expires_at < NOW() AND consumed_at IS NULL;

-- name: DeleteExpiredAuthFlows :exec
DELETE FROM auth_flows WHERE expires_at < NOW() AND completed_at IS NULL;