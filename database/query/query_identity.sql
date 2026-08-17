-- name: CreateUser :exec
INSERT INTO users (id, status, name, avatar_url, created_at, updated_at, deleted_at)
VALUES (@id, @status, @name, @avatar_url, @created_at, @updated_at, @deleted_at);

-- name: GetUserByID :one
SELECT id, status, name, avatar_url, created_at, updated_at, deleted_at
FROM users
WHERE id = @id;

-- name: UpdateUser :exec
UPDATE users SET status = @status, name = @name, avatar_url = @avatar_url, updated_at = @updated_at, deleted_at = @deleted_at
WHERE id = @id;

-- name: CreateUserEmail :exec
INSERT INTO user_emails (id, user_id, email, is_primary, created_at, verified_at, deleted_at)
VALUES (@id, @user_id, @email, @is_primary, @created_at, @verified_at, @deleted_at);

-- name: GetUserEmailByID :one
SELECT id, user_id, email, is_primary, created_at, verified_at, deleted_at
FROM user_emails
WHERE id = @id;

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

-- name: ListUserEmailsByUserID :many
SELECT id, user_id, email, is_primary, created_at, verified_at, deleted_at
FROM user_emails
WHERE user_id = @user_id AND deleted_at IS NULL
ORDER BY is_primary DESC, created_at;

-- name: ListUserEmailsByUserIDAll :many
SELECT id, user_id, email, is_primary, created_at, verified_at, deleted_at
FROM user_emails
WHERE user_id = @user_id
ORDER BY is_primary DESC, created_at;

-- name: UpdateUserEmail :exec
UPDATE user_emails SET email = @email, is_primary = @is_primary, verified_at = @verified_at, deleted_at = @deleted_at
WHERE id = @id;

-- name: CountUserEmails :one
SELECT COUNT(*) FROM user_emails WHERE user_id = @user_id AND deleted_at IS NULL;

-- name: ClearPrimaryEmails :exec
UPDATE user_emails SET is_primary = false WHERE user_id = @user_id AND deleted_at IS NULL;

-- name: SetPrimaryEmail :exec
UPDATE user_emails SET is_primary = true WHERE id = @id;

-- name: CreateUserPhoneNumber :exec
INSERT INTO user_phone_numbers (id, user_id, phone, created_at, verified_at, deleted_at)
VALUES (@id, @user_id, @phone, @created_at, @verified_at, @deleted_at);

-- name: GetUserPhoneByPhone :one
SELECT id, user_id, phone, created_at, verified_at, deleted_at
FROM user_phone_numbers
WHERE phone = @phone AND deleted_at IS NULL
LIMIT 1;

-- name: ListPhonesByUserID :many
SELECT id, user_id, phone, created_at, verified_at, deleted_at
FROM user_phone_numbers
WHERE user_id = @user_id AND deleted_at IS NULL
ORDER BY created_at;

-- name: GetUserPhoneByID :one
SELECT id, user_id, phone, created_at, verified_at, deleted_at
FROM user_phone_numbers
WHERE id = @id;

-- name: CreatePasswordCredential :exec
INSERT INTO password_credentials (user_id, password, password_changed_at, created_at, updated_at)
VALUES (@user_id, @password, @password_changed_at, @created_at, @updated_at);

-- name: GetPasswordCredentialByUserID :one
SELECT user_id, password, password_changed_at, created_at, updated_at
FROM password_credentials
WHERE user_id = @user_id;

-- name: UpdatePasswordCredential :exec
UPDATE password_credentials SET password = @password, password_changed_at = @password_changed_at, updated_at = @updated_at
WHERE user_id = @user_id;

-- name: UpsertPasswordCredential :exec
INSERT INTO password_credentials (user_id, password, password_changed_at, created_at, updated_at)
VALUES (@user_id, @password, @password_changed_at, @created_at, @updated_at)
ON CONFLICT (user_id) DO UPDATE SET password = EXCLUDED.password, password_changed_at = EXCLUDED.password_changed_at, updated_at = EXCLUDED.updated_at;

-- name: CreateIdentity :exec
INSERT INTO identities (id, user_id, provider, provider_subject, created_at, last_used_at, revoked_at)
VALUES (@id, @user_id, @provider, @provider_subject, @created_at, @last_used_at, @revoked_at);

-- name: GetIdentityByProviderSubject :one
SELECT id, user_id, provider, provider_subject, created_at, last_used_at, revoked_at
FROM identities
WHERE provider = @provider AND provider_subject = @provider_subject AND revoked_at IS NULL
LIMIT 1;

-- name: ListIdentitiesByUserID :many
SELECT id, user_id, provider, provider_subject, created_at, last_used_at, revoked_at
FROM identities
WHERE user_id = @user_id AND revoked_at IS NULL
ORDER BY created_at;

-- name: RevokeIdentity :exec
UPDATE identities SET revoked_at = @revoked_at WHERE id = @id AND revoked_at IS NULL;

-- name: CreateAuthFlow :exec
INSERT INTO auth_flows (id, user_id, flow_type, flow_state, ip_address, user_agent, context, created_at, expires_at, completed_at)
VALUES (@id, @user_id, @flow_type, @flow_state, @ip_address, @user_agent, @context, @created_at, @expires_at, @completed_at);

-- name: GetAuthFlowByID :one
SELECT id, user_id, flow_type, flow_state, ip_address, user_agent, context, created_at, expires_at, completed_at
FROM auth_flows
WHERE id = @id;

-- name: UpdateAuthFlow :exec
UPDATE auth_flows SET flow_state = @flow_state, context = @context, completed_at = @completed_at
WHERE id = @id;

-- name: CreateSession :exec
INSERT INTO sessions (id, user_id, token, created_at, expires_at, last_seen_at, revoked_at, ip_address, user_agent, mfa_verified_at)
VALUES (@id, @user_id, @token, @created_at, @expires_at, @last_seen_at, @revoked_at, @ip_address, @user_agent, @mfa_verified_at);

-- name: GetSessionByID :one
SELECT id, user_id, token, created_at, expires_at, last_seen_at, revoked_at, ip_address, user_agent, mfa_verified_at
FROM sessions
WHERE id = @id;

-- name: GetSessionByTokenHash :one
SELECT id, user_id, token, created_at, expires_at, last_seen_at, revoked_at, ip_address, user_agent, mfa_verified_at
FROM sessions
WHERE token = @token
LIMIT 1;

-- name: ListSessionsByUserIDAll :many
SELECT id, user_id, token, created_at, expires_at, last_seen_at, revoked_at, ip_address, user_agent, mfa_verified_at
FROM sessions
WHERE user_id = @user_id
ORDER BY created_at DESC;

-- name: UpdateSession :exec
UPDATE sessions SET last_seen_at = @last_seen_at, mfa_verified_at = @mfa_verified_at, revoked_at = @revoked_at, expires_at = @expires_at
WHERE id = @id;

-- name: RevokeSession :exec
UPDATE sessions SET revoked_at = @revoked_at WHERE id = @id AND revoked_at IS NULL;

-- name: RevokeAllOtherSessions :exec
UPDATE sessions SET revoked_at = @revoked_at WHERE user_id = @user_id AND id != @id AND revoked_at IS NULL;

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = @last_seen_at WHERE id = @id;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, session_id, token, issued_at, expires_at, revoked_at, replaced_by, created_ip)
VALUES (@id, @session_id, @token, @issued_at, @expires_at, @revoked_at, @replaced_by, @created_ip);

-- name: GetRefreshTokenByHash :one
SELECT id, session_id, token, issued_at, expires_at, revoked_at, replaced_by, created_ip
FROM refresh_tokens
WHERE token = @token
LIMIT 1;

-- name: GetRefreshTokenByID :one
SELECT id, session_id, token, issued_at, expires_at, revoked_at, replaced_by, created_ip
FROM refresh_tokens
WHERE id = @id;

-- name: UpdateRefreshToken :exec
UPDATE refresh_tokens SET revoked_at = @revoked_at, replaced_by = @replaced_by WHERE id = @id;

-- name: RevokeRefreshTokensBySessionID :exec
UPDATE refresh_tokens SET revoked_at = @revoked_at WHERE session_id = @session_id AND revoked_at IS NULL;

-- name: CreateMfaFactor :exec
INSERT INTO mfa_factors (id, user_id, type, name, created_at, verified_at, last_used_at, revoked_at)
VALUES (@id, @user_id, @type, @name, @created_at, @verified_at, @last_used_at, @revoked_at);

-- name: GetMfaFactorByID :one
SELECT id, user_id, type, name, created_at, verified_at, last_used_at, revoked_at
FROM mfa_factors
WHERE id = @id;

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

-- name: UpdateMfaFactor :exec
UPDATE mfa_factors SET name = @name, verified_at = @verified_at, last_used_at = @last_used_at, revoked_at = @revoked_at
WHERE id = @id;

-- name: CreateTotpFactor :exec
INSERT INTO totp_factors (factor_id, secret, algorithm, digits, period, created_at)
VALUES (@factor_id, @secret, @algorithm, @digits, @period, @created_at);

-- name: GetTotpFactorByFactorID :one
SELECT factor_id, secret, algorithm, digits, period, created_at
FROM totp_factors
WHERE factor_id = @factor_id;

-- name: UpdateTotpSecret :exec
UPDATE totp_factors SET secret = @secret WHERE factor_id = @factor_id;

-- name: DeleteTotpFactor :exec
DELETE FROM totp_factors WHERE factor_id = @factor_id;

-- name: CreateBackupCode :exec
INSERT INTO backup_codes (id, user_id, code, used_at, created_at)
VALUES (@id, @user_id, @code, @used_at, @created_at);

-- name: ListBackupCodesByUserID :many
SELECT id, user_id, code, used_at, created_at
FROM backup_codes
WHERE user_id = @user_id
ORDER BY created_at;

-- name: CountUnusedBackupCodes :one
SELECT COUNT(*) FROM backup_codes WHERE user_id = @user_id AND used_at IS NULL;

-- name: DeleteBackupCodesByUserID :exec
DELETE FROM backup_codes WHERE user_id = @user_id;

-- name: FindUnusedBackupCodeByHash :one
SELECT id, user_id, code, used_at, created_at
FROM backup_codes
WHERE user_id = @user_id AND code = @code AND used_at IS NULL
LIMIT 1;

-- name: MarkBackupCodeUsed :exec
UPDATE backup_codes SET used_at = @used_at WHERE id = @id AND used_at IS NULL;

-- name: GetBackupCodesForVerification :many
SELECT id, user_id, code, used_at, created_at
FROM backup_codes
WHERE user_id = @user_id AND used_at IS NULL;

-- name: CreatePasskey :exec
INSERT INTO passkeys (id, user_id, credential_id, public_key, sign_count, name, aaguid, transports, device_type, backed_up, created_at, last_used_at, revoked_at)
VALUES (@id, @user_id, @credential_id, @public_key, @sign_count, @name, @aaguid, @transports, @device_type, @backed_up, @created_at, @last_used_at, @revoked_at);

-- name: GetPasskeyByID :one
SELECT id, user_id, credential_id, public_key, sign_count, name, aaguid, transports, device_type, backed_up, created_at, last_used_at, revoked_at
FROM passkeys
WHERE id = @id;

-- name: GetPasskeyByCredentialID :one
SELECT id, user_id, credential_id, public_key, sign_count, name, aaguid, transports, device_type, backed_up, created_at, last_used_at, revoked_at
FROM passkeys
WHERE credential_id = @credential_id AND revoked_at IS NULL
LIMIT 1;

-- name: ListPasskeysByUserID :many
SELECT id, user_id, credential_id, public_key, sign_count, name, aaguid, transports, device_type, backed_up, created_at, last_used_at, revoked_at
FROM passkeys
WHERE user_id = @user_id
ORDER BY created_at;

-- name: ListPasskeysByUserIDActive :many
SELECT id, user_id, credential_id, public_key, sign_count, name, aaguid, transports, device_type, backed_up, created_at, last_used_at, revoked_at
FROM passkeys
WHERE user_id = @user_id AND revoked_at IS NULL
ORDER BY created_at;

-- name: UpdatePasskey :exec
UPDATE passkeys SET sign_count = @sign_count, last_used_at = @last_used_at, revoked_at = @revoked_at, name = @name
WHERE id = @id;

-- name: CreateVerificationChallenge :exec
INSERT INTO verification_challenges (id, user_id, flow_id, identifier, purpose, code, attempts, max_attempts, ip_address, expires_at, consumed_at, created_at)
VALUES (@id, @user_id, @flow_id, @identifier, @purpose, @code, @attempts, @max_attempts, @ip_address, @expires_at, @consumed_at, @created_at);

-- name: GetVerificationChallengeByID :one
SELECT id, user_id, flow_id, identifier, purpose, code, attempts, max_attempts, ip_address, expires_at, consumed_at, created_at
FROM verification_challenges
WHERE id = @id;

-- name: GetVerificationByIdentifierPurpose :many
SELECT id, user_id, flow_id, identifier, purpose, code, attempts, max_attempts, ip_address, expires_at, consumed_at, created_at
FROM verification_challenges
WHERE identifier = @identifier AND purpose = @purpose AND consumed_at IS NULL AND expires_at > NOW()
ORDER BY created_at DESC;

-- name: GetVerificationChallengeByHash :one
SELECT id, user_id, flow_id, identifier, purpose, code, attempts, max_attempts, ip_address, expires_at, consumed_at, created_at
FROM verification_challenges
WHERE code = @code AND purpose = @purpose AND consumed_at IS NULL AND expires_at > NOW()
ORDER BY created_at DESC
LIMIT 1;

-- name: UpdateVerificationChallenge :exec
UPDATE verification_challenges SET attempts = @attempts, consumed_at = @consumed_at
WHERE id = @id;

-- name: IncrementVerificationAttempts :exec
UPDATE verification_challenges SET attempts = attempts + 1 WHERE id = @id;

-- name: ConsumeVerificationChallenge :exec
UPDATE verification_challenges SET consumed_at = @consumed_at WHERE id = @id AND consumed_at IS NULL;

-- name: CreateSecurityEvent :exec
INSERT INTO security_events (id, user_id, event_type, ip_address, user_agent, metadata, created_at)
VALUES (@id, @user_id, @event_type, @ip_address, @user_agent, @metadata, @created_at);

-- name: ListSecurityEventsByUserID :many
SELECT id, user_id, event_type, ip_address, user_agent, metadata, created_at
FROM security_events
WHERE user_id = @user_id
ORDER BY created_at DESC;
