-- name: GetIdentityByEmail :one
SELECT id, email, name, status
FROM identities
WHERE lower(email) = lower(@email);

-- name: GetIdentityByID :one
SELECT id, email, name, status
FROM identities
WHERE id = @id;

-- name: ListIdentities :many
SELECT id, email, name, status, COUNT(*) OVER() AS total_count
FROM identities
WHERE (@email IS NULL OR lower(email) = lower(@email))
  AND (@name IS NULL OR name ILIKE '%' || @name || '%')
ORDER BY id
LIMIT @limit_rows OFFSET @offset_rows;

-- name: GetIdentityCredentialByIdentityID :one
SELECT id, identity_id, type, password_hash
FROM identity_credentials
WHERE identity_id = @identity_id
  AND type = @type;