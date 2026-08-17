-- name: GetUserByEmail :one
SELECT id, email, name, status
FROM users
WHERE lower(email) = lower(@email);

-- name: GetUserByID :one
SELECT id, email, name, status
FROM users
WHERE id = @id;

-- name: ListUsers :many
SELECT id, email, name, status, COUNT(*) OVER() AS total_count
FROM users
WHERE (@email IS NULL OR lower(email) = lower(@email))
  AND (@name IS NULL OR name ILIKE '%' || @name || '%')
ORDER BY id
LIMIT @limit_rows OFFSET @offset_rows;

-- name: GetCredentialByUserID :one
SELECT id, user_id, type, password_hash
FROM credentials
WHERE user_id = @user_id
  AND type = @type;