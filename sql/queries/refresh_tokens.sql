-- name: InsertRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES (
    $1,
    clock_timestamp(),
    clock_timestamp(),
    $2,
    $3,
    $4
)
RETURNING *;
--


-- name: GetRefreshToken :one
SELECT token, user_id, expires_at, revoked_at FROM refresh_tokens WHERE token = $1;
--


-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = $2, updated_at = $3
WHERE token = $1;
--