-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    clock_timestamp(),
    clock_timestamp(),
    $1,
    $2
)
RETURNING *;
--

-- name: DeleteAllUsers :exec
DELETE FROM users;
--

-- name: GetEncryptedPassword :one
SELECT hashed_password, id, created_at, updated_at, email FROM users 
WHERE email = $1
LIMIT 1;
--