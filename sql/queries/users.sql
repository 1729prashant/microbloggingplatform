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