-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email)
VALUES (
    gen_random_uuid(),
    clock_timestamp(),
    clock_timestamp(),
    $1
)
RETURNING *;