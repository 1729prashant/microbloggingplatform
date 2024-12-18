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
SELECT hashed_password, id, created_at, updated_at, email, is_chirpy_red FROM users 
WHERE email = $1
LIMIT 1;
--


-- name: UpdateUser :exec
UPDATE users
SET email = $2, hashed_password = $3, updated_at = clock_timestamp()
WHERE id = $1;
--


-- name: GetUser :one
SELECT id, created_at, updated_at, email FROM users 
WHERE id = $1;
--


-- name: UpgradeToChirpyRed :exec
UPDATE users
SET is_chirpy_red = TRUE, updated_at = clock_timestamp()
WHERE id = $1;
--