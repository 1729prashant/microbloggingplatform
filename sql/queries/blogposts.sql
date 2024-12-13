-- name: CreateBlogPost :one
INSERT INTO blogposts (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(),
    clock_timestamp(),
    clock_timestamp(),
    $1,
    $2
)
RETURNING *;
--



-- name: GetAllBlogPosts :many
SELECT id, created_at, updated_at, body, user_id FROM blogposts
ORDER BY created_at ASC;
--



-- name: GetBlogPost :one
SELECT id, created_at, updated_at, body, user_id 
FROM blogposts 
WHERE id = $1 
LIMIT 1;
--


-- name: DeleteBlogPost :exec
DELETE FROM blogposts
WHERE id = $1 AND user_id = $2;
--