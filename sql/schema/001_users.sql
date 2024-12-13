-- +goose Up
CREATE TABLE users(
   id UUID PRIMARY KEY,
   created_at TIMESTAMP NOT NULL,
   updated_at TIMESTAMP NOT NULL,
   email VARCHAR UNIQUE NOT NULL,
   hashed_password TEXT NOT NULL,
   is_chirpy_red BOOLEAN DEFAULT false
);

-- +goose Down
DROP TABLE users;
--