-- +goose Up
CREATE TABLE blogposts(
   id UUID PRIMARY KEY,
   created_at TIMESTAMP NOT NULL,
   updated_at TIMESTAMP NOT NULL,
   body VARCHAR NOT NULL,
   user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE 
);

-- +goose Down
DROP TABLE blogposts;
--