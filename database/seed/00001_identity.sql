-- +goose Up

INSERT INTO users (id, email, name, status)
VALUES (1, 'admin@oryon.com', 'Administrator', 1)
ON CONFLICT (id) DO NOTHING;

INSERT INTO credentials (id, user_id, type, password_hash)
VALUES (1, 1, 1, '$argon2id$v=19$m=32768,t=3,p=2$LjGWAFbpnzvaFWj/8lGmNA$irLWOT5g2ftYajO2pMmbkJzTzAL9N510N/LXWqRnBrw')
ON CONFLICT (id) DO NOTHING;

-- +goose Down
DELETE FROM credentials WHERE id = 1;
DELETE FROM users WHERE id = 1;