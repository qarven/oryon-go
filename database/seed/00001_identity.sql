-- +goose Up

INSERT INTO users (id, status, name)
VALUES (1, 1, 'Administrator')
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_emails (id, user_id, email, is_primary, verified_at)
VALUES (1, 1, 'admin@oryon.com', TRUE, NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO password_credentials (user_id, password)
VALUES (1, '$argon2id$v=19$m=32768,t=3,p=2$LjGWAFbpnzvaFWj/8lGmNA$irLWOT5g2ftYajO2pMmbkJzTzAL9N510N/LXWqRnBrw')
ON CONFLICT (user_id) DO NOTHING;

-- +goose Down
DELETE FROM password_credentials WHERE user_id = 1;
DELETE FROM user_emails WHERE user_id = 1;
DELETE FROM users WHERE id = 1;
