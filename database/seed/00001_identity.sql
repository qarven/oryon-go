-- +goose Up

INSERT INTO users (id, status, name, username)
VALUES (1, 1, 'Administrator', 'admin')
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_emails (id, user_id, email, is_primary, verified_at)
VALUES (1, 1, 'admin@oryon.com', TRUE, NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_phone_numbers (id, user_id, phone, verified_at)
VALUES (1, 1, '+6287777777777', NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO password_credentials (user_id, password)
VALUES (1, '$argon2id$v=19$m=32768,t=3,p=2$LjGWAFbpnzvaFWj/8lGmNA$irLWOT5g2ftYajO2pMmbkJzTzAL9N510N/LXWqRnBrw')
ON CONFLICT (user_id) DO NOTHING;

INSERT INTO mfa_factors (id, user_id, type, name, verified_at)
VALUES (1, 1, 1, 'TOTP Authenticator', NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO totp_factors (factor_id, secret, algorithm, digits, period)
VALUES (1, '\x00014f9080a21d4a82aaf4da48dcfdc47aee0d063ba0ceca732481051983bfcc4a8c6c888953c9f0fe670e7d887d', 1, 6, 30)
ON CONFLICT (factor_id) DO NOTHING;

-- inactive user

INSERT INTO users (id, status, name, username)
VALUES (2, 2, 'Inactive User', 'inactive-user')
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_emails (id, user_id, email, is_primary)
VALUES (2, 2, 'inactive-user@oryon.com', TRUE)
ON CONFLICT (id) DO NOTHING;

INSERT INTO password_credentials (user_id, password)
VALUES (2, '$argon2id$v=19$m=32768,t=3,p=2$LjGWAFbpnzvaFWj/8lGmNA$irLWOT5g2ftYajO2pMmbkJzTzAL9N510N/LXWqRnBrw')
ON CONFLICT (user_id) DO NOTHING;

-- deleted user

INSERT INTO users (id, status, name, username, deleted_at)
VALUES (3, 5, 'Deleted User', 'deleted-user', NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_emails (id, user_id, email, is_primary, verified_at)
VALUES (3, 3, 'deleted-user@oryon.com', TRUE, NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO password_credentials (user_id, password)
VALUES (3, '$argon2id$v=19$m=32768,t=3,p=2$LjGWAFbpnzvaFWj/8lGmNA$irLWOT5g2ftYajO2pMmbkJzTzAL9N510N/LXWqRnBrw')
ON CONFLICT (user_id) DO NOTHING;

-- +goose Down
DELETE FROM totp_factors WHERE factor_id IN (1);
DELETE FROM mfa_factors WHERE id IN (1);
DELETE FROM password_credentials WHERE user_id IN (1, 2, 3);
DELETE FROM user_phone_numbers WHERE id IN (1, 2, 3);
DELETE FROM user_emails WHERE id IN (1, 2, 3);
DELETE FROM users WHERE id IN (1, 2, 3);
