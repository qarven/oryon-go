-- +goose Up

INSERT INTO users (id, status, name, username)
VALUES ('0199f3a1-1b00-7a01-8001-000000000001', 1, 'Administrator', 'admin')
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_emails (id, user_id, email, is_primary, verified_at)
VALUES ('0199f3a1-1b00-7a02-8002-000000000002', '0199f3a1-1b00-7a01-8001-000000000001', 'admin@oryon.com', TRUE, NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_phone_numbers (id, user_id, phone, verified_at)
VALUES ('0199f3a1-1b00-7a03-8003-000000000003', '0199f3a1-1b00-7a01-8001-000000000001', '+6287777777777', NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO password_credentials (user_id, password)
VALUES ('0199f3a1-1b00-7a01-8001-000000000001', '$argon2id$v=19$m=32768,t=3,p=2$LjGWAFbpnzvaFWj/8lGmNA$irLWOT5g2ftYajO2pMmbkJzTzAL9N510N/LXWqRnBrw')
ON CONFLICT (user_id) DO NOTHING;

INSERT INTO mfa_factors (id, user_id, type, name, verified_at)
VALUES ('0199f3a1-1b00-7a04-8004-000000000004', '0199f3a1-1b00-7a01-8001-000000000001', 1, 'TOTP Authenticator', NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO totp_factors (factor_id, secret, algorithm, digits, period)
VALUES ('0199f3a1-1b00-7a04-8004-000000000004', '\x00014f9080a21d4a82aaf4da48dcfdc47aee0d063ba0ceca732481051983bfcc4a8c6c888953c9f0fe670e7d887d', 1, 6, 30)
ON CONFLICT (factor_id) DO NOTHING;

INSERT INTO mfa_factors (id, user_id, type, name, verified_at)
VALUES ('0199f3a1-1b00-7a05-8005-000000000005', '0199f3a1-1b00-7a01-8001-000000000001', 5, 'Recovery Codes', NOW())
ON CONFLICT (id) DO NOTHING;

-- recovery codes for user 0199f3a1-1b00-7a01-8001-000000000001 (argon2id, pepper "secret" from modules.identity.hash.argon2id).
-- format: 16 alphanumeric chars in two groups of 8 separated by hyphen (XXXXXXXX-XXXXXXXX), single-use.
-- plaintexts: A1B2C3D4-E5F6G7H8, K9L8M7N6-P5Q4R3S2, T1U2V3W4-X5Y6Z7A8, B9C8D7E6-F5G4H3J2, K1L2M3N4-P5Q6R7S8
-- verify with CompleteLoginMfa using factor_type=5.
INSERT INTO backup_codes (id, user_id, code) VALUES
('0199f3a1-1b00-7a06-8006-000000000006', '0199f3a1-1b00-7a01-8001-000000000001', '$argon2id$v=19$m=32768,t=3,p=2$6XsqekoqTFlD5zyD5bGgpA$mz6MQvKqWjjZ5JNaENqiNVgQk3ENVpBdve/7Kbo4XDs'::bytea),
('0199f3a1-1b00-7a07-8007-000000000007', '0199f3a1-1b00-7a01-8001-000000000001', '$argon2id$v=19$m=32768,t=3,p=2$NOJBwW5rrdpIzkZKBDgshw$bQAY1Tp7pcF371wRA0QcTXRE4C28qh6aqjBldVOmJ9M'::bytea),
('0199f3a1-1b00-7a08-8008-000000000008', '0199f3a1-1b00-7a01-8001-000000000001', '$argon2id$v=19$m=32768,t=3,p=2$XSw0Y2d6Od2fNPALmD8zBw$cA8YElMDgL81SSXkxSWGFOQZVEsTzlEPwon7YRf+eNo'::bytea),
('0199f3a1-1b00-7a09-8009-000000000009', '0199f3a1-1b00-7a01-8001-000000000001', '$argon2id$v=19$m=32768,t=3,p=2$lmmRixRPxgKuWTnHf2yIyw$5npb+Ub1eDnxiifTwgKVibjIcQjQsVDfPWfkamyqSjE'::bytea),
('0199f3a1-1b00-7a0a-800a-00000000000a', '0199f3a1-1b00-7a01-8001-000000000001', '$argon2id$v=19$m=32768,t=3,p=2$zrWovbuoruCY8Nuw4rhPfQ$at1KaLwPAG/r5xaCfrwOirAtZYuiJgTVTrSNskd7xJY'::bytea)
ON CONFLICT (id) DO NOTHING;

-- inactive user

INSERT INTO users (id, status, name, username)
VALUES ('0199f3a1-1b00-7a0b-800b-00000000000b', 2, 'Inactive User', 'inactive-user')
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_emails (id, user_id, email, is_primary)
VALUES ('0199f3a1-1b00-7a0c-800c-00000000000c', '0199f3a1-1b00-7a0b-800b-00000000000b', 'inactive-user@oryon.com', TRUE)
ON CONFLICT (id) DO NOTHING;

INSERT INTO password_credentials (user_id, password)
VALUES ('0199f3a1-1b00-7a0b-800b-00000000000b', '$argon2id$v=19$m=32768,t=3,p=2$LjGWAFbpnzvaFWj/8lGmNA$irLWOT5g2ftYajO2pMmbkJzTzAL9N510N/LXWqRnBrw')
ON CONFLICT (user_id) DO NOTHING;

-- deleted user

INSERT INTO users (id, status, name, username, deleted_at)
VALUES ('0199f3a1-1b00-7a0d-800d-00000000000d', 5, 'Deleted User', 'deleted-user', NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_emails (id, user_id, email, is_primary, verified_at)
VALUES ('0199f3a1-1b00-7a0e-800e-00000000000e', '0199f3a1-1b00-7a0d-800d-00000000000d', 'deleted-user@oryon.com', TRUE, NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO password_credentials (user_id, password)
VALUES ('0199f3a1-1b00-7a0d-800d-00000000000d', '$argon2id$v=19$m=32768,t=3,p=2$LjGWAFbpnzvaFWj/8lGmNA$irLWOT5g2ftYajO2pMmbkJzTzAL9N510N/LXWqRnBrw')
ON CONFLICT (user_id) DO NOTHING;

-- +goose Down
DELETE FROM backup_codes WHERE id IN ('0199f3a1-1b00-7a06-8006-000000000006', '0199f3a1-1b00-7a07-8007-000000000007', '0199f3a1-1b00-7a08-8008-000000000008', '0199f3a1-1b00-7a09-8009-000000000009', '0199f3a1-1b00-7a0a-800a-00000000000a');
DELETE FROM totp_factors WHERE factor_id IN ('0199f3a1-1b00-7a04-8004-000000000004');
DELETE FROM mfa_factors WHERE id IN ('0199f3a1-1b00-7a04-8004-000000000004', '0199f3a1-1b00-7a05-8005-000000000005');
DELETE FROM password_credentials WHERE user_id IN ('0199f3a1-1b00-7a01-8001-000000000001', '0199f3a1-1b00-7a0b-800b-00000000000b', '0199f3a1-1b00-7a0d-800d-00000000000d');
DELETE FROM user_phone_numbers WHERE id IN ('0199f3a1-1b00-7a03-8003-000000000003');
DELETE FROM user_emails WHERE id IN ('0199f3a1-1b00-7a02-8002-000000000002', '0199f3a1-1b00-7a0c-800c-00000000000c', '0199f3a1-1b00-7a0e-800e-00000000000e');
DELETE FROM users WHERE id IN ('0199f3a1-1b00-7a01-8001-000000000001', '0199f3a1-1b00-7a0b-800b-00000000000b', '0199f3a1-1b00-7a0d-800d-00000000000d');
