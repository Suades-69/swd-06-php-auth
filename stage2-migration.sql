USE swd_auth;

ALTER TABLE users
    MODIFY email VARCHAR(254) NOT NULL,
    ADD COLUMN role ENUM('user', 'admin') NOT NULL DEFAULT 'user' AFTER password_hash,
    ADD COLUMN last_login_at DATETIME NULL AFTER created_at;

ALTER TABLE login_attempts
    MODIFY email VARCHAR(254) NOT NULL;
