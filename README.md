# PHP authentication starter

## Setup

1. Import `schema.sql` in phpMyAdmin or with the MySQL command-line client. It creates the `swd_auth` database, `users`, and `login_attempts`.
2. The defaults target a local XAMPP MySQL server (`127.0.0.1:3306`, database `swd_auth`, user `root`, empty password). Set `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, and `DB_PASS` in the PHP process environment to override them.
3. Open `http://localhost/swd/06-php-auth/register.php`.

Set `APP_ENV=production` in production so PHP errors are not displayed to visitors. Use HTTPS in production; the session cookie is marked `Secure` automatically when PHP detects HTTPS.

## Password storage

The application stores only the one-way hash returned by `password_hash()` with `PASSWORD_DEFAULT`, never the submitted password. `password_verify()` can later validate a login attempt against that hash. Modern password-hashing algorithms use salts and are deliberately expensive to compute, which makes large-scale guessing more difficult if the database is exposed.

Do not use plain-text passwords, MD5, or SHA-1 for password storage. Plain text directly exposes every password after a database leak. MD5 and SHA-1 are fast general-purpose hashes and are vulnerable to rapid offline guessing; they also do not provide the password-specific protections of PHP's password hashing API.
