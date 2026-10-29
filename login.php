<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_guest();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? null;
    if (!csrf_verify(is_string($submittedToken) ? $submittedToken : null)) {
        flash('errors', ['Your session expired. Please submit the form again.']);
        redirect('login.php');
    }

    $email = is_string($_POST['email'] ?? null)
        ? strtolower(trim($_POST['email']))
        : '';
    $password = is_string($_POST['password'] ?? null)
        ? $_POST['password']
        : '';

    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '';

    // Throttle: block if >= 5 failures for this email/IP in the last 15 minutes.
    if (strlen($email) <= 254 && filter_var($email, FILTER_VALIDATE_EMAIL) !== false) {
        $attemptCount = db()->prepare(
            'SELECT COUNT(*)
             FROM login_attempts
             WHERE attempted_at >= (NOW() - INTERVAL 15 MINUTE)
               AND (email = :email OR ip = :ip)'
        );
        $attemptCount->execute(['email' => $email, 'ip' => $ipAddress]);
        $failures = (int) $attemptCount->fetchColumn();

        if ($failures >= 5) {
            $oldestAttempt = db()->prepare(
                'SELECT MIN(attempted_at) FROM login_attempts
                 WHERE attempted_at >= (NOW() - INTERVAL 15 MINUTE)
                   AND (email = :email OR ip = :ip)'
            );
            $oldestAttempt->execute(['email' => $email, 'ip' => $ipAddress]);
            $oldest = $oldestAttempt->fetchColumn();
            $minutesLeft = 15 - (int) floor((time() - strtotime((string) $oldest)) / 60);
            $minutesLeft = max(1, min(15, $minutesLeft));
            flash('errors', ["Too many attempts, try again in {$minutesLeft} minutes."]);
            redirect('login.php');
        }
    }

    $user = null;
    if (strlen($email) <= 254 && filter_var($email, FILTER_VALIDATE_EMAIL) !== false) {
        $statement = db()->prepare(
            'SELECT id, name, email, password_hash, role
             FROM users
             WHERE email = :email
             LIMIT 1'
        );
        $statement->execute(['email' => $email]);
        $user = $statement->fetch();
    }

    $passwordHash = is_array($user)
        ? $user['password_hash']
        : '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2uheWG/igi.';
    $passwordIsValid = is_string($password)
        && strlen($password) <= 4096
        && password_verify($password, $passwordHash);

    if (!is_array($user) || !$passwordIsValid) {
        $recordAttempt = db()->prepare('INSERT INTO login_attempts (email, ip) VALUES (:email, :ip)');
        $recordAttempt->execute(['email' => $email, 'ip' => $ipAddress]);
        flash('errors', ['Invalid email or password.']);
        redirect('login.php');
    }

    // Success — clear failed attempts for this email and IP.
    $clearAttempts = db()->prepare('DELETE FROM login_attempts WHERE email = :email OR ip = :ip');
    $clearAttempts->execute(['email' => $email, 'ip' => $ipAddress]);

    if (password_needs_rehash($user['password_hash'], PASSWORD_DEFAULT)) {
        $newPasswordHash = password_hash($password, PASSWORD_DEFAULT);
        $rehash = db()->prepare('UPDATE users SET password_hash = :password_hash WHERE id = :id');
        $rehash->execute([
            'password_hash' => $newPasswordHash,
            'id' => $user['id'],
        ]);
    }

    $lastLogin = db()->prepare('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = :id');
    $lastLogin->execute(['id' => $user['id']]);

    session_regenerate_id(true);
    unset($_SESSION['_csrf_token']);
    $_SESSION['user_id'] = (string) $user['id'];
    $_SESSION['role'] = $user['role'];
    $_SESSION['user_name'] = $user['name'];
    $_SESSION['last_activity'] = time();

    $intendedUrl = $_SESSION['intended_url'] ?? null;
    unset($_SESSION['intended_url']);
    redirect(is_valid_intended_url($intendedUrl) ? $intendedUrl : 'dashboard.php');
}

$errors = flash('errors');
if (!is_array($errors)) {
    $errors = [];
}
$notice = flash('notice');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-shell">
    <section class="auth-card" aria-labelledby="page-title">
        <p class="eyebrow">SWD AUTH</p>
        <h1 id="page-title">Welcome back</h1>
        <p class="intro">Sign in to continue to your account.</p>

        <?php if (is_string($notice)): ?>
            <p class="success" role="status"><?= e($notice) ?></p>
        <?php endif; ?>

        <?php if ($errors !== []): ?>
            <div class="alert" role="alert">
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?= e($error) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <form action="login.php" method="post">
            <?= csrf_field() ?>
            <label for="email">Email</label>
            <input
                id="email"
                name="email"
                type="email"
                maxlength="254"
                autocomplete="username"
                value="<?= e(old('email')) ?>"
                required
            >

            <label for="password">Password</label>
            <input
                id="password"
                name="password"
                type="password"
                autocomplete="current-password"
                required
            >

            <button type="submit">Sign in</button>
        </form>
    </section>
</main>
</body>
</html>
