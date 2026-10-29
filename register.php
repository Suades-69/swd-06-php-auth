<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? null;
    if (!csrf_verify(is_string($submittedToken) ? $submittedToken : null)) {
        $_SESSION['_old'] = [
            'name' => is_string($_POST['name'] ?? null) ? trim($_POST['name']) : '',
            'email' => is_string($_POST['email'] ?? null) ? trim($_POST['email']) : '',
        ];
        flash('errors', ['Your session expired. Please submit the form again.']);
        redirect('register.php');
    }

    $name = is_string($_POST['name'] ?? null) ? trim($_POST['name']) : '';
    $email = is_string($_POST['email'] ?? null) ? strtolower(trim($_POST['email'])) : '';
    $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
    $confirmPassword = is_string($_POST['confirm_password'] ?? null)
        ? $_POST['confirm_password']
        : '';
    $errors = [];

    if (preg_match('/\A.{1,100}\z/us', $name) !== 1) {
        $errors[] = 'Enter a name no longer than 100 characters.';
    }

    if (strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        $errors[] = 'Enter a valid email address.';
    }

    $passwordIsValid = strlen($password) <= 4096
        && preg_match('/\A(?=.*\p{L})(?=.*\p{N})[\s\S]{10,}\z/u', $password) === 1;
    if (!$passwordIsValid) {
        $errors[] = 'Use a password of at least 10 characters with at least one letter and one number.';
    }

    if ($password !== $confirmPassword) {
        $errors[] = 'The passwords do not match.';
    }

    if ($errors === []) {
        $emailCheck = db()->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
        $emailCheck->execute(['email' => $email]);

        if ($emailCheck->fetch() !== false) {
            $errors[] = 'An account with that email address already exists.';
        }
    }

    if ($errors !== []) {
        $_SESSION['_old'] = ['name' => $name, 'email' => $email];
        flash('errors', $errors);
        redirect('register.php');
    }

    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    $insert = db()->prepare(
        'INSERT INTO users (name, email, password_hash) VALUES (:name, :email, :password_hash)'
    );

    try {
        $insert->execute([
            'name' => $name,
            'email' => $email,
            'password_hash' => $passwordHash,
        ]);
    } catch (PDOException $exception) {
        $mysqlErrorCode = $exception->errorInfo[1] ?? null;
        if ($exception->getCode() !== '23000' || $mysqlErrorCode !== 1062) {
            throw $exception;
        }

        $_SESSION['_old'] = ['name' => $name, 'email' => $email];
        flash('errors', ['An account with that email address already exists.']);
        redirect('register.php');
    }

    session_regenerate_id(true);
    unset($_SESSION['_csrf_token'], $_SESSION['intended_url']);
    $_SESSION['user_id'] = db()->lastInsertId();
    $_SESSION['user_name'] = $name;
    $_SESSION['role'] = 'user';
    $_SESSION['last_activity'] = time();
    $lastLogin = db()->prepare('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = :id');
    $lastLogin->execute(['id' => $_SESSION['user_id']]);
    flash('success', 'Your account has been created.');
    redirect('dashboard.php');
}

$errors = flash('errors');
if (!is_array($errors)) {
    $errors = [];
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Create account</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-shell">
    <section class="auth-card" aria-labelledby="page-title">
        <p class="eyebrow">SWD AUTH</p>
        <h1 id="page-title">Create your account</h1>
        <p class="intro">Get started by entering your details below.</p>

        <?php if ($errors !== []): ?>
            <div class="alert" role="alert">
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?= e($error) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <form action="register.php" method="post">
            <?= csrf_field() ?>
            <label for="name">Name</label>
            <input
                id="name"
                name="name"
                type="text"
                maxlength="100"
                autocomplete="name"
                value="<?= e(old('name')) ?>"
                required
            >

            <label for="email">Email</label>
            <input
                id="email"
                name="email"
                type="email"
                maxlength="254"
                autocomplete="email"
                value="<?= e(old('email')) ?>"
                required
            >

            <label for="password">Password</label>
            <input
                id="password"
                name="password"
                type="password"
                autocomplete="new-password"
                minlength="10"
                required
            >
            <p class="hint">At least 10 characters, including a letter and a number.</p>

            <label for="confirm-password">Confirm password</label>
            <input
                id="confirm-password"
                name="confirm_password"
                type="password"
                autocomplete="new-password"
                minlength="10"
                required
            >

            <button type="submit">Create account</button>
        </form>
    </section>
</main>
</body>
</html>
