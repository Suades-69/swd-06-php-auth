<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_login();
$user = current_user();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? null;
    $form = $_POST['form'] ?? '';

    if (!csrf_verify(is_string($submittedToken) ? $submittedToken : null)) {
        flash('errors', ['Your session expired. Please submit the form again.']);
        redirect('profile.php');
    }

    if ($form === 'details') {
        $name = is_string($_POST['name'] ?? null) ? trim($_POST['name']) : '';
        $email = is_string($_POST['email'] ?? null) ? strtolower(trim($_POST['email'])) : '';
        $errors = [];

        if (preg_match('/\A.{1,100}\z/us', $name) !== 1) {
            $errors[] = 'Enter a name no longer than 100 characters.';
        }

        if (strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $errors[] = 'Enter a valid email address.';
        }

        if ($errors === [] && strcasecmp($email, (string) $user['email']) !== 0) {
            $emailCheck = db()->prepare('SELECT id FROM users WHERE email = :email AND id != :id LIMIT 1');
            $emailCheck->execute(['email' => $email, 'id' => $user['id']]);
            if ($emailCheck->fetch() !== false) {
                $errors[] = 'An account with that email address already exists.';
            }
        }

        if ($errors !== []) {
            $_SESSION['_old'] = ['name' => $name, 'email' => $email];
            flash('errors', $errors);
            redirect('profile.php');
        }

        $update = db()->prepare('UPDATE users SET name = :name, email = :email WHERE id = :id');
        $update->execute([
            'name' => $name,
            'email' => $email,
            'id' => $user['id'],
        ]);

        $_SESSION['user_name'] = $name;
        flash('success', 'Profile updated.');
        redirect('profile.php');
    }

    if ($form === 'password') {
        $currentPassword = is_string($_POST['current_password'] ?? null) ? $_POST['current_password'] : '';
        $newPassword = is_string($_POST['new_password'] ?? null) ? $_POST['new_password'] : '';
        $confirmPassword = is_string($_POST['confirm_password'] ?? null) ? $_POST['confirm_password'] : '';
        $errors = [];

        $row = db()->prepare('SELECT password_hash FROM users WHERE id = :id LIMIT 1');
        $row->execute(['id' => $user['id']]);
        $stored = (string) ($row->fetchColumn() ?: '');

        if ($stored === '' || !password_verify($currentPassword, $stored)) {
            $errors[] = 'Your current password is incorrect.';
        }

        if (strlen($newPassword) > 4096
            || preg_match('/\A(?=.*\p{L})(?=.*\p{N})[\s\S]{10,}\z/u', $newPassword) !== 1) {
            $errors[] = 'Use a password of at least 10 characters with at least one letter and one number.';
        }

        if ($newPassword !== $confirmPassword) {
            $errors[] = 'The passwords do not match.';
        }

        if ($errors !== []) {
            flash('errors', $errors);
            redirect('profile.php');
        }

        $newHash = password_hash($newPassword, PASSWORD_DEFAULT);
        $update = db()->prepare('UPDATE users SET password_hash = :hash WHERE id = :id');
        $update->execute(['hash' => $newHash, 'id' => $user['id']]);

        session_regenerate_id(true);
        unset($_SESSION['_csrf_token']);

        flash('success', 'Password changed.');
        redirect('profile.php');
    }

    flash('errors', ['Unknown action.']);
    redirect('profile.php');
}

$errors = flash('errors');
if (!is_array($errors)) {
    $errors = [];
}
$successMessage = flash('success');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Profile</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<?= navbar_html($user) ?>
<main class="auth-shell">
    <section class="auth-card" aria-labelledby="page-title">
        <p class="eyebrow">SWD AUTH</p>
        <h1 id="page-title">Your profile</h1>
        <p class="intro">Update your account details or change your password.</p>

        <?php if (is_string($successMessage)): ?>
            <p class="success" role="status"><?= e($successMessage) ?></p>
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

        <form action="profile.php" method="post">
            <?= csrf_field() ?>
            <input type="hidden" name="form" value="details">
            <label for="name">Name</label>
            <input
                id="name"
                name="name"
                type="text"
                maxlength="100"
                autocomplete="name"
                value="<?= e(old('name', (string) $user['name'])) ?>"
                required
            >

            <label for="email">Email</label>
            <input
                id="email"
                name="email"
                type="email"
                maxlength="254"
                autocomplete="email"
                value="<?= e(old('email', (string) $user['email'])) ?>"
                required
            >

            <button type="submit">Save changes</button>
        </form>

        <hr class="form-divider">

        <h2 class="section-title">Change password</h2>
        <form action="profile.php" method="post">
            <?= csrf_field() ?>
            <input type="hidden" name="form" value="password">
            <label for="current-password">Current password</label>
            <input
                id="current-password"
                name="current_password"
                type="password"
                autocomplete="current-password"
                required
            >

            <label for="new-password">New password</label>
            <input
                id="new-password"
                name="new_password"
                type="password"
                autocomplete="new-password"
                minlength="10"
                required
            >
            <p class="hint">At least 10 characters, including a letter and a number.</p>

            <label for="confirm-password">Confirm new password</label>
            <input
                id="confirm-password"
                name="confirm_password"
                type="password"
                autocomplete="new-password"
                minlength="10"
                required
            >

            <button type="submit">Change password</button>
        </form>

        <a href="dashboard.php">← Back to dashboard</a>
    </section>
</main>
</body>
</html>
