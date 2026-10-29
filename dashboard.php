<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_login();
$user = current_user();

$successMessage = flash('success');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dashboard</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<?= navbar_html($user) ?>
<main class="auth-shell">
    <section class="auth-card" aria-labelledby="page-title">
        <?php if (is_string($successMessage)): ?>
            <p class="success" role="status"><?= e($successMessage) ?></p>
        <?php endif; ?>
        <p class="eyebrow">SWD AUTH</p>
        <h1 id="page-title">Welcome, <?= e($user['name']) ?></h1>
        <p class="intro">You are signed in. Your account details are below.</p>

        <dl class="account-details">
            <div>
                <dt>Name</dt>
                <dd><?= e($user['name']) ?></dd>
            </div>
            <div>
                <dt>Email</dt>
                <dd><?= e($user['email']) ?></dd>
            </div>
            <div>
                <dt>Role</dt>
                <dd><?= e($user['role']) ?></dd>
            </div>
            <div>
                <dt>Member since</dt>
                <dd><?= e($user['created_at']) ?></dd>
            </div>
            <div>
                <dt>Last login</dt>
                <dd><?= e($user['last_login_at'] ?? 'Not recorded') ?></dd>
            </div>
        </dl>

        <form action="logout.php" method="post">
            <?= csrf_field() ?>
            <button type="submit">Log out</button>
        </form>
    </section>
</main>
</body>
</html>
