<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if (!isset($_SESSION['user_id'], $_SESSION['user_name'])) {
    redirect('register.php');
}

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
<main class="auth-shell">
    <section class="auth-card" aria-labelledby="page-title">
        <?php if (is_string($successMessage)): ?>
            <p class="success" role="status"><?= e($successMessage) ?></p>
        <?php endif; ?>
        <p class="eyebrow">SWD AUTH</p>
        <h1 id="page-title">Welcome, <?= e($_SESSION['user_name']) ?></h1>
        <p class="intro">You are signed in.</p>
    </section>
</main>
</body>
</html>
