<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';

require_role('admin');
$currentUser = current_user();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? null;
    if (!csrf_verify(is_string($submittedToken) ? $submittedToken : null)) {
        flash('errors', ['Your session expired. Please submit the form again.']);
        redirect('admin/users.php');
    }

    $targetId = $_POST['user_id'] ?? null;
    $newRole = $_POST['new_role'] ?? null;

    if (!is_numeric($targetId) || !in_array($newRole, ['user', 'admin'], true)) {
        flash('errors', ['Invalid request.']);
        redirect('admin/users.php');
    }

    if ((int) $targetId === (int) $currentUser['id']) {
        flash('errors', ['You cannot change your own role.']);
        redirect('admin/users.php');
    }

    $update = db()->prepare('UPDATE users SET role = :role WHERE id = :id');
    $update->execute([
        'role' => $newRole,
        'id' => (int) $targetId,
    ]);

    flash('success', 'Role updated.');
    redirect('admin/users.php');
}

$statement = db()->query(
    'SELECT id, name, email, role, created_at, last_login_at
     FROM users
     ORDER BY id ASC'
);
$users = $statement->fetchAll();

$successMessage = flash('success');
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
    <title>User management</title>
    <link rel="stylesheet" href="../assets/auth.css">
</head>

<body>
<nav class="navbar">
    <span class="navbar-brand">SWD AUTH</span>
    <div class="navbar-links">
        <a href="../dashboard.php">Dashboard</a>
    </div>
</nav>
    <main class="auth-shell">
        <section class="auth-card" aria-labelledby="page-title">
            <p class="eyebrow">SWD AUTH</p>
            <h1 id="page-title">Users</h1>
            <p class="intro">Manage user roles. You cannot change your own role.</p>

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

            <table class="user-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Created</th>
                        <th>Last login</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $user): ?>
                        <tr>
                            <td><?= e($user['name']) ?></td>
                            <td><?= e($user['email']) ?></td>
                            <td><?= e($user['role']) ?></td>
                            <td><?= e($user['created_at']) ?></td>
                            <td><?= e($user['last_login_at'] ?? '—') ?></td>
                            <td>
                                <?php if ((int) $user['id'] === (int) $currentUser['id']): ?>
                                    <span class="muted">(you)</span>
                                <?php else: ?>
                                    <form method="post" action="users.php">
                                        <?= csrf_field() ?>
                                        <input type="hidden" name="user_id" value="<?= e($user['id']) ?>">
                                        <input type="hidden" name="new_role" value="<?= e($user['role'] === 'admin' ? 'user' : 'admin') ?>">
                                        <button type="submit"><?= e($user['role'] === 'admin' ? 'Demote' : 'Promote') ?></button>
                                    </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

            <a href="../dashboard.php">← Back to dashboard</a>
        </section>
    </main>
</body>

</html>