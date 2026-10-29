<?php
declare(strict_types=1);

function current_user(): ?array
{
    if (!isset($_SESSION['user_id']) || !is_numeric($_SESSION['user_id'])) {
        return null;
    }

    $statement = db()->prepare(
        'SELECT id, name, email, role, created_at, last_login_at
         FROM users
         WHERE id = :id
         LIMIT 1'
    );
    $statement->execute(['id' => $_SESSION['user_id']]);
    $user = $statement->fetch();

    if ($user === false) {
        unset($_SESSION['user_id'], $_SESSION['role'], $_SESSION['user_name']);
        return null;
    }

    $_SESSION['role'] = $user['role'];
    $_SESSION['user_name'] = $user['name'];

    return $user;
}

function require_login(): void
{
    if (current_user() !== null) {
        return;
    }

    $requestedUrl = $_SERVER['REQUEST_URI'] ?? '';
    if (is_valid_intended_url($requestedUrl)) {
        $_SESSION['intended_url'] = $requestedUrl;
    }

    redirect('login.php');
}

function require_guest(): void
{
    if (current_user() !== null) {
        redirect('dashboard.php');
    }
}

function require_role(string $role): void
{
    require_login();

    $user = current_user();
    if ($user === null) {
        redirect('login.php');
    }

    if ($user['role'] !== $role) {
        http_response_code(403);
        ?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Forbidden</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-shell">
    <section class="auth-card" aria-labelledby="page-title">
        <p class="eyebrow">SWD AUTH</p>
        <h1 id="page-title">403 — Forbidden</h1>
        <p class="intro">You don't have permission to view this page. If you think you should have access, contact an administrator.</p>
        <a href="dashboard.php">← Back to dashboard</a>
    </section>
</main>
</body>
</html>
        <?php
        exit;
    }
}

function is_valid_intended_url(mixed $url): bool
{
    if (!is_string($url) || $url === '' || preg_match('/[\x00-\x20\x7f\\\\]/', $url) === 1) {
        return false;
    }

    $parts = parse_url($url);
    if (
        $parts === false
        || isset($parts['scheme'])
        || isset($parts['host'])
        || isset($parts['user'])
        || isset($parts['pass'])
    ) {
        return false;
    }

    $path = $parts['path'] ?? '';

    return str_starts_with($path, '/')
        && !str_starts_with($path, '//')
        && !str_contains($path, '\\');
}

function navbar_html(array $user): void
{
    $isAdmin = $user['role'] === 'admin';
    ?>
<nav class="navbar">
    <span class="navbar-brand">SWD AUTH</span>
    <div class="navbar-links">
        <a href="dashboard.php">Dashboard</a>
        <?php if ($isAdmin): ?>
            <a href="admin/users.php">Admin</a>
        <?php endif; ?>
    </div>
</nav>
    <?php
}

function enforce_idle_timeout(): void
{
    if (!isset($_SESSION['user_id'])) {
        return;
    }

    $now = time();
    $lastActivity = $_SESSION['last_activity'] ?? null;

    if (is_int($lastActivity) && $now - $lastActivity >= 1800) {
        end_session();
        session_start();
        flash('notice', 'You were signed out after 30 minutes of inactivity.');
        return;
    }

    $_SESSION['last_activity'] = $now;
}

function end_session(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies') === '1') {
        $cookie = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $cookie['path'],
            'domain' => $cookie['domain'],
            'secure' => $cookie['secure'],
            'httponly' => $cookie['httponly'],
            'samesite' => $cookie['samesite'],
        ]);
    }

    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
}
