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
        exit('Forbidden');
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
