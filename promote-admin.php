<?php
declare(strict_types=1);

// CLI ONLY — refuse to run if invoked via a web request.
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script may only be run from the command line.' . PHP_EOL);
}

require_once __DIR__ . '/bootstrap.php';

if ($argc < 2) {
    fwrite(STDERR, "Usage: php promote-admin.php <email>\n");
    fwrite(STDERR, "Example: php promote-admin.php me@example.com\n");
    exit(1);
}

$email = strtolower(trim($argv[1]));
if ($email === '' || strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
    fwrite(STDERR, "Error: '{$email}' is not a valid email address.\n");
    exit(1);
}

$statement = db()->prepare('SELECT id, name, email, role FROM users WHERE email = :email LIMIT 1');
$statement->execute(['email' => $email]);
$user = $statement->fetch();

if ($user === false) {
    fwrite(STDERR, "Error: no user found with email '{$email}'.\n");
    exit(1);
}

if ($user['role'] === 'admin') {
    echo "User '{$user['name']}' <{$user['email']}> is already an admin. Nothing to do.\n";
    exit(0);
}

$update = db()->prepare("UPDATE users SET role = 'admin' WHERE id = :id");
$update->execute(['id' => $user['id']]);

echo "Promoted '{$user['name']}' <{$user['email']}> to admin.\n";
exit(0);
