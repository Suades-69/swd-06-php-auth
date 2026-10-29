<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Method Not Allowed');
}

$submittedToken = $_POST['csrf_token'] ?? null;
if (!csrf_verify(is_string($submittedToken) ? $submittedToken : null)) {
    http_response_code(403);
    exit('Invalid CSRF token');
}

end_session();
session_start();
flash('notice', 'You have been logged out.');
redirect('login.php');
