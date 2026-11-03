<?php
declare(strict_types=1);

// Front controller (Slim 4). Works from a sub-folder (XAMPP) or as the web root; point the web root at this folder
// or, better, copy only index.php + assets/ to a public/ directory and adjust the require paths.
if (PHP_SAPI === 'cli-server') {   // PHP built-in server: serve /assets/* directly, everything else through Slim
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
    if ((str_starts_with($path, '/assets/') && is_file(__DIR__ . $path)) || $path === '/install.php') return false;
}
// Not installed yet, or the files were upgraded but the database was not: send people to the installer/upgrader (collectors get 503 and retry).
if (PHP_SAPI !== 'cli') {
    $lockFile = __DIR__ . '/config/installed.lock';
    $lock = is_file($lockFile) ? json_decode((string)file_get_contents($lockFile), true) : null;
    $verFile = __DIR__ . '/VERSION';
    if (!is_array($lock) || (is_file($verFile) && trim((string)file_get_contents($verFile)) !== ($lock['version'] ?? ''))) {
        $dir = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
        if (str_contains($_SERVER['REQUEST_URI'] ?? '', '/api/')) {
            http_response_code(503); header('Retry-After: 300'); header('Content-Type: application/json');
            exit(json_encode(['error' => ['code' => 'maintenance', 'message' => is_array($lock) ? 'Upgrade in progress.' : 'Not installed yet.']]));
        }
        header('Location: ' . $dir . '/install.php');
        exit;
    }
}
require __DIR__ . '/app/bootstrap.php';
Saip\Kernel::create()->run();
