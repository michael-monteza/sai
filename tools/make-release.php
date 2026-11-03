<?php
declare(strict_types=1);

/**
 * Builds the distributable package: dist/saip-<version>.zip. Extract it on the server, browse to /install.php, done.
 * Contains the application and vendor/; excludes anything instance-specific (config.php, app.key, installed.lock, initial-admin.txt),
 * tests, legacy code and previous packages.   php tools\make-release.php
 */
if (PHP_SAPI !== 'cli') exit(1);
require __DIR__ . '/../app/Xlsx.php';

$root = dirname(__DIR__);
$version = trim((string)@file_get_contents($root . '/VERSION')) ?: '0.0.0';
$skipDirs = ['dist', 'legacy', 'legacy-v1', 'tests', '.git', '.claude'];
$skipFiles = ['config/config.php', 'config/app.key', 'config/installed.lock', 'config/initial-admin.txt', 'sidebar-component.html'];
$files = [];
$it = new RecursiveIteratorIterator(new RecursiveCallbackFilterIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), static function (SplFileInfo $f) use ($root, $skipDirs): bool {
    $rel = str_replace('\\', '/', substr($f->getPathname(), strlen($root) + 1));
    return !($f->isDir() && in_array($rel, $skipDirs, true));
}));
foreach ($it as $f) {
    $rel = str_replace('\\', '/', substr($f->getPathname(), strlen($root) + 1));
    if (in_array($rel, $skipFiles, true) || str_contains($rel, '.tmp') || preg_match('#^tools/_#', $rel) || preg_match('#\.(log|bak)$#', $rel)) continue;
    $files["saip/$rel"] = (string)file_get_contents($f->getPathname());
}
$files['saip/config/.gitkeep'] = '';
@mkdir($root . '/dist');
$out = "$root/dist/saip-$version.zip";
file_put_contents($out, Saip\Xlsx::zip($files));
printf("Built %s (%d files, %.1f MB)\n", $out, count($files), filesize($out) / 1048576);
