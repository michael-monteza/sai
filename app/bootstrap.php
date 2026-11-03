<?php
declare(strict_types=1);

// Shared by the web front controller and the CLI tools (tools/*.php).
define('SAIP_ROOT', dirname(__DIR__));
require SAIP_ROOT . '/vendor/autoload.php';
date_default_timezone_set('UTC');
