<?php
declare(strict_types=1);

/**
 * Delivers pending events to SIEM / webhook integrations. Schedule every minute:
 *   schtasks /Create /SC MINUTE /MO 1 /TN "SAIP integrations" /TR "php C:\xampp\htdocs\2026\saip\tools\dispatch-integrations.php"
 *   php tools/dispatch-integrations.php [--force] [--id=N]
 */
require __DIR__ . '/../app/bootstrap.php';

use Saip\IntegrationDispatcher;

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$force = in_array('--force', $argv, true);
$id = null;
foreach ($argv as $a) if (preg_match('/^--id=(\d+)$/', $a, $m)) $id = (int)$m[1];
$results = IntegrationDispatcher::run($id, $force);
foreach ($results as $r) echo "#{$r['id']} {$r['name']}: {$r['status']}" . ($r['sent'] ? ", {$r['sent']} event(s) sent" : '') . (!empty($r['error']) ? " ({$r['error']})" : '') . "\n";
if (!$results) echo "Nothing due.\n";
