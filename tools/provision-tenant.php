<?php
// php tools\provision-tenant.php "Company Name" [slug]
// Creates a company, clones the AI catalogue / ISO 42001 controls / policies, prints the collector enrollment key (once).
declare(strict_types=1);
if (PHP_SAPI !== 'cli') exit(1);
require __DIR__ . '/../app/bootstrap.php';

use Saip\{Audit, Tenants};

[, $name, $slug] = $argv + [null, null, null];
if (!$name) { fwrite(STDERR, "Usage: provision-tenant.php \"Company Name\" [slug]\n"); exit(2); }
$r = Tenants::create($name, $slug);
Audit::log('cli:' . (getenv('USERNAME') ?: 'admin'), 'tenant_created', $name, ['id' => $r['id']], $r['id']);
echo "Tenant '{$name}' created (id {$r['id']}, slug {$r['slug']}).\nCollector enrollment key (shown once):\n{$r['enrollment_key']}\n";
