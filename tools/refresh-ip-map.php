<?php
declare(strict_types=1);

/**
 * Re-resolves every company's registered FQDNs so network connections (Sysmon EID 3) can be matched by IP address. Schedule hourly:
 *   schtasks /Create /SC HOURLY /TN "SAIP ip map" /TR "php C:\xampp\htdocs\2026\saip\tools\refresh-ip-map.php"
 *   php tools/refresh-ip-map.php [company-slug]
 * Only dedicated addresses are used; CDN / shared addresses are recorded as shared and never counted as usage.
 */
require __DIR__ . '/../app/bootstrap.php';

use Saip\{Db, DomainRegistry, IpIntel};

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$slug = $argv[1] ?? null;
$tenants = $slug ? Db::all('SELECT id, slug FROM tenants WHERE slug = ?', [$slug]) : Db::all("SELECT id, slug FROM tenants WHERE status = 'active'");
foreach ($tenants as $t) {
    $before = IpIntel::status((int)$t['id']);
    $r = IpIntel::refresh((int)$t['id']);
    if ($r['usable'] !== $before['usable']) DomainRegistry::bump((int)$t['id']);   // collectors resync the changed address list
    echo "{$t['slug']}: {$r['domains']} domains -> {$r['ips']} addresses ({$r['usable']} dedicated, {$r['shared']} shared/ignored)\n";
}
