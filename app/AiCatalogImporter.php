<?php
declare(strict_types=1);

namespace Saip;

/**
 * Bulk-loads AI services and their FQDNs into one company's inventory and DNS registry.
 * Used by the console import (CSV) and by tools/load-top100.php. Idempotent: existing services are matched by name,
 * existing domains are only enriched (registrar, purpose, category) and never moved between services.
 *
 * Row keys: service, fqdn (required) + endpoint, root, registrar, purpose, category (optional).
 */
final class AiCatalogImporter
{
    /** @param list<array<string,mixed>> $rows @param list<string> $shared domains that also carry non-AI traffic
     *  @return array{services_created:int,services_matched:int,domains_added:int,domains_updated:int,skipped:list<array>,errors:list<array>} */
    public static function import(int $t, array $rows, string $actor, array $shared = [], bool $dry = false): array
    {
        $res = ['services_created' => 0, 'services_matched' => 0, 'domains_added' => 0, 'domains_updated' => 0, 'skipped' => [], 'errors' => []];
        $bySvc = [];
        foreach ($rows as $i => $r) {
            $svc = trim((string)($r['service'] ?? ''));
            if ($svc === '' || mb_strlen($svc) > 100) { $res['errors'][] = ['row' => $i + 1, 'reason' => 'service name is required (max 100)']; continue; }
            $bySvc[$svc][] = [$i + 1, $r];
        }
        $pdo = Db::pdo();
        $pdo->beginTransaction();
        try {
            foreach ($bySvc as $name => $list) {
                $first = $list[0][1];
                $sid = Db::val('SELECT id FROM ai_services WHERE tenant_id = ? AND LOWER(service_name) = LOWER(?)', [$t, $name]);
                $created = false;
                $prepared = [];
                foreach ($list as [$line, $r]) {
                    $fqdn = strtolower(trim((string)($r['fqdn'] ?? '')));
                    $root = strtolower(trim((string)($r['root'] ?? '')));
                    $note = null;
                    if (str_contains(ltrim($fqdn, '*.'), '*')) { $note = 'Pattern: ' . $fqdn; $fqdn = '*.' . ($root !== '' ? $root : preg_replace('/^.*\*\./', '', $fqdn)); }
                    $n = DomainRegistry::normalize($fqdn);
                    if (!$n) { $res['errors'][] = ['row' => $line, 'reason' => 'invalid FQDN: ' . mb_substr($fqdn, 0, 80)]; continue; }
                    $prepared[] = [$line, $r, $n[0], $n[1], $root !== '' ? (Validator::hostname($root) ?? null) : null, $note];
                }
                if (!$prepared) continue;
                if (!$sid) {
                    $res['services_created']++;
                    $created = true;
                    if (!$dry) {
                        $cat = mb_substr(trim((string)($first['category'] ?? '')) ?: 'Generative AI', 0, 60);
                        [$dc, $tr, $vr, $ir] = self::profile($cat, (string)($first['registrar'] ?? ''));
                        $allShared = $shared && count(array_filter($prepared, static fn ($p) => !in_array($p[2], $shared, true))) === 0;
                        $status = $allShared ? 'under_review' : 'unsanctioned';
                        $life = $allShared ? 'Under Security Evaluation' : 'Shadow Usage Detected';
                        $prov = mb_substr(ucfirst(explode('.', $prepared[0][4] ?? $prepared[0][2])[count(explode('.', $prepared[0][4] ?? $prepared[0][2])) - 2] ?? 'Unknown'), 0, 100);
                        Db::run('INSERT INTO ai_services (tenant_id, service_name, provider, primary_domain, category, sanction_status, description, data_class, training_exposure, vendor_risk, identity_risk, risk_score, owner, lifecycle, source, created_by, updated_by)
                                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?, "Unassigned", ?, "import", ?, ?)',
                            [$t, $name, $prov, $prepared[0][2], $cat, $status, mb_substr(trim((string)($first['purpose'] ?? '')), 0, 500) ?: null, $dc, $tr, $vr, $ir, Risk::score($dc, $tr, $vr, $ir, 0), $life, $actor, $actor]);
                        $sid = Db::insertId();
                    }
                } else {
                    $res['services_matched']++;
                }
                $hasDomains = $sid && !$created ? (int)Db::val('SELECT COUNT(*) FROM ai_domains WHERE ai_service_id = ?', [$sid]) : 0;
                foreach ($prepared as $k => [$line, $r, $host, $implied, $root, $note]) {
                    $existing = Db::one('SELECT id, ai_service_id, registrar, purpose, category, root_domain FROM ai_domains WHERE tenant_id = ? AND domain = ?', [$t, $host]);
                    $registrar = self::cut($r['registrar'] ?? null, 150); $purpose = self::cut($r['purpose'] ?? null, 400); $category = self::cut($r['category'] ?? null, 100);
                    if ($existing) {
                        if ($sid && (int)$existing['ai_service_id'] !== (int)$sid) { $res['skipped'][] = ['row' => $line, 'domain' => $host, 'reason' => 'already registered under another service']; continue; }
                        $fill = array_filter(['registrar' => $existing['registrar'] === null ? $registrar : null, 'purpose' => $existing['purpose'] === null ? $purpose : null,
                                              'category' => $existing['category'] === null ? $category : null, 'root_domain' => $existing['root_domain'] === null ? $root : null], static fn ($v) => $v !== null);
                        if ($fill) { $res['domains_updated']++; if (!$dry) Db::run('UPDATE ai_domains SET ' . implode(', ', array_map(static fn ($c) => "`$c` = ?", array_keys($fill))) . ' WHERE id = ?', array_merge(array_values($fill), [$existing['id']])); }
                        else $res['skipped'][] = ['row' => $line, 'domain' => $host, 'reason' => 'already present'];
                        continue;
                    }
                    $isShared = in_array($host, $shared, true) || ($root !== null && in_array($root, $shared, true) && $host === $root);
                    $rule = $implied ?? (($root !== null && $host === $root) || $isShared ? 'subdomain' : 'exact');
                    $type = self::type((string)($r['endpoint'] ?? $r['service'] ?? ''), $k === 0 && $hasDomains === 0 && $created);
                    $res['domains_added']++;
                    if ($dry) continue;
                    Db::run('INSERT INTO ai_domains (tenant_id, ai_service_id, domain, root_domain, registrar, purpose, category, domain_type, matching_rule, shared, notes, created_by, updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                        [$t, $sid, $host, $root, $registrar, $purpose, $category, $type, $rule, $isShared ? 1 : 0, $note ?? ($isShared ? 'Shared domain: also carries non-AI traffic' : null), $actor, $actor]);
                }
            }
            if (!$dry) {
                $pdo->commit();
                if ($res['services_created'] || $res['domains_added'] || $res['domains_updated']) {
                    $v = DomainRegistry::bump($t);
                    Audit::log($actor, 'registry_import', 'FQDN import', ['config_version' => $v] + array_diff_key($res, ['skipped' => 1, 'errors' => 1]) + ['skipped' => count($res['skipped']), 'errors' => count($res['errors'])], $t);
                }
            } else {
                $pdo->rollBack();
            }
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            throw $e;
        }
        return $res;
    }

    private static function cut(mixed $v, int $max): ?string
    {
        $s = is_string($v) ? trim($v) : '';
        return $s === '' ? null : mb_substr($s, 0, $max);
    }

    private static function type(string $label, bool $primary): string
    {
        $l = strtolower($label);
        return match (true) {
            $primary => 'primary',
            (bool)preg_match('/auth|identity|login|oauth/', $l) => 'authentication',
            (bool)preg_match('/cdn|static|asset|storage|lfs|delivery|sandbox/', $l) => 'cdn',
            (bool)preg_match('/api|gateway|endpoint|data plane|inference|backend|engine|queue/', $l) => 'api',
            default => 'secondary',
        };
    }

    /** Starting data class and risk inputs from the functional category and registrar (an administrator can change them). @return array{0:string,1:int,2:int,3:int} */
    public static function profile(string $category, string $registrar): array
    {
        $c = strtolower($category);
        [$dc, $tr, $vr, $ir] = match (true) {
            (bool)preg_match('/meeting|transcri/', $c) => ['Restricted / PII', 65, 55, 60],
            (bool)preg_match('/knowledge|productiv|enterprise (knowledge|search)|workflow/', $c) => ['Confidential', 50, 45, 50],
            (bool)preg_match('/conversational|chat|persona|search engine|hub/', $c) => ['Confidential', 60, 55, 60],
            (bool)preg_match('/code|coding|app builder|generator|ide|editor/', $c) => ['Confidential', 50, 45, 50],
            (bool)preg_match('/vector|mlops|data annotation|rlhf|deployment|distributed/', $c) => ['Confidential', 30, 35, 40],
            (bool)preg_match('/image|video|audio|voice|music|design|avatar|speech|presentation|translation|writing|content|marketing/', $c) => ['Internal', 50, 45, 45],
            default => ['Internal', 40, 40, 45],
        };
        if (preg_match('/alibaba|baidu|tencent|bytedance/i', $registrar)) { $vr = max($vr, 85); $tr = max($tr, 80); }
        return [$dc, $tr, $vr, $ir];
    }
}
