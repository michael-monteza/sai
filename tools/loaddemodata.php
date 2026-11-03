<?php
// php tools\loaddemodata.php <company-slug>
// DEMO DATA ONLY: sample governance states, requests, ISO sample, discovered domains and 30 days of synthetic telemetry from DEMO-* workstations
// (usage events, a few network connections, heartbeats). Safe to re-run (existing DEMO-* workstations are skipped). Remove again with: php tools\cleandemo.php <slug> --yes
// Never run against a production company.
declare(strict_types=1);
if (PHP_SAPI !== 'cli' && !defined('SAIP_INSTALLER')) exit(1);
require_once __DIR__ . '/../app/bootstrap.php';

use Saip\Middleware\CollectorAuth;
use Saip\{Db, Risk};

$args = array_slice($argv, 1);
$slug = array_values(array_filter($args, static fn ($a) => !str_starts_with($a, '--')))[0] ?? null;
$t = $slug ? (int)Db::val('SELECT id FROM tenants WHERE slug = ?', [$slug]) : 0;
if (!$t) { fwrite(STDERR, "Usage: php tools\loaddemodata.php <company-slug>
"); exit(2); }

// --- service states (as in the original mockup) ---
$states = [
    'ChatGPT'           => ['Shadow Usage Detected', 'Unassigned', 'Ad copy generation and draft product pitch reviews', 'Draft proposals, marketing copy'],
    'Microsoft Copilot' => ['Formally Sanctioned', 'IT Governance', 'Corporate productivity with enterprise tenant isolation', 'Corporate emails, internal presentations'],
    'Google Gemini'     => ['Formally Sanctioned', 'Product Operations', 'Competitor feature synthesis and public market research', 'Public web research, internal product specs'],
    'Claude'            => ['Under Security Evaluation', 'Data Science Lead', 'Python script evaluation and refactoring tests', 'Internal scripts'],
    'Perplexity'        => ['Shadow Usage Detected', 'Unassigned', 'Competitor dossier lookup and customer deal research', 'Prospect names, customer contract estimates'],
    'GitHub Copilot'    => ['Formally Sanctioned', 'Engineering', 'Code completion with enterprise licence', 'Internal source code'],
    'DeepSeek'          => ['Prohibited / Blocked', 'Unassigned', 'Unreviewed chat use', 'Unknown'],
    'Midjourney'        => ['Shadow Usage Detected', 'Creative Director', 'Social media concept illustration generation', 'Public graphics'],
    'Hugging Face Hub'  => ['Formally Sanctioned', 'ML Engineering Team', 'Pretrained tokenizer and open weights repository', 'Open source model weights'],
];
$map = ['Formally Sanctioned' => 'sanctioned', 'Under Security Evaluation' => 'under_review'];
foreach ($states as $name => [$life, $owner, $purpose, $cats]) {
    Db::run('UPDATE ai_services SET lifecycle=?, sanction_status=?, owner=?, purpose=?, data_categories=? WHERE tenant_id=? AND service_name=?',
        [$life, $map[$life] ?? 'unsanctioned', $owner, $purpose, $cats, $t, $name]);
    Db::run('UPDATE ai_domains d JOIN ai_services s ON s.id = d.ai_service_id SET d.blocked=? WHERE s.tenant_id=? AND s.service_name=?',
        [$life === 'Prohibited / Blocked' ? 1 : 0, $t, $name]);
}
foreach ([['Unknown AI API', 'Unverified Host', 'api.unapproved-ai.io', ['api.unapproved-ai.io']],
          ['Unverified AI Hosts', 'Various', 'rogue-model-hub.org', ['rogue-model-hub.org', 'shadow-translate-bot.cc', 'unverified-copilot-clone.xyz', 'prompt-leaker-api.net', 'fast-genai-bypass.biz', 'dev-shadow-llm.internal.run']]] as [$n, $prov, $pd, $doms]) {
    if (Db::val('SELECT 1 FROM ai_services WHERE tenant_id=? AND service_name=?', [$t, $n])) continue;
    Db::run('INSERT INTO ai_services (tenant_id, service_name, provider, primary_domain, category, sanction_status, data_class, training_exposure, vendor_risk, identity_risk, risk_score, owner, purpose, lifecycle, source)
             VALUES (?,?,?,?, "AI API", "unsanctioned", "Confidential", 90, 85, 75, ?, "Unassigned", "Suspected source code egress via direct API calls", "Prohibited / Blocked", "discovered")',
        [$t, $n, $prov, $pd, Risk::score('Confidential', 90, 85, 75, 0)]);
    $sid = Db::insertId();
    foreach ($doms as $d) Db::run('INSERT IGNORE INTO ai_domains (tenant_id, ai_service_id, domain, blocked) VALUES (?,?,?,1)', [$t, $sid, $d]);
}

// --- sample ISO control assessment (SAMPLE values from the mockup; replace with a real assessment) ---
$ok = ['A.2-1', 'A.3-1', 'A.4-1', 'A.5-1', 'A.5-2', 'A.6-1', 'A.7-1', 'A.8-1', 'A.9-1', 'A.10-1'];
Db::run("UPDATE iso_controls SET compliant = 0, evidence = NULL, notes = NULL, updated_at = NULL WHERE tenant_id = ?", [$t]);
$ph = implode(',', array_fill(0, count($ok), '?'));
Db::run("UPDATE iso_controls SET compliant = 1, evidence = 'DEMO sample evidence', notes = 'Demo data - not a real assessment', updated_at = UTC_TIMESTAMP(), updated_by = 'demo-seed' WHERE tenant_id = ? AND control_code IN ($ph)", array_merge([$t], $ok));

if (!Db::val("SELECT 1 FROM access_requests WHERE tenant_id = ?", [$t])) {
    foreach ([['Cursor AI IDE', 'cursor.com', 'Fullstack dev team', 'AI code assistant plugin to accelerate frontend refactor', 'Proprietary code'],
              ['GitHub Copilot Enterprise', null, 'Platform team', 'Code auto-completion with enterprise licence and IP indemnity', 'Internal code'],
              ['Otter.ai Meeting Assistant', 'otter.ai', 'Human Resources', 'Automated executive meeting minutes and transcription', 'Sensitive discussions']] as $r) {
        Db::run('INSERT INTO access_requests (tenant_id, tool_name, domain, requester, justification, data_class) VALUES (?,?,?,?,?,?)', [$t, $r[0], $r[1], $r[2], $r[3], $r[4]]);
    }
}
Db::run("UPDATE policies SET status='Enforced' WHERE tenant_id=? AND name IN ('Default Prohibit on Shadow AI','Sanctioned Enterprise Only with SSO')", [$t]);

// --- synthetic workstations and 30 days of telemetry ---
$depts = ['Marketing' => 'MKT', 'Finance' => 'FIN', 'Core Platform Engineering' => 'ENG', 'Data Science' => 'DS', 'Sales Ops' => 'SLS', 'Design' => 'DSG', 'Human Resources' => 'HR', 'Executive Office' => 'EXC'];
$svcRows = Db::all('SELECT s.id, s.service_name, (SELECT domain FROM ai_domains d WHERE d.ai_service_id = s.id ORDER BY d.id LIMIT 1) dom FROM ai_services s WHERE s.tenant_id = ?', [$t]);
$svc = array_column($svcRows, null, 'service_name');
$profile = ['MKT' => ['ChatGPT', 'Midjourney', 'Microsoft Copilot'], 'FIN' => ['Microsoft Copilot', 'ChatGPT'], 'ENG' => ['GitHub Copilot', 'Unknown AI API', 'ChatGPT', 'Claude'],
            'DS' => ['Claude', 'Hugging Face Hub', 'Google Gemini'], 'SLS' => ['Perplexity', 'ChatGPT'], 'DSG' => ['Midjourney', 'Google Gemini'], 'HR' => ['Microsoft Copilot', 'DeepSeek'], 'EXC' => ['Microsoft Copilot']];
$pdo = Db::pdo();
$pdo->beginTransaction();
$ins = $pdo->prepare('INSERT IGNORE INTO ai_usage_events (tenant_id, collector_id, computer_name, ai_service_id, query_domain, process_image, process_id, sysmon_record_id, event_timestamp, received_timestamp, event_type)
                      VALUES (?,?,?,?,?,?,?,?,?,UTC_TIMESTAMP(3),"dns_query")');
$n = 0; $i = 0;
foreach ($depts as $dept => $code) {
    foreach ([1, 2, 3] as $k) {
        if ($code === 'EXC' && $k === 2) continue;
        if ($k === 3 && !in_array($code, ['FIN', 'HR', 'SLS', 'DSG'], true)) continue;   // quiet workstations for the adoption demo
        $comp = sprintf('DEMO-%s-%02d', $code, $k);
        if (Db::val('SELECT 1 FROM collectors WHERE tenant_id=? AND computer_name=?', [$t, $comp])) continue;
        $mac = strtoupper(implode(':', str_split(bin2hex(random_bytes(6)), 2)));
        Db::run('INSERT INTO collectors (tenant_id, computer_name, mac_address, collector_uuid, api_key_hash, status, last_seen, collector_version) VALUES (?,?,?,?,?,"authorized",UTC_TIMESTAMP(),"1.0.0")',
            [$t, $comp, $mac, sprintf('%08x-%04x-4%03x-a%03x-%012x', random_int(0, 0xffffffff), random_int(0, 0xffff), random_int(0, 0xfff), random_int(0, 0xfff), random_int(0, 0xffffffffffff)), CollectorAuth::hashKey(bin2hex(random_bytes(8)))]);
        $cid = Db::insertId();
        Db::run('INSERT IGNORE INTO employee_inventory (tenant_id, computer_name, employee_reference, department, business_unit) VALUES (?,?,?,?,"Demo")', [$t, $comp, "EMP-D$i", $dept]);
        $i++; $rec = 1000;
        $mine = array_values(array_filter($profile[$code], static fn ($s) => isset($svc[$s])));
        $intensity = $k === 3 ? 1 : random_int(2, 14);
        for ($day = 29; $day >= 0; $day--) {
            $dow = (int)gmdate('N', time() - $day * 86400);
            if ($dow >= 6 || random_int(1, 10) <= 2) continue;                 // weekdays, some quiet days
            if ($k === 3 && ($code === 'HR' || random_int(1, 10) > 1)) continue;   // HR-03: no activity; others: a handful of days
            foreach ($mine as $sn) {
                if (random_int(1, 10) > 6) continue;
                for ($e = random_int(1, $intensity); $e > 0; $e--) {
                    $ts = gmdate('Y-m-d H:i:s', strtotime(gmdate('Y-m-d', time() - $day * 86400) . ' 08:00:00') + random_int(0, 36000)) . '.' . sprintf('%03d', random_int(0, 999));
                    $ins->execute([$t, $cid, $comp, $svc[$sn]['id'], $svc[$sn]['dom'], 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', random_int(1000, 9000), ++$rec, $ts]);
                    $n++;
                }
            }
        }
    }
}
$pdo->commit();

// --- discovered domains (Discovery queue) ---
$demoPcs = Db::all("SELECT computer_name FROM collectors WHERE tenant_id = ? AND computer_name LIKE 'DEMO-%' ORDER BY id LIMIT 4", [$t]);
foreach ([['new-llm-playground.ai', 'new'], ['promptbench.dev', 'new'], ['summarize-it.app', 'under_review'], ['cdn.example-assets.net', 'excluded']] as [$dom, $st]) {
    Db::run('INSERT IGNORE INTO discovered_domains (tenant_id, domain, status, hit_count, first_seen, last_seen) VALUES (?,?,?,?,UTC_TIMESTAMP() - INTERVAL 5 DAY, UTC_TIMESTAMP() - INTERVAL 1 HOUR)', [$t, $dom, $st, random_int(3, 40)]);
    $did = (int)Db::val('SELECT id FROM discovered_domains WHERE tenant_id = ? AND domain = ?', [$t, $dom]);
    foreach ($demoPcs as $p) Db::run('INSERT IGNORE INTO discovered_domain_hosts (discovered_id, computer_name, hit_count, first_seen, last_seen) VALUES (?,?,?,UTC_TIMESTAMP() - INTERVAL 5 DAY, UTC_TIMESTAMP() - INTERVAL 1 HOUR)', [$did, $p['computer_name'], random_int(1, 12)]);
}
// --- heartbeats and a few network connections ---
foreach (Db::all("SELECT id, computer_name FROM collectors WHERE tenant_id = ? AND computer_name LIKE 'DEMO-%'", [$t]) as $c) {
    Db::run('INSERT INTO collector_heartbeats (collector_id, heartbeat_timestamp, collector_version, status) VALUES (?, UTC_TIMESTAMP() - INTERVAL ? MINUTE, "1.0.0", "ok")', [$c['id'], random_int(1, 30)]);
    foreach (array_slice(array_values($svc), 0, 2) as $k => $s) {
        Db::run('INSERT IGNORE INTO network_connection_events (tenant_id, collector_id, computer_name, ai_service_id, destination_host, destination_ip, destination_port, protocol, process_image, sysmon_record_id, event_timestamp)
                 VALUES (?,?,?,?,?,?,443,"tcp","C:\Program Files\Google\Chrome\Application\chrome.exe",?,UTC_TIMESTAMP(3) - INTERVAL ? HOUR)',
            [$t, $c['id'], $c['computer_name'], $s['id'], $s['dom'], '203.0.113.' . random_int(2, 250), 900000 + $c['id'] * 10 + $k, random_int(1, 48)]);
    }
}
Risk::recalculate($t);
echo "Demo seeded for '$slug': $n synthetic events across " . $i . " DEMO-* workstations. Remove with: php tools\cleandemo.php $slug --demo-only --yes
";
