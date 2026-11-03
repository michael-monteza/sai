<?php
declare(strict_types=1);

namespace Saip;

final class Tenants
{
    public static function newEnrollmentKey(): string
    {
        return 'enr_' . bin2hex(random_bytes(20));
    }

    public static function slugify(string $name): string
    {
        $s = trim(preg_replace('/[^a-z0-9]+/', '-', strtolower($name)), '-');
        return substr($s !== '' ? $s : 'tenant', 0, 60);
    }

    /**
     * Creates a company tenant and clones the AI service catalogue, ISO 42001 controls and policies into it.
     * @return array{id:int,slug:string,enrollment_key:string}
     */
    public static function create(string $name, ?string $slug = null): array
    {
        $slug = self::slugify($slug ?: $name);
        $key = self::newEnrollmentKey();
        $pdo = Db::pdo();
        $pdo->beginTransaction();
        try {
            if (Db::val('SELECT 1 FROM tenants WHERE slug = ?', [$slug])) {
                throw new ApiException(409, 'tenant_exists', 'A tenant with this short name already exists.');
            }
            Db::run('INSERT INTO tenants (name, slug, enrollment_key_hash) VALUES (?, ?, ?)', [$name, $slug, hash('sha256', $key)]);
            $tid = Db::insertId();

            foreach (Db::all('SELECT * FROM catalog_services ORDER BY id') as $c) {
                $score = Risk::score($c['data_class'], (int)$c['training_exposure'], (int)$c['vendor_risk'], (int)$c['identity_risk'], 0);
                Db::run('INSERT INTO ai_services (tenant_id, service_name, provider, primary_domain, category, sanction_status, description,
                         data_class, training_exposure, vendor_risk, identity_risk, risk_score, lifecycle, source)
                         VALUES (?, ?, ?, ?, ?, "unsanctioned", ?, ?, ?, ?, ?, ?, "Shadow Usage Detected", "registry")',
                    [$tid, $c['service_name'], $c['provider'], $c['primary_domain'], $c['category'], $c['description'],
                     $c['data_class'], $c['training_exposure'], $c['vendor_risk'], $c['identity_risk'], $score]);
                $sid = Db::insertId();
                foreach (Db::all('SELECT domain FROM catalog_domains WHERE catalog_service_id = ?', [$c['id']]) as $d) {
                    Db::run('INSERT INTO ai_domains (tenant_id, ai_service_id, domain) VALUES (?, ?, ?)', [$tid, $sid, $d['domain']]);
                }
            }
            Db::run('INSERT INTO iso_controls (tenant_id, control_code, domain, name, description, sort_order)
                     SELECT ?, control_code, domain, name, description, sort_order FROM catalog_controls', [$tid]);
            Db::run('INSERT INTO policies (tenant_id, name, policy_type, status, description)
                     SELECT ?, name, policy_type, status, description FROM catalog_policies', [$tid]);
            Db::run('INSERT INTO settings (tenant_id, setting_key, setting_value) VALUES (?, "collector_offline_after_minutes", "15")', [$tid]);
            $pdo->commit();
        } catch (\Throwable $e) {
            $pdo->rollBack();
            throw $e;
        }
        return ['id' => $tid, 'slug' => $slug, 'enrollment_key' => $key];
    }
}
