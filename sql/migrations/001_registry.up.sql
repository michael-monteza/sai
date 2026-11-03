-- Registry: services, domains, per-tenant config version, audit before/after.
ALTER TABLE ai_services
  MODIFY sanction_status ENUM('sanctioned','unsanctioned','under_review','excluded') NOT NULL DEFAULT 'unsanctioned',
  ADD COLUMN website VARCHAR(255) NULL AFTER description,
  ADD COLUMN logo_url VARCHAR(255) NULL AFTER website,
  ADD COLUMN archived TINYINT(1) NOT NULL DEFAULT 0 AFTER active,
  ADD COLUMN created_by VARCHAR(100) NULL,
  ADD COLUMN updated_by VARCHAR(100) NULL;
ALTER TABLE ai_domains
  ADD COLUMN domain_type ENUM('primary','secondary','api','authentication','cdn','other') NOT NULL DEFAULT 'primary' AFTER domain,
  ADD COLUMN matching_rule ENUM('exact','subdomain') NOT NULL DEFAULT 'subdomain' AFTER domain_type,
  ADD COLUMN notes VARCHAR(500) NULL,
  ADD COLUMN shared TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN confidence TINYINT UNSIGNED NOT NULL DEFAULT 100,
  ADD COLUMN first_observed DATETIME(3) NULL,
  ADD COLUMN last_observed DATETIME(3) NULL,
  ADD COLUMN created_at DATETIME NOT NULL DEFAULT UTC_TIMESTAMP(),
  ADD COLUMN updated_at DATETIME NOT NULL DEFAULT UTC_TIMESTAMP(),
  ADD COLUMN created_by VARCHAR(100) NULL,
  ADD COLUMN updated_by VARCHAR(100) NULL;
UPDATE ai_domains d JOIN ai_services s ON s.id = d.ai_service_id SET d.domain_type = IF(d.domain = s.primary_domain, 'primary', 'secondary');
ALTER TABLE tenants ADD COLUMN config_version INT UNSIGNED NOT NULL DEFAULT 1;
ALTER TABLE audit_logs ADD COLUMN before_json TEXT NULL, ADD COLUMN after_json TEXT NULL;
