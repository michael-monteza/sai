ALTER TABLE audit_logs DROP COLUMN before_json, DROP COLUMN after_json;
ALTER TABLE tenants DROP COLUMN config_version;
ALTER TABLE ai_domains DROP COLUMN domain_type, DROP COLUMN matching_rule, DROP COLUMN notes, DROP COLUMN shared, DROP COLUMN confidence, DROP COLUMN first_observed, DROP COLUMN last_observed, DROP COLUMN created_at, DROP COLUMN updated_at, DROP COLUMN created_by, DROP COLUMN updated_by;
UPDATE ai_services SET sanction_status = 'under_review' WHERE sanction_status = 'excluded';
ALTER TABLE ai_services DROP COLUMN website, DROP COLUMN logo_url, DROP COLUMN archived, DROP COLUMN created_by, DROP COLUMN updated_by,
  MODIFY sanction_status ENUM('sanctioned','unsanctioned','under_review') NOT NULL DEFAULT 'unsanctioned';
