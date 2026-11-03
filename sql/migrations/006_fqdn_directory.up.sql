-- FQDN directory: root domain, DNS registrar, functional purpose and category per registered domain.
ALTER TABLE ai_domains ADD COLUMN root_domain VARCHAR(253) NULL AFTER domain;
ALTER TABLE ai_domains ADD COLUMN registrar VARCHAR(150) NULL AFTER root_domain;
ALTER TABLE ai_domains ADD COLUMN purpose VARCHAR(400) NULL AFTER registrar;
ALTER TABLE ai_domains ADD COLUMN category VARCHAR(100) NULL AFTER purpose;
ALTER TABLE ai_domains ADD INDEX idx_domain_registrar (tenant_id, registrar);
