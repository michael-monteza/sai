ALTER TABLE collectors
  ADD COLUMN config_version_applied INT UNSIGNED NULL,
  ADD COLUMN last_config_sync DATETIME NULL,
  ADD COLUMN failed_submissions INT UNSIGNED NOT NULL DEFAULT 0,
  ADD COLUMN spool_depth INT UNSIGNED NOT NULL DEFAULT 0,
  ADD COLUMN last_error VARCHAR(300) NULL,
  ADD COLUMN workstation_ip VARCHAR(45) NULL;
ALTER TABLE collector_heartbeats
  ADD COLUMN config_version INT UNSIGNED NULL,
  ADD COLUMN spool_depth INT UNSIGNED NULL,
  ADD COLUMN failed_submissions INT UNSIGNED NULL,
  ADD COLUMN last_error VARCHAR(300) NULL;
ALTER TABLE ai_usage_events ADD KEY idx_usage_domain (tenant_id, query_domain);
