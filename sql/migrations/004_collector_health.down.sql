ALTER TABLE ai_usage_events DROP KEY idx_usage_domain;
ALTER TABLE collector_heartbeats DROP COLUMN config_version, DROP COLUMN spool_depth, DROP COLUMN failed_submissions, DROP COLUMN last_error;
ALTER TABLE collectors DROP COLUMN config_version_applied, DROP COLUMN last_config_sync, DROP COLUMN failed_submissions, DROP COLUMN spool_depth, DROP COLUMN last_error, DROP COLUMN workstation_ip;
