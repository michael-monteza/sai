DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS integration_deliveries;
DROP TABLE IF EXISTS integrations;
DROP TABLE IF EXISTS event_outbox;
ALTER TABLE admin_users DROP INDEX idx_admin_email;
ALTER TABLE admin_users DROP INDEX uq_admin_google_sub;
ALTER TABLE admin_users DROP COLUMN local_login;
ALTER TABLE admin_users DROP COLUMN google_sub;
DROP TABLE IF EXISTS platform_settings;
