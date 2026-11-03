-- RBAC roles, account protection and audit context.
ALTER TABLE admin_users MODIFY role ENUM('super_admin','it_admin','auditor','viewer') NOT NULL DEFAULT 'viewer';
ALTER TABLE admin_users ADD COLUMN email VARCHAR(190) NULL AFTER display_name;
ALTER TABLE admin_users ADD COLUMN failed_logins SMALLINT UNSIGNED NOT NULL DEFAULT 0;
ALTER TABLE admin_users ADD COLUMN locked_until DATETIME NULL;
ALTER TABLE admin_users ADD COLUMN password_changed_at DATETIME NULL;
ALTER TABLE admin_users ADD COLUMN last_login_ip VARCHAR(45) NULL;
ALTER TABLE audit_logs ADD COLUMN ip_address VARCHAR(45) NULL;
ALTER TABLE audit_logs ADD COLUMN request_id VARCHAR(16) NULL;
ALTER TABLE audit_logs ADD INDEX idx_audit_action (tenant_id, action);
