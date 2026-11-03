-- Least-privilege database accounts (OWASP ASVS V14 / A05). Run once as a DBA (edit the passwords first):
--     mysql -u root < sql/db-least-privilege.sql
--     php tools/db-grants.php saip_app            (run with an administrative DB account; grants per-table access)
-- Then run the web app with SAIP_DB_USER=saip_app SAIP_DB_PASS=...  and apply schema changes with the migration account:
--     SAIP_DB_USER=saip_migrate SAIP_DB_PASS=... php tools/migrate.php
--
-- Runtime account: data access only (no DDL, FILE or GRANT). The audit trail is append-only for it (SELECT, INSERT): see tools/db-grants.php.

CREATE USER IF NOT EXISTS 'saip_app'@'localhost' IDENTIFIED BY 'CHANGE-ME-long-random-app-password';
CREATE USER IF NOT EXISTS 'saip_migrate'@'localhost' IDENTIFIED BY 'CHANGE-ME-long-random-migrate-password';

-- Migration account: schema changes, only used when running tools/migrate.php.
GRANT ALL PRIVILEGES ON saip.* TO 'saip_migrate'@'localhost';
FLUSH PRIVILEGES;
