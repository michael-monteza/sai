-- SAIP - Shadow AI Platform (multi-tenant). One tenant = one company/customer.
-- Install (destroys nothing if tables exist; for a clean dev reset: DROP DATABASE saip first):
--   C:\xampp\mysql\bin\mysql.exe -u root < sql\schema.sql
--   C:\xampp\mysql\bin\mysql.exe -u root saip < sql\catalog_seed.sql

CREATE DATABASE IF NOT EXISTS saip CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE saip;

CREATE TABLE IF NOT EXISTS tenants (
  id                  INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name                VARCHAR(150) NOT NULL,
  slug                VARCHAR(60)  NOT NULL,
  status              ENUM('active','suspended') NOT NULL DEFAULT 'active',
  enrollment_key_hash CHAR(64)     NOT NULL,         -- collectors present this to register into the tenant
  created_at          DATETIME     NOT NULL DEFAULT UTC_TIMESTAMP(),
  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_slug (slug),
  UNIQUE KEY uq_tenant_enroll (enrollment_key_hash)
) ENGINE=InnoDB;

-- tenant_id NULL = platform super administrator (can switch between all tenants).
CREATE TABLE IF NOT EXISTS admin_users (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id     INT UNSIGNED NULL,
  username      VARCHAR(60)  NOT NULL,
  display_name  VARCHAR(100) NOT NULL DEFAULT '',
  password_hash VARCHAR(255) NOT NULL,
  role          ENUM('super_admin','it_admin','viewer') NOT NULL DEFAULT 'viewer',
  active        TINYINT(1) NOT NULL DEFAULT 1,
  created_at    DATETIME NOT NULL DEFAULT UTC_TIMESTAMP(),
  last_login    DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_admin_username (username),
  CONSTRAINT fk_admin_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS collectors (
  id                INT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id         INT UNSIGNED NOT NULL,
  computer_name     VARCHAR(63)  NOT NULL,
  mac_address       CHAR(17)     NULL,
  collector_uuid    CHAR(36)     NOT NULL,
  api_key_hash      CHAR(64)     NOT NULL,
  status            ENUM('pending','authorized','suspended','revoked') NOT NULL DEFAULT 'pending',
  registered_at     DATETIME     NOT NULL DEFAULT UTC_TIMESTAMP(),
  last_seen         DATETIME     NULL,
  collector_version VARCHAR(20)  NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_collector_uuid (collector_uuid),
  KEY idx_collector_tenant (tenant_id, computer_name),
  CONSTRAINT fk_collector_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ai_services (
  id                INT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id         INT UNSIGNED NOT NULL,
  service_name      VARCHAR(100) NOT NULL,
  provider          VARCHAR(100) NOT NULL,
  primary_domain    VARCHAR(253) NOT NULL,
  category          VARCHAR(60)  NOT NULL DEFAULT 'Generative AI',
  sanction_status   ENUM('sanctioned','unsanctioned','under_review') NOT NULL DEFAULT 'unsanctioned',
  description       VARCHAR(500) NULL,
  active            TINYINT(1)   NOT NULL DEFAULT 1,
  data_class        ENUM('Public','Internal','Confidential','Restricted / PII') NOT NULL DEFAULT 'Internal',
  training_exposure TINYINT UNSIGNED NOT NULL DEFAULT 50,
  vendor_risk       TINYINT UNSIGNED NOT NULL DEFAULT 50,
  identity_risk     TINYINT UNSIGNED NOT NULL DEFAULT 50,
  usage_volume      TINYINT UNSIGNED NOT NULL DEFAULT 0,
  risk_score        TINYINT UNSIGNED NOT NULL DEFAULT 0,
  owner             VARCHAR(120) NOT NULL DEFAULT 'Unassigned',
  purpose           VARCHAR(500) NULL,
  data_categories   VARCHAR(300) NULL,
  lifecycle         ENUM('Shadow Usage Detected','Under Security Evaluation','Formally Sanctioned','Prohibited / Blocked','Decommissioned') NOT NULL DEFAULT 'Shadow Usage Detected',
  source            ENUM('registry','discovered','manual','request') NOT NULL DEFAULT 'manual',
  created_at        DATETIME NOT NULL DEFAULT UTC_TIMESTAMP(),
  updated_at        DATETIME NOT NULL DEFAULT UTC_TIMESTAMP(),
  PRIMARY KEY (id),
  UNIQUE KEY uq_service_name (tenant_id, service_name),
  CONSTRAINT fk_service_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ai_domains (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id     INT UNSIGNED NOT NULL,
  ai_service_id INT UNSIGNED NOT NULL,
  domain        VARCHAR(253) NOT NULL,
  active        TINYINT(1)   NOT NULL DEFAULT 1,
  blocked       TINYINT(1)   NOT NULL DEFAULT 0,      -- included in the exported DNS blocklist feed
  PRIMARY KEY (id),
  UNIQUE KEY uq_domain (tenant_id, domain),
  KEY idx_domain_service (ai_service_id),
  CONSTRAINT fk_domain_service FOREIGN KEY (ai_service_id) REFERENCES ai_services(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Observed DNS / network telemetry. NOT verified sessions.
CREATE TABLE IF NOT EXISTS ai_usage_events (
  id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id          INT UNSIGNED NOT NULL,
  collector_id       INT UNSIGNED NOT NULL,
  computer_name      VARCHAR(63)  NOT NULL,
  ai_service_id      INT UNSIGNED NOT NULL,
  query_domain       VARCHAR(253) NOT NULL,
  process_image      VARCHAR(512) NULL,
  process_id         INT UNSIGNED NULL,
  sysmon_record_id   BIGINT UNSIGNED NOT NULL,
  event_timestamp    DATETIME(3)  NOT NULL,
  received_timestamp DATETIME(3)  NOT NULL,
  event_type         ENUM('dns_query','network_connection') NOT NULL DEFAULT 'dns_query',
  PRIMARY KEY (id),
  UNIQUE KEY uq_event (collector_id, sysmon_record_id, event_timestamp),
  KEY idx_evt_tenant_time (tenant_id, event_timestamp),
  KEY idx_evt_service_time (tenant_id, ai_service_id, event_timestamp),
  KEY idx_evt_computer_time (tenant_id, computer_name, event_timestamp),
  CONSTRAINT fk_evt_collector FOREIGN KEY (collector_id) REFERENCES collectors(id),
  CONSTRAINT fk_evt_service   FOREIGN KEY (ai_service_id) REFERENCES ai_services(id)
) ENGINE=InnoDB;

-- AI-looking domains reported by collectors that match no registry entry: admin review only.
CREATE TABLE IF NOT EXISTS unknown_domains (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id     INT UNSIGNED NOT NULL,
  domain        VARCHAR(253) NOT NULL,
  hit_count     INT UNSIGNED NOT NULL DEFAULT 1,
  first_seen    DATETIME(3)  NOT NULL,
  last_seen     DATETIME(3)  NOT NULL,
  last_computer VARCHAR(63)  NULL,
  review_status ENUM('new','dismissed','promoted') NOT NULL DEFAULT 'new',
  PRIMARY KEY (id),
  UNIQUE KEY uq_unknown_domain (tenant_id, domain)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS collector_heartbeats (
  id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  collector_id        INT UNSIGNED NOT NULL,
  heartbeat_timestamp DATETIME NOT NULL DEFAULT UTC_TIMESTAMP(),
  collector_version   VARCHAR(20) NULL,
  status              ENUM('ok','degraded','error') NOT NULL DEFAULT 'ok',
  PRIMARY KEY (id),
  KEY idx_hb_collector_time (collector_id, heartbeat_timestamp),
  CONSTRAINT fk_hb_collector FOREIGN KEY (collector_id) REFERENCES collectors(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
  id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id       INT UNSIGNED NULL,
  administrator   VARCHAR(100) NOT NULL,
  action          VARCHAR(60)  NOT NULL,
  affected_record VARCHAR(120) NULL,
  timestamp       DATETIME NOT NULL DEFAULT UTC_TIMESTAMP(),
  details         TEXT NULL,
  PRIMARY KEY (id),
  KEY idx_audit_tenant_time (tenant_id, timestamp)
) ENGINE=InnoDB;

-- Optional mapping computer -> department. Computer name is the identifier; no Windows usernames.
CREATE TABLE IF NOT EXISTS employee_inventory (
  id                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id          INT UNSIGNED NOT NULL,
  computer_name      VARCHAR(63)  NOT NULL,
  employee_reference VARCHAR(100) NULL,
  department         VARCHAR(100) NULL,
  business_unit      VARCHAR(100) NULL,
  assigned_date      DATE NULL,
  status             ENUM('active','retired','spare') NOT NULL DEFAULT 'active',
  PRIMARY KEY (id),
  UNIQUE KEY uq_inventory_computer (tenant_id, computer_name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS settings (
  tenant_id     INT UNSIGNED NOT NULL,
  setting_key   VARCHAR(80)  NOT NULL,
  setting_value VARCHAR(500) NOT NULL,
  PRIMARY KEY (tenant_id, setting_key)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS rate_limits (
  bucket       VARCHAR(100) NOT NULL,
  window_start INT UNSIGNED NOT NULL,
  hits         INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, window_start)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS policies (
  id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id   INT UNSIGNED NOT NULL,
  name        VARCHAR(150) NOT NULL,
  policy_type VARCHAR(60)  NOT NULL,
  status      ENUM('Enforced','Draft','Disabled') NOT NULL DEFAULT 'Draft',
  description VARCHAR(500) NULL,
  created_at  DATETIME NOT NULL DEFAULT UTC_TIMESTAMP(),
  PRIMARY KEY (id),
  UNIQUE KEY uq_policy_name (tenant_id, name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS access_requests (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id     INT UNSIGNED NOT NULL,
  tool_name     VARCHAR(150) NOT NULL,
  domain        VARCHAR(253) NULL,
  requester     VARCHAR(150) NOT NULL,
  justification VARCHAR(500) NOT NULL,
  data_class    VARCHAR(80)  NOT NULL DEFAULT 'Internal',
  status        ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  created_at    DATETIME NOT NULL DEFAULT UTC_TIMESTAMP(),
  decided_at    DATETIME NULL,
  decided_by    VARCHAR(100) NULL,
  service_id    INT UNSIGNED NULL,
  PRIMARY KEY (id),
  KEY idx_req_tenant_status (tenant_id, status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS iso_controls (
  id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id    INT UNSIGNED NOT NULL,
  control_code VARCHAR(20)  NOT NULL,
  domain       VARCHAR(60)  NOT NULL,
  name         VARCHAR(150) NOT NULL,
  description  VARCHAR(400) NOT NULL,
  compliant    TINYINT(1)   NOT NULL DEFAULT 0,
  evidence     VARCHAR(300) NULL,
  notes        VARCHAR(500) NULL,
  sort_order   SMALLINT     NOT NULL DEFAULT 0,
  updated_at   DATETIME     NULL,
  updated_by   VARCHAR(100) NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_control_code (tenant_id, control_code)
) ENGINE=InnoDB;

-- Templates cloned into every new tenant (a company can then change its own copy).
CREATE TABLE IF NOT EXISTS catalog_services (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  service_name VARCHAR(100) NOT NULL, provider VARCHAR(100) NOT NULL, primary_domain VARCHAR(253) NOT NULL,
  category VARCHAR(60) NOT NULL, description VARCHAR(500) NULL,
  data_class VARCHAR(20) NOT NULL DEFAULT 'Internal',
  training_exposure TINYINT UNSIGNED NOT NULL DEFAULT 50, vendor_risk TINYINT UNSIGNED NOT NULL DEFAULT 50, identity_risk TINYINT UNSIGNED NOT NULL DEFAULT 50,
  PRIMARY KEY (id), UNIQUE KEY uq_cat_service (service_name)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS catalog_domains (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT, catalog_service_id INT UNSIGNED NOT NULL, domain VARCHAR(253) NOT NULL,
  PRIMARY KEY (id), UNIQUE KEY uq_cat_domain (domain),
  CONSTRAINT fk_catdom FOREIGN KEY (catalog_service_id) REFERENCES catalog_services(id) ON DELETE CASCADE
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS catalog_controls (
  control_code VARCHAR(20) NOT NULL, domain VARCHAR(60) NOT NULL, name VARCHAR(150) NOT NULL,
  description VARCHAR(400) NOT NULL, sort_order SMALLINT NOT NULL DEFAULT 0, PRIMARY KEY (control_code)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS catalog_policies (
  name VARCHAR(150) NOT NULL, policy_type VARCHAR(60) NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'Draft',
  description VARCHAR(500) NULL, PRIMARY KEY (name)
) ENGINE=InnoDB;
