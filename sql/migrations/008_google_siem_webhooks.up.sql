-- Google sign-in, platform settings, SIEM / webhook integrations and the event outbox.
CREATE TABLE IF NOT EXISTS platform_settings (
  name       VARCHAR(80)  NOT NULL,
  value      TEXT         NULL,
  secret     TINYINT(1)   NOT NULL DEFAULT 0,
  updated_at DATETIME     NOT NULL DEFAULT UTC_TIMESTAMP(),
  updated_by VARCHAR(100) NULL,
  PRIMARY KEY (name)
) ENGINE=InnoDB;

ALTER TABLE admin_users ADD COLUMN google_sub VARCHAR(64) NULL;
ALTER TABLE admin_users ADD COLUMN local_login TINYINT(1) NOT NULL DEFAULT 1;
ALTER TABLE admin_users ADD UNIQUE KEY uq_admin_google_sub (google_sub);
ALTER TABLE admin_users ADD INDEX idx_admin_email (email);

CREATE TABLE IF NOT EXISTS event_outbox (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id  INT UNSIGNED NOT NULL,
  type       VARCHAR(40) NOT NULL,
  payload    MEDIUMTEXT  NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT UTC_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY idx_outbox_tenant (tenant_id, id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS integrations (
  id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id       INT UNSIGNED NOT NULL,
  name            VARCHAR(100) NOT NULL,
  kind            ENUM('webhook','splunk_hec','syslog') NOT NULL,
  url             VARCHAR(500) NULL,
  host            VARCHAR(253) NULL,
  port            SMALLINT UNSIGNED NULL,
  protocol        ENUM('udp','tcp') NULL,
  format          ENUM('json','cef') NOT NULL DEFAULT 'json',
  secret_enc      TEXT NULL,
  events          VARCHAR(400) NOT NULL DEFAULT 'audit.event,shadow_ai.detected,discovery.new_domain',
  active          TINYINT(1) NOT NULL DEFAULT 1,
  cursor_outbox   BIGINT UNSIGNED NOT NULL DEFAULT 0,
  cursor_usage    BIGINT UNSIGNED NOT NULL DEFAULT 0,
  failures        INT UNSIGNED NOT NULL DEFAULT 0,
  last_status     VARCHAR(20) NULL,
  last_error      VARCHAR(300) NULL,
  last_success_at DATETIME NULL,
  next_attempt_at DATETIME NULL,
  created_by      VARCHAR(100) NULL,
  created_at      DATETIME NOT NULL DEFAULT UTC_TIMESTAMP(),
  updated_at      DATETIME NOT NULL DEFAULT UTC_TIMESTAMP(),
  PRIMARY KEY (id),
  UNIQUE KEY uq_integration_name (tenant_id, name),
  KEY idx_integration_active (active, next_attempt_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS integration_deliveries (
  id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  integration_id INT UNSIGNED NOT NULL,
  event_count    INT UNSIGNED NOT NULL DEFAULT 0,
  status         ENUM('ok','failed') NOT NULL,
  http_status    SMALLINT UNSIGNED NULL,
  error          VARCHAR(300) NULL,
  duration_ms    INT UNSIGNED NULL,
  created_at     DATETIME NOT NULL DEFAULT UTC_TIMESTAMP(),
  PRIMARY KEY (id),
  KEY idx_delivery_integration (integration_id, id),
  CONSTRAINT fk_delivery_integration FOREIGN KEY (integration_id) REFERENCES integrations(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS api_tokens (
  id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id    INT UNSIGNED NOT NULL,
  name         VARCHAR(100) NOT NULL,
  token_hash   CHAR(64) NOT NULL,
  scope        VARCHAR(40) NOT NULL DEFAULT 'siem.read',
  last_used_at DATETIME NULL,
  revoked      TINYINT(1) NOT NULL DEFAULT 0,
  created_by   VARCHAR(100) NULL,
  created_at   DATETIME NOT NULL DEFAULT UTC_TIMESTAMP(),
  PRIMARY KEY (id),
  UNIQUE KEY uq_token_hash (token_hash),
  KEY idx_token_tenant (tenant_id)
) ENGINE=InnoDB;
