-- Network-connection (Sysmon EID 3) matching by IP address for registered services on dedicated addresses.
CREATE TABLE IF NOT EXISTS ip_map (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id     INT UNSIGNED NOT NULL,
  ip            VARCHAR(45)  NOT NULL,
  ai_service_id INT UNSIGNED NOT NULL,
  domain        VARCHAR(253) NOT NULL,
  shared        TINYINT(1)   NOT NULL DEFAULT 0,
  reason        VARCHAR(40)  NULL,
  resolved_at   DATETIME     NOT NULL DEFAULT UTC_TIMESTAMP(),
  PRIMARY KEY (id),
  UNIQUE KEY uq_ipmap (tenant_id, ip, domain),
  KEY idx_ipmap_lookup (tenant_id, ip),
  CONSTRAINT fk_ipmap_service FOREIGN KEY (ai_service_id) REFERENCES ai_services(id) ON DELETE CASCADE
) ENGINE=InnoDB;

ALTER TABLE network_connection_events ADD COLUMN match_basis ENUM('host','ip') NOT NULL DEFAULT 'host';
