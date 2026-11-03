ALTER TABLE ai_usage_events
  ADD COLUMN query_status VARCHAR(40) NULL,
  ADD COLUMN process_guid CHAR(36) NULL,
  ADD COLUMN workstation_ip VARCHAR(45) NULL,
  ADD COLUMN destination_ip VARCHAR(45) NULL;
CREATE TABLE network_connection_events (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id INT UNSIGNED NOT NULL,
  collector_id INT UNSIGNED NOT NULL,
  computer_name VARCHAR(63) NOT NULL,
  ai_service_id INT UNSIGNED NULL,
  destination_host VARCHAR(253) NULL,
  destination_ip VARCHAR(45) NOT NULL,
  destination_port INT UNSIGNED NULL,
  protocol VARCHAR(10) NULL,
  process_image VARCHAR(512) NULL,
  process_guid CHAR(36) NULL,
  sysmon_record_id BIGINT UNSIGNED NOT NULL,
  event_timestamp DATETIME(3) NOT NULL,
  received_timestamp DATETIME(3) NOT NULL DEFAULT UTC_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_net_event (collector_id, sysmon_record_id, event_timestamp),
  KEY idx_net_tenant_time (tenant_id, event_timestamp),
  KEY idx_net_service (ai_service_id),
  CONSTRAINT fk_net_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
  CONSTRAINT fk_net_collector FOREIGN KEY (collector_id) REFERENCES collectors (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
