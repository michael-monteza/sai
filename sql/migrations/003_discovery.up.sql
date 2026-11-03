CREATE TABLE discovered_domains (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id INT UNSIGNED NOT NULL,
  domain VARCHAR(253) NOT NULL,
  status ENUM('new','under_review','classified','excluded') NOT NULL DEFAULT 'new',
  hit_count INT UNSIGNED NOT NULL DEFAULT 1,
  first_seen DATETIME(3) NOT NULL,
  last_seen DATETIME(3) NOT NULL,
  notes VARCHAR(500) NULL,
  classified_service_id INT UNSIGNED NULL,
  updated_by VARCHAR(100) NULL,
  updated_at DATETIME NOT NULL DEFAULT UTC_TIMESTAMP(),
  PRIMARY KEY (id),
  UNIQUE KEY uq_discovered (tenant_id, domain),
  CONSTRAINT fk_disc_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE discovered_domain_hosts (
  discovered_id INT UNSIGNED NOT NULL,
  computer_name VARCHAR(63) NOT NULL,
  hit_count INT UNSIGNED NOT NULL DEFAULT 1,
  first_seen DATETIME(3) NOT NULL,
  last_seen DATETIME(3) NOT NULL,
  PRIMARY KEY (discovered_id, computer_name),
  CONSTRAINT fk_dh_disc FOREIGN KEY (discovered_id) REFERENCES discovered_domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO discovered_domains (tenant_id, domain, status, hit_count, first_seen, last_seen)
  SELECT tenant_id, domain, CASE review_status WHEN 'dismissed' THEN 'excluded' WHEN 'promoted' THEN 'classified' ELSE 'new' END, hit_count, first_seen, last_seen FROM unknown_domains;
INSERT INTO discovered_domain_hosts (discovered_id, computer_name, hit_count, first_seen, last_seen)
  SELECT dd.id, u.last_computer, u.hit_count, u.first_seen, u.last_seen FROM unknown_domains u
  JOIN discovered_domains dd ON dd.tenant_id = u.tenant_id AND dd.domain = u.domain WHERE u.last_computer IS NOT NULL;
