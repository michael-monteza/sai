-- Reverse-DNS results for the IP matching heuristics (a lookup can take seconds; results are reused for a week).
CREATE TABLE IF NOT EXISTS ip_ptr_cache (
  ip         VARCHAR(45)  NOT NULL,
  ptr        VARCHAR(253) NULL,
  checked_at DATETIME     NOT NULL DEFAULT UTC_TIMESTAMP(),
  PRIMARY KEY (ip)
) ENGINE=InnoDB;
