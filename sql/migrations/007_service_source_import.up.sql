ALTER TABLE ai_services MODIFY source ENUM('registry','discovered','manual','request','import') NOT NULL DEFAULT 'manual';
