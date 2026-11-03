UPDATE ai_services SET source = 'registry' WHERE source = 'import';
ALTER TABLE ai_services MODIFY source ENUM('registry','discovered','manual','request') NOT NULL DEFAULT 'manual';
