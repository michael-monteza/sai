DROP TABLE IF EXISTS network_connection_events;
ALTER TABLE ai_usage_events DROP COLUMN query_status, DROP COLUMN process_guid, DROP COLUMN workstation_ip, DROP COLUMN destination_ip;
