ALTER TABLE signature_audit_logs
  ADD COLUMN client_id VARCHAR(100) NULL AFTER api_client_id;

CREATE INDEX idx_signature_audit_logs_client_id
  ON signature_audit_logs (client_id);

ALTER TABLE api_audit_logs
  ADD COLUMN client_id VARCHAR(100) NULL AFTER api_client_id;

CREATE INDEX idx_api_audit_logs_client_id
  ON api_audit_logs (client_id);
