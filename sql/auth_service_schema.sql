-- Auth Service SNAP Security - MySQL DDL
-- Store partner public keys only. Never store partner private keys.
-- Store hashes for client secrets and tokens; never store raw secrets/tokens.

CREATE TABLE merchants (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  merchant_code VARCHAR(64) NOT NULL UNIQUE,
  merchant_name VARCHAR(150) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  created_by VARCHAR(100) NOT NULL DEFAULT 'system',
  updated_by VARCHAR(100) NULL
);

CREATE TABLE api_clients (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  merchant_id BIGINT NOT NULL,
  client_id VARCHAR(100) NOT NULL UNIQUE,
  client_name VARCHAR(150) NOT NULL,
  client_secret_hash VARCHAR(255) NULL,
  channel_id VARCHAR(5) NULL,
  allowed_ip_cidr VARCHAR(255) NULL,
  token_ttl_seconds INT NOT NULL DEFAULT 900,
  status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  created_by VARCHAR(100) NOT NULL DEFAULT 'system',
  updated_by VARCHAR(100) NULL,
  CONSTRAINT fk_api_clients_merchant FOREIGN KEY (merchant_id) REFERENCES merchants(id)
);

CREATE TABLE client_public_keys (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  api_client_id BIGINT NOT NULL,
  key_id VARCHAR(64) NOT NULL,
  public_key_pem TEXT NOT NULL,
  algorithm VARCHAR(32) NOT NULL DEFAULT 'SHA256withRSA',
  valid_from TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  valid_to TIMESTAMP NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  created_by VARCHAR(100) NOT NULL DEFAULT 'system',
  updated_by VARCHAR(100) NULL,
  UNIQUE KEY uk_client_key (api_client_id, key_id),
  CONSTRAINT fk_client_public_keys_client FOREIGN KEY (api_client_id) REFERENCES api_clients(id)
);

CREATE TABLE client_scopes (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  api_client_id BIGINT NOT NULL,
  scope_code VARCHAR(100) NOT NULL,
  service_code VARCHAR(10) NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  created_by VARCHAR(100) NOT NULL DEFAULT 'system',
  updated_by VARCHAR(100) NULL,
  UNIQUE KEY uk_client_scope (api_client_id, scope_code),
  CONSTRAINT fk_client_scopes_client FOREIGN KEY (api_client_id) REFERENCES api_clients(id)
);

CREATE TABLE oauth_access_tokens (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  api_client_id BIGINT NOT NULL,
  token_jti VARCHAR(64) NOT NULL UNIQUE,
  token_hash VARCHAR(128) NOT NULL,
  token_type VARCHAR(20) NOT NULL DEFAULT 'Bearer',
  scopes VARCHAR(500) NULL,
  issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP NULL,
  revoke_reason VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  created_by VARCHAR(100) NOT NULL DEFAULT 'system',
  updated_by VARCHAR(100) NULL,
  INDEX idx_access_client_exp (api_client_id, expires_at),
  CONSTRAINT fk_access_tokens_client FOREIGN KEY (api_client_id) REFERENCES api_clients(id)
);

CREATE TABLE oauth_auth_codes (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  api_client_id BIGINT NOT NULL,
  auth_code_hash VARCHAR(128) NOT NULL UNIQUE,
  customer_reference VARCHAR(150) NOT NULL,
  redirect_uri VARCHAR(500) NULL,
  scopes VARCHAR(500) NULL,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  created_by VARCHAR(100) NOT NULL DEFAULT 'system',
  updated_by VARCHAR(100) NULL,
  CONSTRAINT fk_auth_codes_client FOREIGN KEY (api_client_id) REFERENCES api_clients(id)
);

CREATE TABLE oauth_refresh_tokens (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  api_client_id BIGINT NOT NULL,
  refresh_token_hash VARCHAR(128) NOT NULL UNIQUE,
  customer_reference VARCHAR(150) NOT NULL,
  scopes VARCHAR(500) NULL,
  issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  created_by VARCHAR(100) NOT NULL DEFAULT 'system',
  updated_by VARCHAR(100) NULL,
  INDEX idx_refresh_client_exp (api_client_id, expires_at),
  CONSTRAINT fk_refresh_tokens_client FOREIGN KEY (api_client_id) REFERENCES api_clients(id)
);

CREATE TABLE signature_audit_logs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  api_client_id BIGINT NULL,
  request_id VARCHAR(64) NOT NULL,
  signature_type VARCHAR(30) NOT NULL,
  algorithm VARCHAR(32) NOT NULL,
  string_to_sign_hash VARCHAR(128) NOT NULL,
  validation_result VARCHAR(20) NOT NULL,
  failure_reason VARCHAR(255) NULL,
  remote_ip VARCHAR(64) NULL,
  user_agent VARCHAR(500) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  created_by VARCHAR(100) NOT NULL DEFAULT 'system',
  updated_by VARCHAR(100) NULL,
  INDEX idx_siglog_request (request_id),
  CONSTRAINT fk_siglog_client FOREIGN KEY (api_client_id) REFERENCES api_clients(id)
);

CREATE TABLE replay_protection_keys (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  api_client_id BIGINT NOT NULL,
  external_id VARCHAR(36) NOT NULL,
  request_date DATE NOT NULL,
  endpoint_path VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  created_by VARCHAR(100) NOT NULL DEFAULT 'system',
  updated_by VARCHAR(100) NULL,
  UNIQUE KEY uk_replay_key (api_client_id, external_id, request_date, endpoint_path),
  CONSTRAINT fk_replay_client FOREIGN KEY (api_client_id) REFERENCES api_clients(id)
);

CREATE TABLE api_audit_logs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  api_client_id BIGINT NULL,
  request_id VARCHAR(64) NOT NULL,
  endpoint_path VARCHAR(255) NOT NULL,
  http_method VARCHAR(10) NOT NULL,
  http_status INT NOT NULL,
  response_code VARCHAR(7) NULL,
  response_message VARCHAR(150) NULL,
  latency_ms BIGINT NULL,
  remote_ip VARCHAR(64) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  created_by VARCHAR(100) NOT NULL DEFAULT 'system',
  updated_by VARCHAR(100) NULL,
  INDEX idx_api_audit_request (request_id),
  INDEX idx_api_audit_client_date (api_client_id, created_at),
  CONSTRAINT fk_api_audit_client FOREIGN KEY (api_client_id) REFERENCES api_clients(id)
);

CREATE TABLE response_code_mappings (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  category VARCHAR(30) NOT NULL,
  http_status INT NOT NULL,
  service_code VARCHAR(10) NOT NULL,
  case_code VARCHAR(2) NOT NULL,
  response_code VARCHAR(7) NOT NULL UNIQUE,
  response_message VARCHAR(150) NOT NULL,
  description VARCHAR(500) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  created_by VARCHAR(100) NOT NULL DEFAULT 'system',
  updated_by VARCHAR(100) NULL
);

INSERT INTO response_code_mappings
(category, http_status, service_code, case_code, response_code, response_message, description)
VALUES
('SUCCESS', 200, '73', '00', '2007300', 'Successful', 'Access Token B2B success'),
('CLIENT_ERROR', 400, '73', '02', '4007302', 'Invalid Mandatory Field', 'Header/body mandatory field invalid'),
('AUTH_ERROR', 401, '73', '00', '4017300', 'Unauthorized', 'Invalid client/signature/IP policy'),
('SERVER_ERROR', 500, '73', '00', '5007300', 'General Error', 'Unexpected internal error');
