-- Local development seed data for SNAP Auth Service.
-- This migration stores only the partner public key PEM.

INSERT INTO response_code_mappings
(category, http_status, service_code, case_code, response_code, response_message, description, created_by, updated_by)
VALUES
('SUCCESS', 200, '73', '00', '2007300', 'Successful', 'Access Token B2B success', 'flyway', 'flyway'),
('CLIENT_ERROR', 400, '73', '02', '4007302', 'Invalid Mandatory Field', 'Header/body mandatory field invalid', 'flyway', 'flyway'),
('AUTH_ERROR', 401, '73', '00', '4017300', 'Unauthorized', 'Invalid client/signature/IP policy', 'flyway', 'flyway'),
('AUTH_ERROR', 401, '73', '01', '4017301', 'Invalid Token', 'Token expired, revoked, malformed, or otherwise invalid', 'flyway', 'flyway'),
('AUTH_ERROR', 403, '73', '00', '4037300', 'Forbidden', 'Client or token does not have sufficient scope', 'flyway', 'flyway'),
('CLIENT_ERROR', 409, '73', '00', '4097300', 'Conflict', 'Duplicate or replayed request', 'flyway', 'flyway'),
('SERVER_ERROR', 500, '73', '00', '5007300', 'General Error', 'Unexpected internal error', 'flyway', 'flyway')
ON DUPLICATE KEY UPDATE
  category = VALUES(category),
  http_status = VALUES(http_status),
  service_code = VALUES(service_code),
  case_code = VALUES(case_code),
  response_message = VALUES(response_message),
  description = VALUES(description),
  updated_at = CURRENT_TIMESTAMP,
  updated_by = VALUES(updated_by);

INSERT INTO merchants
(merchant_code, merchant_name, status, created_by, updated_by)
VALUES
('SNAP-LOCAL', 'SNAP Local Merchant', 'ACTIVE', 'flyway', 'flyway')
ON DUPLICATE KEY UPDATE
  merchant_name = VALUES(merchant_name),
  status = VALUES(status),
  updated_at = CURRENT_TIMESTAMP,
  updated_by = VALUES(updated_by);

INSERT INTO api_clients
(merchant_id, client_id, client_name, client_secret_hash, channel_id, allowed_ip_cidr, token_ttl_seconds, status, created_by, updated_by)
SELECT
  m.id,
  '962489e9-de5d-4eb7-92a4-b07d44d64bf4',
  'SNAP Local API Client',
  NULL,
  '95221',
  '0.0.0.0/0',
  900,
  'ACTIVE',
  'flyway',
  'flyway'
FROM merchants m
WHERE m.merchant_code = 'SNAP-LOCAL'
ON DUPLICATE KEY UPDATE
  merchant_id = VALUES(merchant_id),
  client_name = VALUES(client_name),
  client_secret_hash = VALUES(client_secret_hash),
  channel_id = VALUES(channel_id),
  allowed_ip_cidr = VALUES(allowed_ip_cidr),
  token_ttl_seconds = VALUES(token_ttl_seconds),
  status = VALUES(status),
  updated_at = CURRENT_TIMESTAMP,
  updated_by = VALUES(updated_by);

INSERT INTO client_public_keys
(api_client_id, key_id, public_key_pem, algorithm, valid_from, valid_to, status, created_by, updated_by)
SELECT
  c.id,
  'local-dev-key-1',
  '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA24HMiE1P0ZL712qThbo/
4Wh5pMcN1O8EF+XJIE1HfRDQmowz2d/kj4JLnuCaZuPDQozdqgGuQDRYm5R06Bhd
oGhWt9hcfKEO3oLWlgjBXUvlETNN83g1wrumgdnjXkHEVfUedGI9W4YiyAtRxksV
cIYJp8D6EpYRfY4cw0FLaILp5xdFIM2xkoxAb6RHEDWFpEnMEFJjflbCazA0jLep
cxK18N+Mkv0qN70CH6A3GZ5/xzuqbIkzep2DaUsNYbzpLmc8s2tTbzBtoZnMjHsO
iqXi0ylSkN8w3SxOJXbE5bzEhAfMzoA1uPuoJTsmnmnexWg5jAG36mQ7XpYTPhzz
cQIDAQAB
-----END PUBLIC KEY-----',
  'SHA256withRSA',
  CURRENT_TIMESTAMP,
  NULL,
  'ACTIVE',
  'flyway',
  'flyway'
FROM api_clients c
WHERE c.client_id = '962489e9-de5d-4eb7-92a4-b07d44d64bf4'
ON DUPLICATE KEY UPDATE
  public_key_pem = VALUES(public_key_pem),
  algorithm = VALUES(algorithm),
  valid_from = VALUES(valid_from),
  valid_to = VALUES(valid_to),
  status = VALUES(status),
  updated_at = CURRENT_TIMESTAMP,
  updated_by = VALUES(updated_by);

INSERT INTO client_scopes
(api_client_id, scope_code, service_code, is_active, created_by, updated_by)
SELECT c.id, scope_data.scope_code, scope_data.service_code, TRUE, 'flyway', 'flyway'
FROM api_clients c
CROSS JOIN (
  SELECT 'openid' AS scope_code, '73' AS service_code
  UNION ALL
  SELECT 'snap:auth:token' AS scope_code, '73' AS service_code
) scope_data
WHERE c.client_id = '962489e9-de5d-4eb7-92a4-b07d44d64bf4'
ON DUPLICATE KEY UPDATE
  service_code = VALUES(service_code),
  is_active = VALUES(is_active),
  updated_at = CURRENT_TIMESTAMP,
  updated_by = VALUES(updated_by);
