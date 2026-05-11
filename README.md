# Auth Service

Spring Boot auth-service foundation for SNAP security portfolio flows.

## Requirements

- Java 21
- Maven wrapper from this repository
- MySQL 8 compatible database

## Run Locally

Copy the example environment file and adjust local credentials as needed.

```powershell
Copy-Item .env.example .env
docker compose up -d
```

Set Java 21 and database credentials through environment variables before running the app.

PowerShell example:

```powershell
$env:JAVA_HOME="C:\Program Files\Eclipse Adoptium\jdk-21.0.9.10-hotspot"
$env:Path="$env:JAVA_HOME\bin;$env:Path"
$env:AUTH_DB_URL="jdbc:mysql://localhost:3306/auth_db?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true"
$env:AUTH_DB_USERNAME="<mysql-username-from-env-file>"
$env:AUTH_DB_PASSWORD="<mysql-password-from-env-file>"
.\mvnw.cmd spring-boot:run
```

Health check:

```powershell
Invoke-WebRequest http://localhost:3031/actuator/health -UseBasicParsing
```

## API Documentation

Swagger UI and the raw OpenAPI document are available locally:

```powershell
Start-Process http://localhost:3031/swagger-ui.html
Invoke-WebRequest http://localhost:3031/v3/api-docs -UseBasicParsing
```

The OpenAPI document includes SNAP response codes, request/response examples, internal endpoint labels, and the Actuator health check reference. Internal endpoints require `X-INTERNAL-API-KEY`. The signature generation utility is documented as `local`/`dev` only and must not be used with production private keys.

## Metrics

Prometheus metrics are exposed through Spring Boot Actuator:

```powershell
Invoke-WebRequest http://localhost:3031/actuator/prometheus -UseBasicParsing
```

Custom auth metrics use safe, non-sensitive names and do not include token, signature, client secret, request id, IP, user-agent, or client-specific labels.

```powershell
(Invoke-WebRequest http://localhost:3031/actuator/prometheus -UseBasicParsing).Content |
    Select-String "auth_token_request_success_total|auth_token_request_failure_total|auth_token_invalid_signature_total|auth_token_unauthorized_total|auth_token_request_latency_seconds"
```

## Test

```powershell
.\mvnw.cmd test
```

The test suite excludes live database auto-configuration so foundation checks can run without mutating local MySQL.

## Local Seed Data

Flyway seeds a SNAP local merchant, API client, public key, scopes, and response code mappings for Postman testing. The matching private key in the Postman environment is for local development only; the database stores only the public key.

## Development Signature Utility

`POST /cashup/v1.0/utilities/signature-auth` is available only when the Spring profile is `local` or `dev`. It signs `clientId|timestamp` with a caller-supplied local/test private key to make Postman testing easier.

Do not enable this endpoint in production and do not use production private keys with it. The Postman private key is local test material only.
