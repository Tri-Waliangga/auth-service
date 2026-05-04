# Auth Service

Spring Boot auth-service foundation for SNAP security portfolio flows.

## Requirements

- Java 21
- Maven wrapper from this repository
- MySQL 8 compatible database

## Run Locally

Set Java 21 and database credentials through environment variables before running the app.

PowerShell example:

```powershell
$env:JAVA_HOME="C:\Program Files\Eclipse Adoptium\jdk-21.0.9.10-hotspot"
$env:Path="$env:JAVA_HOME\bin;$env:Path"
$env:AUTH_DB_URL="jdbc:mysql://localhost:3306/auth_db?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
$env:AUTH_DB_USERNAME="<mysql-username>"
$env:AUTH_DB_PASSWORD="<mysql-password>"
.\mvnw.cmd spring-boot:run
```

Health check:

```powershell
Invoke-WebRequest http://localhost:8080/actuator/health -UseBasicParsing
```

## Test

```powershell
.\mvnw.cmd test
```

The test suite excludes live database auto-configuration so foundation checks can run without mutating local MySQL.
