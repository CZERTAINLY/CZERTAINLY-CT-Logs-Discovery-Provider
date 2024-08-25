# CZERTAINLY-CT-Logs-Discovery-Provider

> This repository is part of the open-source project CZERTAINLY. You can find more information about the project at [CZERTAINLY](https://github.com/CZERTAINLY/CZERTAINLY) repository, including the contribution guide.

CT Log discovery provider is the implementation of the following `Function Groups` and `Kinds`:

| Function Group       | Kind         |
|----------------------|--------------|
| `Discovery Provider` | `CT-SSLMate` |

CT Logs discovery provider allows you to perform the following operations:

`Discovery Provider`
- Discover certificates

## Database requirements

CT Logs discovery provider requires the PostgreSQL database version 12+.

## Docker container

CT Logs discovery provider is provided as a Docker container. Use the `docker.io/czertainly/czertainly-ct-logs-discovery-provider:tagname` to pull the required image from the repository. It can be configured using the following environment variables:

| Variable            | Description                                                                                     | Required                                           | Default value |
|---------------------|-------------------------------------------------------------------------------------------------|----------------------------------------------------|---------------|
| `SERVER_PORT`       | Port where the service is exposed                                                               | ![](https://img.shields.io/badge/-NO-red.svg)      | `8080`        |
| `DATABASE_HOST`     | Database host                                                                                   | ![](https://img.shields.io/badge/-NO-red.svg)      | `localhost`   |
| `DATABASE_PORT`     | Database port                                                                                   | ![](https://img.shields.io/badge/-NO-red.svg)      | `5432`        |
| `DATABASE_NAME`     | Database name                                                                                   | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`         |
| `DATABASE_USER`     | Database user                                                                                   | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`         |
| `DATABASE_PASSWORD` | Database password                                                                               | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`         |
| `DATABASE_SCHEMA`   | Database schema                                                                                 | ![](https://img.shields.io/badge/-NO-red.svg)      | `ctlogs`      |
| `LOG_LEVEL`         | Logging level for the service, allowed value is `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` | ![](https://img.shields.io/badge/-NO-red.svg)      | `INFO`        |
