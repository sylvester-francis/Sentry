# Sentry Dagger Module

## Project Overview

This project is intended to be a Dagger module named "Sentry" for auditing container security. The goal of Sentry is to provide a comprehensive security audit for containers, filling a gap in the Daggerverse for compliance-ready reporting.

### Core Features

*   **Security Checks:** Perform checks for common security best practices, such as running as a non-root user, detecting secrets in environment variables, and verifying health checks.
*   **Trivy Integration:** Integrate with the Trivy vulnerability scanner to include vulnerability reports in the audit.
*   **Compliance Reports:** Generate compliance reports in both Markdown and JSON formats.
*   **CI/CD Integration:** Provide pass/fail exit codes for easy integration into CI/CD pipelines.

## Building and Running

This project is not yet implemented. The following commands are based on the `daggeraudit-build-guide.md` and are the intended commands to be used once the project is developed.

### Initialization

To initialize the project, you would run:

```sh
dagger init --sdk=go --name=Sentry
```

### Development

To generate the necessary Dagger types and see the available functions:

```sh
dagger develop
dagger functions
```

### Running the Audit

To run the audit on a container:

```sh
dagger call scan --container=<container-image> report
```

To get the report in JSON format:

```sh
dagger call scan --container=<container-image> json
```

To get a simple pass/fail status:

```sh
dagger call scan --container=<container-image> passed
```

## Development Conventions

The development of this project should follow the conventions outlined in the `daggeraudit-build-guide.md`.

*   **Language:** Go
*   **Framework:** Dagger
*   **Testing:** Unit tests should be written for the core logic and have a coverage of at least 70%.
*   **Project Structure:** The project should follow the standard Dagger module structure.
```
Sentry/
├── dagger.json
├── main.go
├── main_test.go
├── go.mod
├── go.sum
└── README.md
```
