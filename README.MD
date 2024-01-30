# OAuth 2.0 - Protected Resource [Ory Hydra, Golang]

## Introduction

This project is a simple example of securing a resource using OAuth2 token validation with token introspection. It
utilizes the [Gin](https://github.com/gin-gonic/gin) web framework for building the API
and [Hydra](https://www.ory.sh/hydra/) for token introspection.

The secured resource is protected by requiring a valid OAuth2 token with a specific scope. The token is introspected
using Hydra to validate its authenticity and check for the required scope before granting access to the resource.

## Prerequisites

Before using this project, ensure that the following prerequisites are met:

1. **Go (Golang):** Make sure you have Go installed on your computer. You can download and install Go
   from [https://golang.org/dl/](https://golang.org/dl/).

2. **Docker and Docker Compose:** The project relies on Docker and Docker Compose for running Ory Hydra and its
   dependencies. If you don't have Docker installed, you can download and install it
   from [https://www.docker.com/get-started](https://www.docker.com/get-started).

3. **Ory Hydra:**
  We will use the Docker Compose configuration provided in the Ory Hydra codebase. You can get the Hydra
  source code in one of the following ways:

    - If you have Go 1.15+ installed, run:
      ```bash
      go get -d github.com/ory/hydra
      ```
    - If you have Git installed, run:
      ```bash
      git clone https://github.com/ory/hydra.git
      ```
    - Otherwise, download the Hydra source code from [https://github.com/ory/hydra](https://github.com/ory/hydra) and
      extract it to a directory.

4. Change into the directory with the Hydra source code and start the required containers using Docker Compose:

    ```bash
    docker-compose -f quickstart.yml -f quickstart-postgres.yml up --build
    ```
   This command starts the PostgreSQL database and Ory Hydra containers.

Make sure that the Docker containers are up and running before proceeding with the usage of the OAuth 2.0 protected
resource example. Adjust the `hydraAdminURL` constant in `main.go` if needed based on your Hydra setup.

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/konstantin-evo/oauth-with-hydra-protected-resource.git
   ```

2. Install dependencies:

   ```bash
   go mod tidy
   ```

3. Set up Hydra: Make sure Hydra is running and accessible at `http://localhost:4445`. Adjust the `hydraAdminURL`
   constant in `main.go` if necessary.

4. Run the application:

   ```bash
   go run main.go
   ```

   The application will start on the default port (8080) or a port specified by the `PORT` environment variable.

## Secured Resource Endpoint

- **Endpoint:** `/secured-resource`
- **Method:** `GET`
- **Headers:**
    - `Authorization`: Bearer token

## Token Introspection

The application introspects the provided OAuth2 token using Hydra. If the token is valid and has the required scope,
access to the secured resource is granted. Otherwise, appropriate error responses are returned.
