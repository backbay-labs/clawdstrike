# Registry Architecture

The registry is an Axum service with SQLite metadata, blob storage, sparse index output, and transparency tracking.

## Core Components

- Metadata DB: package/version rows, orgs, trusted publishers
- Blob store: content-addressed `.cpkg` archives
- Sparse index endpoint: `GET /api/v1/index/{name}` with ETag revalidation
- Transparency endpoints: attestation/proof/checkpoint/consistency

## Key API Endpoints

- `POST /api/v1/packages` publish
- `GET /api/v1/packages/{name}/{version}/download`
- `GET /api/v1/packages/{name}/{version}/attestation`
- `GET /api/v1/packages/{name}/{version}/proof`
- `GET /api/v1/search`
- `GET /api/v1/packages/{name}/stats`

## Authenticated Surfaces

- publish/yank
- org membership mutation
- trusted publisher mutation
