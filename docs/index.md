# OIDC Zero

Simple OIDC Authentication Server. Intentionally missing a lot of features. Simply designed to allow for a basic
configuration to load users and authenticate them. Not designed to be a full-featured OIDC server.

Bulk of the `pkg/storage` borrowed and adapted from github.com/zitadel/oidc which is licensed under Apache 2.0.

## Features

- Provide login capability for OIDC clients.
- Simple configuration to load users and authenticate them. (yes passwords are stored in plaintext)

## Built from go-project-template

This project was built from the [go-project-template](https://github.com/ekristen/go-project-template).
Below are some of the features and decisions made in the template.

### Opinionated Decisions

- Uses `init` functions for registering commands globally.
  - This allows for multiple `main` package files to be written and include different commands.
  - Allows the command code to remain isolated from each other and a simple import to include the command.

### Multi-Platform Builds

This project is designed to build for multiple platforms, including macOS, Linux, and Windows. It also supports
multiple architectures including amd64 and arm64.

The goreleaser configuration is set up to build for all platforms and architectures by default. It even supports pushing
multi-architecture docker manifests by default. Some knowledge about GoReleaser's configuration is required should you
want to remove these capabilities.

### Apple Notary Signing

This makes use of a tool called [quill](https://github.com/anchore/quill). To make use of this feature you will need
to have an Apple Developer account and be able to create an Developer ID certificate.

The workflow is designed to pull the necessary secrets from 1Password. This is done to keep the secrets out of the
GitHub Actions logs. The secrets are pulled from 1Password if the event triggering the workflow is a tag **AND** the
actor is the owner of the repository. This is to prevent forks from being able to pull the secrets and is an extra
guard to help prevent theft.

GoReleaser is configured to always sign and notarize for macOS. However, it will not notarize if the build is a snapshot.

If configured properly, the binaries located within the archives produced by GoReleaser will be signed and notarized
by the Apple Notary Service and will automatically run on any macOS system without having to approve it under System
Preferences.

If you do not wish to use 1Password simply export the same environment variables using secrets to populate them. The
`QUILL_SIGN_P12` and `QUILL_NOTARY_KEY` need to be base64 encoded or paths to the actual files.

## Building

The following will build binaries in snapshot order.

```console
goreleaser --clean --snapshot --skip sign
```

**Note:** we are skipping signing because this project uses cosign's keyless signing with GitHub Actions OIDC provider.

You can opt to generate a cosign keypair locally and set the following environment variables, and then you can run
`goreleaser --clean --snapshot` without the `--skip sign` flag to get signed artifacts.

Environment Variables:
- 
- COSIGN_PASSWORD
- COSIGN_KEY (path to the key file) (recommend cosign.key, it is git ignored already)

```console
cosign generate-key-pair
```

### Docker

The Dockerfile is set up to build the project and then copy the artifacts from the build into the final image. It is
also configured to allow you to just run `docker build` directly if you do not want to use GoReleaser.

To make things easier and faster, the Dockerfile has a default build argument set to `go-project-template`. GoReleaser
will pass the new project name down (if you update the `.goreleaser.yml` file) and the Dockerfile will use that instead.

However, it would be better longer term to update this argument in the file or remove it all together.

### Signing

Signing happens via cosign's keyless features using the GitHub Actions OIDC provider.

## Documentation

The project is built to have the documentation right alongside the code in the `docs/` directory leveraging Mkdocs Material.

In the root of the project exists mkdocs.yml which drives the configuration for the documentation.

This README.md is currently copied to `docs/index.md` and the documentation is automatically published to the GitHub
pages location for this repository using a GitHub Action workflow. It does not use the `gh-pages` branch.

### Running Locally

```console
make docs-serve
```

OR (if you have docker)

```console
docker run --rm -it -p 8000:8000 -v ${PWD}:/docs squidfunk/mkdocs-material
```
