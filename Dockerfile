# syntax=docker/dockerfile:1.7-labs
FROM cgr.dev/chainguard/wolfi-base:latest as base
ARG PROJECT_NAME=oidc-zero
RUN addgroup -S ${PROJECT_NAME} && adduser -S ${PROJECT_NAME} -G ${PROJECT_NAME}
ENTRYPOINT ["/usr/local/bin/oidc-zero"]

FROM docker.io/library/golang:1.21 AS build
ARG PROJECT_NAME=oidc-zero
COPY / /src
WORKDIR /src
RUN \
  --mount=type=cache,target=/go/pkg \
  --mount=type=cache,target=/root/.cache/go-build \
  go build -o bin/${PROJECT_NAME} main.go

FROM base AS goreleaser
ARG PROJECT_NAME=oidc-zero
COPY ${PROJECT_NAME} /usr/local/bin/${PROJECT_NAME}
USER ${PROJECT_NAME}

FROM base
ARG PROJECT_NAME=oidc-zero
COPY --from=build /src/bin/${PROJECT_NAME} /usr/local/bin/${PROJECT_NAME}
USER ${PROJECT_NAME}