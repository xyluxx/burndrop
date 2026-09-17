# syntax=docker/dockerfile:1.7
#
# Builds the relay with the drop page embedded. Three stages: the page from
# web/ (Node), the static Go binary, and a distroless runtime that contains
# nothing but that binary and runs as a non-root user. The relay writes no
# files, so the container can run with a read-only root filesystem.
#
#   docker build -t burndrop-relay --build-arg VERSION=v0.1.0 .

ARG VERSION=dev

FROM node:24.12.0-alpine3.23 AS page
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
ARG VERSION
RUN node build.mjs --version "$VERSION"

FROM golang:1.27-alpine3.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=page /src/web/dist/ ./web/dist/
ARG VERSION
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/burndrop-relay ./cmd/burndrop-relay

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/burndrop-relay /burndrop-relay
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/burndrop-relay", "healthcheck"]
ENTRYPOINT ["/burndrop-relay"]
CMD ["serve"]
