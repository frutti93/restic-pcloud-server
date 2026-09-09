# restic-pcloud-server container image.
#
# Two stages:
#   1. Compile the Go binary from source (stdlib only, no external modules).
#   2. Minimal runtime: our binary + a pinned, statically-linked rclone + CA certs.
#
# rclone is bundled here rather than bind-mounted from the host on purpose: a host's own
# system rclone package is often dynamically linked, which would need its shared libraries
# present inside whatever base image this container uses - fragile and version-dependent.
# Bundling a pinned static build avoids that entirely and guarantees the exact rclone
# version this project was tested against.

FROM docker.io/library/golang:1.23-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=${VERSION}" -o /out/restic-pcloud-server main.go

FROM docker.io/library/alpine:3.20
ARG RCLONE_VERSION=1.75.0
RUN apk add --no-cache ca-certificates curl unzip \
	&& curl -fsSL "https://downloads.rclone.org/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-linux-amd64.zip" -o /tmp/rclone.zip \
	&& unzip -j /tmp/rclone.zip "*/rclone" -d /usr/local/bin \
	&& chmod +x /usr/local/bin/rclone \
	&& rm -rf /tmp/rclone.zip \
	&& apk del curl unzip

COPY --from=build /out/restic-pcloud-server /usr/local/bin/restic-pcloud-server

ENTRYPOINT ["/usr/local/bin/restic-pcloud-server"]
