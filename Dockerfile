# syntax=docker/dockerfile:1.7

FROM rust:1.95-slim-trixie@sha256:e14e87345b4d5964ddcc3491d27ee046a0f23820f340c3c1e24da6880141f7c0 AS builder
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked && strip target/release/code-explorer

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS gitleaks
ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) arch=x64; sum="$GITLEAKS_SHA256_AMD64" ;; \
      arm64) arch=arm64; sum="$GITLEAKS_SHA256_ARM64" ;; \
      *) echo "unsupported arch $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz"; \
    echo "${sum}  /tmp/gitleaks.tgz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    /usr/local/bin/gitleaks version

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update \
 && apt-get install -y --no-install-recommends git openssh-client ca-certificates ripgrep \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 explorer && useradd -u 10001 -g 10001 -M -d /nonexistent -s /usr/sbin/nologin explorer \
 && mkdir -p /data /etc/code-explorer && chown explorer:explorer /data
COPY --from=gitleaks /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=builder /src/target/release/code-explorer /usr/local/bin/code-explorer
COPY deploy/known_hosts /etc/code-explorer/known_hosts
ENV CODE_EXPLORER_CONFIG=/etc/code-explorer/config.toml
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["code-explorer", "healthcheck"]
ENTRYPOINT ["code-explorer"]
CMD ["serve"]
