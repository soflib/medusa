# ─── Build ───────────────────────────────────────────────────────────────────
FROM rust:1.95-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV SQLX_OFFLINE=true

# Layer 1: dependency cache — only invalidates when Cargo.toml/Cargo.lock change
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto/ proto/
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release --locked \
    && rm src/main.rs

# Layer 2: application source
# Prerequisite: run `cargo sqlx prepare` to generate .sqlx/ before building this image
COPY .sqlx/ .sqlx/
COPY src/ src/
RUN touch src/main.rs \
    && cargo build --release --locked

# ─── Runtime ─────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home --shell /sbin/nologin appuser

WORKDIR /app
# certs/ is mount-injected at runtime for mTLS (ca.crt, server.crt, server.key)
RUN mkdir -p logs certs && chown -R appuser:appuser /app

COPY --from=builder --chown=appuser:appuser /app/target/release/security-core ./

USER appuser

EXPOSE 50051

ENTRYPOINT ["./security-core"]
