# Build stage
FROM rust:1-bookworm AS builder

WORKDIR /app

# Copy manifests and lockfile first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Copy source and migrations
COPY src ./src
COPY migrations ./migrations

# Build release binaries (app + seed)
RUN cargo build --release && cargo build --release --bin seed

# Runtime stage
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /app/target/release/authrs /app/authrs
COPY --from=builder /app/target/release/seed /app/seed

# Copy migrations (run at startup by the app)
COPY --from=builder /app/migrations /app/migrations

# Non-root user
RUN useradd -r -u 1000 authrs
USER authrs

EXPOSE 3000

ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=3000

ENTRYPOINT ["/app/authrs"]
