FROM rust:1.88-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY core ./core
RUN cargo build --release -p crabouncer-core

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /build/target/release/crabouncer-core /usr/local/bin/crabouncer-core
COPY core/migrations ./core/migrations
COPY config/docker.toml ./config/docker.toml
ENV CRABOUNCER_CONFIG=/app/config/docker.toml
EXPOSE 3000
CMD ["crabouncer-core"]
