FROM rust:1.88-bookworm AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && printf "fn main() {}\n" > src/main.rs
RUN cargo fetch --locked
RUN cargo build --release --locked
RUN rm -rf src

COPY . .
RUN cargo clean
RUN cargo build --release --locked
RUN ls -la /app/target/release && test -f /app/target/release/auth-service

FROM debian:bookworm-slim AS runtime
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/auth-service /app/auth-service
RUN chmod +x /app/auth-service

EXPOSE 3000
ENTRYPOINT ["/app/auth-service"]

