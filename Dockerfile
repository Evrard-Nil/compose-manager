FROM rust:1.75-slim as builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y docker-compose-plugin ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/compose-manager /usr/local/bin/
CMD ["compose-manager"]
