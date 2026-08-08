# Official ghidra-cli image (headless RE CLI + MCP).
# Ghidra is large; this image installs the CLI and expects Ghidra via volume
# or a follow-on setup step (`ghidra setup` inside the container).

FROM rust:1.88-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
# Build release binary only
RUN cargo build --release --bin ghidra

FROM debian:bookworm-slim
# Bookworm ships OpenJDK 17 as the default full JDK; Ghidra 11+/12 work with it.
# For newer JDKs, use a custom base or install Temurin after first boot.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates default-jdk-headless curl unzip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/ghidra /usr/local/bin/ghidra

# Project + config defaults (Ghidra 12.1 rejects dot-prefix path components)
ENV GHIDRA_CLI_PROJECTS_DIR=/data/projects
ENV XDG_CONFIG_HOME=/data/config
ENV XDG_DATA_HOME=/data/share
RUN mkdir -p /data/projects /data/config /data/share

WORKDIR /work
VOLUME ["/data", "/work"]

# MCP HTTP default (override with docker run args)
EXPOSE 8080
ENTRYPOINT ["ghidra"]
CMD ["--help"]

# Examples:
#   docker build -t ghidra-cli .
#   docker run --rm -v "$PWD:/work" ghidra-cli doctor
#   docker run --rm -p 127.0.0.1:8080:8080 ghidra-cli mcp http --listen 0.0.0.0:8080
# Note: HTTP transport rejects non-loopback peers unless you adjust policy;
# for container use prefer stdio or host-network with 127.0.0.1.
