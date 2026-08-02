# Stage 1 — build the Zig binaries
FROM debian:bookworm-slim AS builder

ARG ZIG_VERSION=0.15.2
# TARGETARCH is injected by Docker buildx (amd64 | arm64).
# Zig uses x86_64 / aarch64 — map between the two.
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl xz-utils ca-certificates libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Download and install the Zig toolchain for the target architecture.
RUN case "$TARGETARCH" in \
      amd64) ZIG_ARCH=x86_64 ;; \
      arm64) ZIG_ARCH=aarch64 ;; \
      *)     echo "unsupported TARGETARCH: $TARGETARCH" && exit 1 ;; \
    esac \
    && curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz" \
         -o /tmp/zig.tar.xz \
    && tar -xf /tmp/zig.tar.xz -C /usr/local \
    && ln -s /usr/local/zig-${ZIG_ARCH}-linux-${ZIG_VERSION}/zig /usr/local/bin/zig \
    && rm /tmp/zig.tar.xz

WORKDIR /src
COPY . .

# Build both enclave binaries
RUN zig build -Doptimize=ReleaseSafe

# Stage 2 — minimal runtime image
# debian:bookworm-slim provides glibc, libstdc++, and ca-certificates.
# Swap for scratch + musl target if you need a fully static image.
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy both runtimes so the image can serve either entry point.
COPY --from=builder /src/zig-out/bin/VAR         /usr/local/bin/VAR
COPY --from=builder /src/zig-out/bin/VAR-gateway /usr/local/bin/VAR-gateway

# The gateway is the recommended entry point for new integrations.
# Override with --entrypoint /usr/local/bin/VAR for the vsock line protocol.
ENTRYPOINT ["/usr/local/bin/VAR-gateway"]
