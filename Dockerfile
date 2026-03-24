# Stage 1 — build the Zig binaries
FROM debian:bookworm-slim AS builder

ARG ZIG_VERSION=0.15.0
ARG ZIG_TARBALL=zig-linux-x86_64-${ZIG_VERSION}.tar.xz

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl xz-utils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and install Zig
RUN curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/${ZIG_TARBALL}" \
        -o /tmp/zig.tar.xz \
    && tar -xf /tmp/zig.tar.xz -C /usr/local \
    && ln -s /usr/local/zig-linux-x86_64-${ZIG_VERSION}/zig /usr/local/bin/zig \
    && rm /tmp/zig.tar.xz

WORKDIR /src
COPY . .

# Build both enclave binaries; package cache is in ~/.cache/zig
RUN --mount=type=cache,target=/root/.cache/zig \
    zig build -Doptimize=ReleaseSafe

# Stage 2 — minimal runtime image
# debian:bookworm-slim provides glibc, libstdc++, and ca-certificates.
# Swap for scratch + musl target if you need a fully static image.
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy both runtimes so the image can serve either entry point.
COPY --from=builder /src/zig-out/bin/VAR         /usr/local/bin/VAR
COPY --from=builder /src/zig-out/bin/VAR-gateway /usr/local/bin/VAR-gateway

# The gateway is the recommended entry point for new integrations.
# Override with --entrypoint /usr/local/bin/VAR for the vsock line protocol.
ENTRYPOINT ["/usr/local/bin/VAR-gateway"]
