# Lean 4 + Yukon CLI research agent, instrumented with VAR attestation.
#
# Build:  docker build -t var-lean-agent .
# Run:    see docker-compose.yml

FROM leanprover/lean4:stable

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-pip curl jq ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Yukon CLI — install once the package is publicly released.
# Uncomment the appropriate line when available:
#   pip3 install yukon-cli
#   curl -fsSL https://get.yukon.codes/install.sh | sh
# For now the agent stubs the submission call so the VAR instrumentation
# can be developed and tested without the live CLI.
RUN pip3 install --no-cache-dir requests 2>/dev/null || true

WORKDIR /workspace

COPY lean_agent.py /workspace/lean_agent.py

ENV VAR_GATEWAY=http://var-gateway:8765
ENV VAR_API_TOKEN=dev-local
ENV YUKON_STUB=1

CMD ["python3", "/workspace/lean_agent.py"]
