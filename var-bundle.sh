#!/usr/bin/env bash
# var-bundle.sh — assemble and verify an APEX evidence bundle from a running VAR gateway.
#
# Usage:
#   ./var-bundle.sh [output-file]
#
# Environment:
#   VAR_GATEWAY   gateway base URL   (default: http://127.0.0.1:8765)
#   VAR_TOKEN     API token          (default: dev-local)
#   VAR_API_TOKEN fallback if VAR_TOKEN is unset
#
# Output file defaults to bundle-<timestamp>.log

set -euo pipefail

GATEWAY="${VAR_GATEWAY:-http://127.0.0.1:8765}"
TOKEN="${VAR_TOKEN:-${VAR_API_TOKEN:-dev-local}}"
OUT="${1:-bundle-$(date +%s).log}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFIER="$SCRIPT_DIR/tools/apex_verify.py"

H=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")

require_cmd() { command -v "$1" &>/dev/null || { echo "ERROR: $1 not found"; exit 1; }; }
require_cmd curl
require_cmd jq

echo "Assembling APEX bundle → $OUT"

# Step 1 — bundle header (session identity + bootstrap nonce)
printf '  [1/4] session header...'
curl -sf "${H[@]}" "$GATEWAY/session" | jq -r '.bundle_header' > "$OUT"
echo " done"

# Step 2 — snapshot current evidence (commits all pending log/compute data)
printf '  [2/4] evidence snapshot...'
MAX_SEQ=$(curl -sf "${H[@]}" "$GATEWAY/evidence" | jq -r '.sequence')
echo " seq=$MAX_SEQ"

# Step 3 — fetch all evidence packets
printf '  [3/4] packets 1–%s...' "$MAX_SEQ"
curl -sf "${H[@]}" "$GATEWAY/evidence?from=1&to=$MAX_SEQ" \
  | jq -r '.packets[] |
      "EVIDENCE:prev_stream=\(.prev_stream):stream=\(.stream):state=\(.state):sig=\(.sig):seq=\(.sequence)"' \
  >> "$OUT"
echo " done"

# Step 4 — seal
printf '  [4/4] sealing...'
curl -sf "${H[@]}" "$GATEWAY/seal" | jq -r '.bundle_seal' >> "$OUT"
echo " done"

echo ""
echo "Bundle written to $OUT"
echo ""

# Verify if apex_verify.py is present
if [ -f "$VERIFIER" ]; then
    python3 "$VERIFIER" "$OUT"
else
    echo "(verifier not found — run: python3 tools/apex_verify.py $OUT)"
fi
