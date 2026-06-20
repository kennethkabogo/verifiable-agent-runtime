#!/bin/bash
# Start the VAR enclave and block until it terminates.
# Systemd tracks this process; when the enclave dies systemd sees the exit
# and Restart=on-failure fires the next run-enclave.sh invocation.
set -euo pipefail

EIF_PATH="${EIF_PATH:-/opt/var/var.eif}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
ENCLAVE_MEMORY="${ENCLAVE_MEMORY:-512}"
ENCLAVE_CPUS="${ENCLAVE_CPUS:-2}"
ID_FILE="/run/var/enclave.id"

mkdir -p /run/var

echo "Starting enclave: CID=${ENCLAVE_CID} memory=${ENCLAVE_MEMORY}MB cpus=${ENCLAVE_CPUS}"
result=$(nitro-cli run-enclave \
    --enclave-cid "${ENCLAVE_CID}" \
    --memory       "${ENCLAVE_MEMORY}" \
    --cpu-count    "${ENCLAVE_CPUS}" \
    --eif-path     "${EIF_PATH}")

enclave_id=$(echo "${result}" | python3 -c "import sys,json; print(json.load(sys.stdin)['EnclaveID'])")
echo "Enclave running: ${enclave_id}"
echo "${enclave_id}" > "${ID_FILE}"

# Block until the enclave is no longer RUNNING so systemd's process tracking
# stays accurate and Restart= fires when the enclave crashes.
while true; do
    state=$(nitro-cli describe-enclaves 2>/dev/null | python3 -c "
import sys, json
eid = open('/run/var/enclave.id').read().strip()
for e in json.load(sys.stdin):
    if e.get('EnclaveID') == eid:
        print(e.get('State', 'UNKNOWN'))
        sys.exit(0)
print('GONE')
" 2>/dev/null || echo "GONE")
    if [ "${state}" != "RUNNING" ]; then
        echo "Enclave ${enclave_id} state=${state}, exiting monitor"
        break
    fi
    sleep 5
done

rm -f "${ID_FILE}"
