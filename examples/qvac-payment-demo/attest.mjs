/**
 * attest.mjs — VAR attestation step
 *
 * Reads the agent's decision from decision.json, submits it to the VAR
 * enclave's verify function, and prints the hardware-attested receipt.
 *
 * The enclave computes SHA-256(decision) and compares it to the expected hash.
 * If they match, the result is sealed into the APEX evidence chain — signed
 * by the enclave's KMS-gated Ed25519 key. The operator cannot forge this.
 *
 * Run: node attest.mjs
 * Env: VAR_DEMO_URL (default: http://127.0.0.1:8080)
 */

import { readFileSync } from 'fs'

const VAR_URL = process.env.VAR_DEMO_URL ?? 'http://127.0.0.1:8080'

// ── Load agent decision ──────────────────────────────────────────────────────

let payload
try {
  payload = JSON.parse(readFileSync('decision.json', 'utf8'))
} catch (e) {
  console.error('[attest] Run agent.mjs first to produce decision.json')
  process.exit(1)
}

const { decision, decisionStr, hash } = payload

console.log('[attest] Submitting decision to VAR enclave...')
console.log(`[attest] Endpoint: ${VAR_URL}/api/run`)
console.log(`[attest] Decision: ${decisionStr}`)
console.log(`[attest] Expected hash: ${hash}`)

// ── Submit to VAR ────────────────────────────────────────────────────────────

let result
try {
  const resp = await fetch(`${VAR_URL}/api/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fn: 'verify',
      inputs: {
        document: decisionStr,
        expected_hash: hash,
      },
    }),
  })
  result = await resp.json()
} catch (e) {
  console.error('[attest] ERROR: could not reach VAR demo server:', e.message)
  console.error('[attest] Is the enclave running? Check: curl', `${VAR_URL}/api/health`)
  process.exit(1)
}

if (!result.ok) {
  console.error('[attest] VAR returned error:', result)
  process.exit(1)
}

// ── Print sealed receipt ─────────────────────────────────────────────────────

const enclaveOutput = JSON.parse(result.compute.output)
const { all_passed, ecr, steps } = result.verification
const failedSteps = steps.filter(s => s.status === 'FAIL')

console.log('\n═══════════════════════════════════════════════════════')
console.log('  VAR ATTESTED PAYMENT RECEIPT')
console.log('═══════════════════════════════════════════════════════')
console.log(`  Invoice:     ${decision.invoice}`)
console.log(`  Recipient:   ${decision.recipient}`)
console.log(`  Decision:    ${decision.decision.toUpperCase()}`)
console.log(`  Amount:      ${decision.currency} ${decision.amount.toLocaleString()}`)
console.log(`  Reasoning:   ${decision.reasoning}`)
console.log('───────────────────────────────────────────────────────')
console.log(`  Enclave match:  ${enclaveOutput.match ? '✓ hash verified' : '✗ hash mismatch'}`)
console.log(`  Computed hash:  ${enclaveOutput.computed_hash}`)
console.log(`  ECR:            ${ecr.toFixed(4)}  ${ecr === 1.0 ? '(all steps passed)' : ''}`)
console.log(`  All passed:     ${all_passed}`)
if (failedSteps.length) {
  console.log(`  Failed steps:   ${failedSteps.map(s => s.step).join(', ')}`)
}
console.log('───────────────────────────────────────────────────────')
console.log(`  PCR0: ${result.bundle.pcr0}`)
console.log(`  PCR2: ${result.bundle.pcr2}`)
console.log('───────────────────────────────────────────────────────')
console.log('  Seal:')
console.log(`    bundle_hash:     ${result.bundle.seal.bundle_hash}`)
console.log(`    seal_sig:        ${result.bundle.seal.seal_sig.slice(0, 32)}...`)
console.log('═══════════════════════════════════════════════════════')
console.log()

if (ecr === 1.0 && all_passed && enclaveOutput.match) {
  console.log('  ✓ This payment decision was sealed by a Nitro enclave.')
  console.log('  ✓ The operator cannot modify it — the signature requires')
  console.log('    the exact EIF binary that produced these PCR values.')
  console.log('  ✓ Run apex_verify.py against the bundle to verify independently.')
} else {
  console.log('  ✗ Verification incomplete — check failed steps above.')
}
