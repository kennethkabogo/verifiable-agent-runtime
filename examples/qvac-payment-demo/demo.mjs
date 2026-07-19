/**
 * demo.mjs — Full pipeline: Qvac agent → VAR enclave → attested receipt
 *
 * Step 1: Local Qvac LLM analyzes an invoice and produces a payment decision.
 * Step 2: The decision is submitted to the VAR enclave's verify function.
 * Step 3: The enclave seals the decision — hardware-attested, operator-proof.
 *
 * The receipt proves: this exact decision, produced from these exact inputs,
 * sealed by this exact enclave binary (committed to in PCR0). The operator
 * who runs the infrastructure cannot modify the decision after the agent made
 * it without the enclave returning match:false.
 *
 * Run: VAR_DEMO_URL=https://your-var-demo.com node demo.mjs
 */

import { loadModel, QWEN3_1_7B_INST_Q4, completion, unloadModel } from '@qvac/sdk'
import { createHash } from 'crypto'

const VAR_URL = process.env.VAR_DEMO_URL ?? 'http://127.0.0.1:8080'

const INVOICE = `
Invoice #1042
Contractor: BuildRight LLC
Date: 2026-07-16

Line Items:
  Labour       40 hrs @ $300/hr     $12,000
  Materials    lumber, concrete       $8,500
  Equipment    crane rental (3 days)  $2,000
  ─────────────────────────────────────────
  Total                             $22,500

Contract budget:  $25,000
Prior payments:   $0
`.trim()

const SYSTEM = `You are an autonomous payment authorization agent.
Analyze the invoice and decide whether to approve or deny payment.
Respond with ONLY valid JSON. All six fields are required. No markdown, no explanation, no other text.
Example: {"decision":"approved","amount":22500,"currency":"USD","recipient":"BuildRight LLC","invoice":"#1042","reasoning":"Invoice totals match line items and payment is within the $25,000 contract budget."}`

// ── Step 1: Agent decision ───────────────────────────────────────────────────

console.log('┌─────────────────────────────────────────────────────┐')
console.log('│  STEP 1: Qvac agent running locally                 │')
console.log('└─────────────────────────────────────────────────────┘')
console.log()

const modelId = await loadModel({
  modelSrc: QWEN3_1_7B_INST_Q4,
  onProgress: ({ percent }) => {
    if (percent !== undefined) process.stderr.write(`\r  Downloading Qwen3 1.7B: ${percent}%   `)
  },
})
process.stderr.write('\n')

const result = completion({
  modelId,
  history: [
    { role: 'system', content: SYSTEM },
    { role: 'user', content: `Authorize payment for this invoice:\n\n${INVOICE}` },
  ],
  stream: true,
})

let raw = ''
process.stdout.write('  Agent output: ')
for await (const token of result.tokenStream) {
  raw += token
  process.stdout.write(token)
}
console.log()

await unloadModel({ modelId })

const jsonMatch = raw.match(/\{[\s\S]*\}/)
if (!jsonMatch) {
  console.error('\n  ERROR: model did not produce valid JSON')
  process.exit(1)
}

const decision = JSON.parse(jsonMatch[0])
const decisionStr = JSON.stringify(decision)
const hash = createHash('sha256').update(decisionStr).digest('hex')

console.log()
console.log(`  Decision: ${decision.decision.toUpperCase()} — ${decision.currency} ${decision.amount.toLocaleString()} to ${decision.recipient}`)
console.log(`  SHA-256:  ${hash}`)

// ── Step 2: Attest via VAR ───────────────────────────────────────────────────

console.log()
console.log('┌─────────────────────────────────────────────────────┐')
console.log('│  STEP 2: Sealing decision in VAR enclave            │')
console.log('└─────────────────────────────────────────────────────┘')
console.log()
console.log(`  Endpoint: ${VAR_URL}/api/run`)

let attested
try {
  const resp = await fetch(`${VAR_URL}/api/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fn: 'verify',
      inputs: { document: decisionStr, expected_hash: hash },
    }),
  })
  attested = await resp.json()
} catch (e) {
  console.error('  ERROR: could not reach VAR:', e.message)
  process.exit(1)
}

if (!attested.ok) {
  console.error('  VAR error:', attested)
  process.exit(1)
}

const enclaveOutput = JSON.parse(attested.compute.output)
const { all_passed, ecr } = attested.verification

// ── Step 3: Receipt ──────────────────────────────────────────────────────────

console.log()
console.log('┌─────────────────────────────────────────────────────┐')
console.log('│  STEP 3: Hardware-attested receipt                  │')
console.log('└─────────────────────────────────────────────────────┘')
console.log()
console.log(`  Invoice:    ${decision.invoice}`)
console.log(`  Recipient:  ${decision.recipient}`)
console.log(`  Decision:   ${decision.decision.toUpperCase()}`)
console.log(`  Amount:     ${decision.currency} ${decision.amount.toLocaleString()}`)
console.log(`  Reasoning:  ${decision.reasoning}`)
console.log()
console.log(`  Enclave hash match: ${enclaveOutput.match ? '✓' : '✗'}`)
console.log(`  ECR: ${ecr.toFixed(4)}   All steps passed: ${all_passed}`)
console.log()
console.log(`  PCR0: ${attested.bundle.pcr0}`)
console.log(`  Seal: ${attested.bundle.seal.seal_sig.slice(0, 48)}...`)
console.log()

if (ecr === 1.0 && all_passed && enclaveOutput.match) {
  console.log('  ✓ Sealed. The operator cannot change what the agent decided.')
  console.log('  ✓ Verify independently: python3 tools/apex_verify.py <bundle>')
} else {
  console.log('  ✗ Verification failed.')
}
