/**
 * agent.mjs — Qvac payment authorization agent
 *
 * Runs a local LLM (Qwen3 1.7B) to analyze an invoice and produce a
 * structured payment decision. The decision JSON is written to decision.json
 * for the attestation step to pick up.
 *
 * Run: node agent.mjs
 */

import { loadModel, QWEN3_1_7B_INST_Q4, completion, unloadModel } from '@qvac/sdk'
import { createHash } from 'crypto'
import { writeFileSync } from 'fs'

// ── Invoice under review ─────────────────────────────────────────────────────

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
Remaining budget: $25,000
`.trim()

// ── System prompt ────────────────────────────────────────────────────────────

const SYSTEM = `You are an autonomous payment authorization agent.
Analyze the invoice and decide whether to approve or deny payment.
Respond with ONLY valid JSON. All six fields are required. No markdown, no explanation, no other text.
Example: {"decision":"approved","amount":22500,"currency":"USD","recipient":"BuildRight LLC","invoice":"#1042","reasoning":"Invoice totals match line items and payment is within the $25,000 contract budget."}`

// ── Run inference ────────────────────────────────────────────────────────────

console.error('[agent] Loading Qwen3 1.7B locally via Qvac...')

const modelId = await loadModel({
  modelSrc: QWEN3_1_7B_INST_Q4,
  onProgress: ({ percent }) => {
    if (percent !== undefined) process.stderr.write(`\r[agent] Download: ${percent}%   `)
  },
})

console.error('\n[agent] Model loaded. Running inference...')

const result = completion({
  modelId,
  history: [
    { role: 'system', content: SYSTEM },
    { role: 'user', content: `Authorize payment for this invoice:\n\n${INVOICE}` },
  ],
  stream: true,
})

let raw = ''
for await (const token of result.tokenStream) {
  raw += token
  process.stderr.write(token)
}

await unloadModel({ modelId })
console.error('\n[agent] Inference complete.')

// ── Parse decision ───────────────────────────────────────────────────────────

// Extract JSON from output — model may wrap it in markdown fences
const jsonMatch = raw.match(/\{[\s\S]*\}/)
if (!jsonMatch) {
  console.error('[agent] ERROR: model did not produce valid JSON')
  console.error('[agent] Raw output:', raw)
  process.exit(1)
}

let decision
try {
  decision = JSON.parse(jsonMatch[0])
} catch (e) {
  console.error('[agent] ERROR: failed to parse JSON:', e.message)
  console.error('[agent] Raw match:', jsonMatch[0])
  process.exit(1)
}

// Canonical form — deterministic serialization for hashing
const decisionStr = JSON.stringify(decision)
const hash = createHash('sha256').update(decisionStr).digest('hex')

const payload = { decision, decisionStr, hash }
writeFileSync('decision.json', JSON.stringify(payload, null, 2))

console.log('\n[agent] Decision:')
console.log(JSON.stringify(decision, null, 2))
console.log(`\n[agent] SHA-256: ${hash}`)
console.log('[agent] Written to decision.json')
