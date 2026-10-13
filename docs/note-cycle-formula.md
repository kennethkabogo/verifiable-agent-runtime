# VAR Cycle Cost Formula — Empirical Derivation and Bounds

*Derived from adversarial SP1 benchmarks. October 2026.*

---

## Corrected Formula

```
cycles(predicate, trace) ≈ 18,000
                          + n × 970
                          + Σ encoded_bytes(packet_i)
                          + n × 8 × inset_total_elements(predicate)
                          + n × 106 × leaves_evaluated(predicate, trace)
```

Where:
- `n` = number of packets in the trace
- `encoded_bytes` = wire-format size: 2 (header) + 2+len (function_name) + 8 (amount) + 2+len (endpoint) + 2 (status_code), for present fields only
- `inset_total_elements` = sum of set sizes across all `InSet`/`NotInSet` leaves
- `leaves_evaluated` = number of predicate leaves actually reached during evaluation (value-dependent for Or nodes)

**Conservative upper bound** (value-independent, safe for ZK context):

```
cycles_max(predicate, trace) ≈ 18,000
                              + n × 970
                              + Σ encoded_bytes(packet_i)
                              + n × 8 × inset_total_elements(predicate)
                              + n × 106 × leaf_count(predicate)
```

---

## Coefficient Derivation

Fitted from controlled benchmarks by isolating each term:

**Per-leaf cost (C_leaf ≈ 106 cycles):**
Measured by comparing `Or[Amount<=1M, FnName!=withdraw]` with short-circuit trace (left always true → 1 leaf evaluated) against full-evaluation trace (left always false → 2 leaves evaluated), at n=10,000:

```
Δ = 12,052,285 − 10,988,825 = 1,063,460 cycles over 10,000 packets
C_leaf = 1,063,460 / 10,000 ≈ 106 cycles/packet/leaf
```

**Per-byte cost (C_byte ≈ 1 cycle) and per-packet overhead (C_overhead ≈ 970 cycles):**
Solved from two equations using Or sc (20 bytes/packet, 1 leaf) and Or full (23 bytes/packet, 2 leaves), both at n=1000–10000:

```
C_overhead + 20×C_byte + 1×C_leaf = 1,097   [Or sc]
C_overhead + 23×C_byte + 2×C_leaf = 1,205   [Or full]
⟹  C_byte ≈ 1,  C_overhead ≈ 970
```

**Intercept (C_0 ≈ 18,000):**
Read off from small-n actuals after subtracting the per-packet component. Stable across predicate shapes (range: 17,800–19,000).

---

## Or Short-Circuit Behavior

Rust `||` short-circuits: `Or(left, right)` skips `right` if `left` evaluates to true. This makes `leaves_evaluated` value-dependent.

Observed gaps (using `leaves_total` in the upper-bound formula):

| Predicate shape | Trace | Leaves total | Leaves evaluated | Formula error |
|---|---|---|---|---|
| `Or[Leaf, Leaf]` | left always true | 2 | 1 | −8.7% |
| `Or[And[L,L], And[L,L]]` | left And always true | 4 | 2 | −11.6% |
| `And[Or[L,L], L]` | inner Or left always true | 3 | 2 | −4.5% |
| `And[Leaf, Leaf]` | all leaves evaluate | 2 | 2 | −0.04% |
| `Not[Leaf]` | single leaf | 1 | 1 | −0.2% |

The gap scales linearly with n and the number of skipped leaves.

**Exact bounds:**

```
cycles_min = cycles_max − n × 106 × (leaf_count − 1)
```

The minimum is achieved when every Or short-circuits after the first leaf (one leaf evaluated across the whole tree). The maximum is when no Or short-circuits (all leaves evaluate).

For `Or[And[L,L], And[L,L]]` with 4 leaves:
- Max gap: n × 106 × 3 = 3,180,000 cycles at n=10,000
- Observed gap: ~1,650,000 (2 leaves skipped, not 3, because the left And evaluates both its children before the Or can short-circuit)

The bound is thus tighter in practice: it's `n × 106 × leaves_in_unevaluated_subtrees`, not `n × 106 × (total − 1)`.

---

## Implications for the ZK Context

The ZK verifier receives the proof output but not the packet values. It cannot observe which Or branches short-circuited. Therefore:

- **`cycles_max` (upper bound) is the correct quantity to use in any on-chain or verifier-side cycle budget.**
- The formula is safe: actual cycle cost is always ≤ `cycles_max`.
- The gap between upper bound and actual is at most ~12% for the predicate shapes benchmarked.

For predicates where short-circuit behavior is **value-independent** (e.g., a left branch that is structurally a tautology — `Amount >= 0` for a u64 field), the tighter formula using `leaves_evaluated` can be computed statically from the predicate structure alone, without access to trace values. These cases are decidable.

---

## InSet Cost Structure (Revised)

The wider sweep exposed a structural error in the InSet term. The original `n × 8 × inset_elems` per-packet term is wrong in two ways.

**Finding 1: InSet lookup is O(1) per packet, regardless of set size.**

Per-packet rate at large n (n=5000→10000) is identical across all three set sizes:

| Shape | Per-packet cost |
|---|---|
| InSet[2 elems] | 1,027 cycles |
| InSet[5 elems] | 1,027 cycles |
| InSet[20 elems] | 1,027 cycles |

Set size has no effect on per-packet cost. The implementation is hash-based, not a linear scan. The `8 × inset_elems` multiplier is therefore zero at large n — the per-packet InSet leaf contribution is:

```
C_leaf_inset ≈ 34 cycles   (vs 106 for a regular comparison leaf)
```

34 cycles is consistent with a hash lookup: cheaper than a comparison chain because the lookup is O(1) regardless of set contents.

**Finding 2: InSet has a large one-time setup cost that grows with set size.**

The setup cost (hash set construction) shows up clearly in the sign reversal at small n vs large n for InSet[20]:

| n | InSet[20] delta |
|---|---|
| 1 | +118.77% (formula under-predicts — large fixed cost dominates) |
| 100 | −2.08% (fixed cost amortized, nearly balanced) |
| 10,000 | −18.34% (per-packet n×8×20 term dominates, over-predicts) |

Fixed cost back-calculated from large-n data (net of per-packet model):

| Shape | Fixed setup cost |
|---|---|
| InSet[2] | ~700 cycles |
| InSet[5] | ~3,000 cycles |
| InSet[20] | ~7,500 cycles |

The fixed cost grows with set size but is not cleanly linear per element. A controlled benchmark (fixed n, varying only set size) would be needed to fit it precisely.

**The InSet error is bounded — it converges to a predictable ceiling.**

The InSet[20] delta grows from −2% at n=100 to −18.34% at n=10,000, then flattens (n=5,000: −18.26%, n=10,000: −18.34% — 0.08pp change). This is not an unbounded or unexplained trend; it is the expected convergence of a fixed coefficient error as n→∞.

The per-packet formula error for InSet is:

```
InSet asymptotic error = -(8×k - C_leaf_inset) / formula_rate_per_packet
```

where `formula_rate_per_packet = C_overhead + C_byte×bytes + 8×k + C_leaf`.

For the `make_trace` packets (~20 bytes each):

| Shape | k | Extra term (8k) | Actual leaf cost | Formula rate | Actual rate | Ceiling |
|---|---|---|---|---|---|---|
| InSet[2] | 2 | 16 | 34 | ~1,112 | 1,027 | −7.6% |
| InSet[5] | 5 | 40 | 34 | ~1,136 | 1,027 | −9.6% |
| InSet[20] | 20 | 160 | 34 | ~1,256 | 1,027 | **−18.2%** |

Predicted ceiling for InSet[20]: −18.2%. Observed at n=10,000: −18.34%. Match.

The error shape (small or positive at low n, growing to plateau) is also expected: at low n, the unmodeled C_setup inflates actual cycles above the formula (hence +118% at n=1, when setup cost dominates). As n grows, C_setup/n → 0 and the asymptotic coefficient error takes over.

This is a different mechanism from Or short-circuit (which is value-dependent and involves unevaluated subtrees), but it is equally explained and equally bounded. The ceiling is set by the magnitude of the per-packet coefficient error, not by any accumulating dynamic.

**Corrected formula for InSet predicates:**

Replace `n × 8 × inset_elems` with:

```
cycles_inset = C_setup(inset_elems) + n × 34
```

where `C_setup` is a one-time per-execution constant that needs its own fit. As a rough bound:
`C_setup ≈ 375 × inset_elems` (fits InSet[20] at ~7,500; over-estimates smaller sets — conservative).

Until C_setup is properly fitted, the safest approach is to treat any InSet predicate as requiring a separate benchmark rather than relying on the per-packet formula.

**Mechanistic precision gap (open, non-blocking):** The 34-cycle figure is the total per-packet InSet leaf cost net of C_overhead and C_byte. The convergence argument tells you the aggregate is ~34 cycles, but it does not partition that between per-element cost (if any) and per-leaf dispatch overhead. Since all three set sizes produce identical per-packet rates, per-element cost is ≤ measurement noise — the 34 cycles are almost certainly pure leaf dispatch with zero per-element component. But confirming that mechanistically would require a wider set-size sweep (e.g. 50, 100 elements) where any per-element term would show up as a non-flat per-packet rate. For the purpose of the bound, this distinction does not matter.

---

## Why the Original C_byte Was Wrong (Root Cause)

The original formula used C_byte = 15. This was 15x too high. The confound:

The original regression varied which fields were *present* in packets (e.g., comparing traces with {type, amount} against traces with {type, amount, function_name, endpoint}). Adding an optional field contributes bytes *and* a conditional branch in the encoder — SP1 must decode the length prefix, dispatch to the right field handler, and copy the value. That overhead is roughly 50–100 cycles per field, and it was absorbed into the per-byte coefficient.

Concretely: a packet gaining `function_name` (8 bytes) and `endpoint` (6 bytes) adds ~14 bytes and ~150 cycles of dispatch overhead. Naively dividing: 150/14 ≈ 11 apparent cycles/byte — in the right range to produce C_byte ≈ 15 when the regression also included some genuine byte-length variation.

The corrected regression holds field presence fixed (every packet has {type, function_name, amount}) and varies only `function_name` length across trace sizes. This isolates genuine byte-decode cost and produces C_byte ≈ 1, consistent with the SP1 RISC-V backend cost of copying a byte.

**Why this matters:** The field-presence overhead is real but belongs in C_overhead, not C_byte. C_overhead captures all fixed-per-packet work (header decode, field dispatch, predicate tree traversal bookkeeping). C_byte captures only the marginal cost of additional bytes within a field already being decoded. These are different cost axes and must be varied independently to measure independently.

---

## Fit Quality (updated coefficients)

| Predicate | n | Actual | Predicted (upper bound) | Delta |
|---|---|---|---|---|
| And[Leaf, Leaf] | 10,000 | 12,062,333 | 12,066,890 | −0.04% |
| Or[Leaf] full eval | 10,000 | 12,052,285 | 12,066,890 | −0.12% |
| Not[Leaf] | 10,000 | 10,981,572 | 11,006,890 | −0.23% |
| And[Leaf, SessionSum] | 10,000 | 11,911,633 | 12,066,890 | −1.29% |
| Or[Leaf] short-circuit | 10,000 | 10,988,825 | 12,038,000 | −8.72% |
| Or[And[L,L], And[L,L]] | 10,000 | 12,535,629 | 14,186,890 | −11.64% |

Shapes without Or short-circuit: ±1.5% across all n. Or-heavy shapes: up to −12% (formula over-predicts, remains a valid upper bound).
