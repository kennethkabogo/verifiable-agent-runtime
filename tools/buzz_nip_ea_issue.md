## Problem: NIP-OA proves authorship, not execution integrity

NIP-OA is a clean, honestly-scoped credential: an owner key authorizes an agent key to publish under its own authorship, subject to `conditions`. The spec is explicit about what this does and doesn't establish:

> "This NIP reuses NIP-26 as prior art for the credential format and signing flow and defines the credential as **authorization evidence only**."

That framing is correct, and the Security Properties section names the failure mode plainly rather than hand-waving it:

> "Compromise of the agent secret key MUST NOT imply compromise of the owner secret key. Compromise of the agent secret key permits only signatures by the compromised agent key... Owners MAY revoke future authorization by refusing to issue new `auth` tags."

Two consequences follow directly from that text, both already acknowledged in the spec rather than things I'm pointing out for the first time:

1. **Compromise is bounded, not prevented.** A compromised agent process holding a still-valid, unexpired `auth` tag can sign an unbounded number of "legitimately provenanced" events until the tag's `conditions` window lapses. Revocation is forward-only — refusing to issue new tags does nothing about one already issued.
2. **Wall-clock expiry doesn't actually hold.** `created_at<...` / `created_at>...` constrain the event's self-declared `created_at`, which the agent itself controls:

   > "These clauses do not enforce wall-clock expiry; a misbehaving agent can backdate `event.created_at` to satisfy an expired window... Relays or clients that require wall-clock freshness MUST enforce it independently of this NIP."

NIP-OA isn't broken — it does exactly what it claims, and says so. The gap is one layer down: nothing in the credential proves that the *thing holding the agent key* is the software it claims to be, as opposed to whatever a host compromise, a poisoned dependency, or a stolen key has substituted in its place.

## Proposed solution: a companion NIP binding the agent key to hardware attestation

The missing layer is a standard one — TEE-backed key custody, where a secret key can only ever be exercised inside an enclave whose measured code hash matches an expected value. This is implemented and tested today in [APEX](https://github.com/kennethkabogo/verifiable-agent-runtime/blob/main/spec/APEX.md) (a runtime-agnostic evidence-bundle spec; reference implementation is VAR, running on AWS Nitro Enclaves). Two properties from that spec map onto exactly the gaps above:

- **Session-identity binding** — `BootstrapNonce = SHA-256(AttestationDoc ‖ SessionID ‖ AllowedFunctionsHash)`, verified against the enclave's TEE-vendor-signed attestation at session start. A verifier that reconstructs this rejects any attempt to graft an old attestation onto a new session.
- **Wall-clock freshness** — Step 3.6 of the same spec asserts `AttestationDoc.timestamp` (an AWS-signed field inside the attestation document, unforgeable without an AWS signing key) against the bundle's own `CreatedAt`, within a permitted skew. This is the exact enforcement NIP-OA's own text says must happen "independently of this NIP" — and it holds regardless of what the agent process itself claims about its `created_at`, because the timestamp comes from hardware, not from the signer.

A companion NIP (call it **NIP-EA**, Enclave Attestation) would let an event optionally carry a reference to an attestation bundle, in the same additive, non-breaking spirit as NIP-OA:

```
["attest", "<bundle-hash>", "<pcr0>", "<attestation-endpoint>"]
```

`<bundle-hash>` is the APEX BundleHash (SHA-256 over the sealed bundle), already computed and signed as part of the Bundle Seal. A verifier fetches the bundle from `<attestation-endpoint>` (or any mirror), hashes the bytes, and checks the hash against the value committed on the Nostr event — so the endpoint is a transport, not a trust anchor. A verifier that controls its own fetch (IPFS, a local cache, a different CDN) can verify without trusting the endpoint at all.

- Verifiers that care about execution integrity fetch and verify the bundle independently.
- Verifiers that don't care ignore the tag, exactly as NIP-OA is already optional at the relay layer.
- Non-goals mirror NIP-OA's: no impersonation semantics, no relay-side rewriting, no requirement that relays understand or validate the tag.

## Why an issue first

Per `CONTRIBUTING.md`, this is more than a small fix, so I'm not opening a `docs/nips/NIP-EA.md` PR yet. I'd rather describe the gap and the proposed shape first and get a maintainer's read on whether this fits the NIP-OA lineage the way I think it does, and whether `attest`/`bundle-id`/`pcr0` is the right tag shape or something else better matches how you're already thinking about agent trust. Happy to write the full spec (Motivation, Non-Goals, Security Properties, test vectors, in NIP-OA's own format) once the approach is acknowledged.
