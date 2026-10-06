# Age Credential Format Decision

Status: Accepted for interface design; cryptographic implementation blocked

Demo status: orchestration is implemented with a non-production HMAC simulation.

Decision date: 2026-10-06

## Context

Age assurance requires repeated presentations of one wallet-held credential to
be unlinkable, audience- and nonce-bound, offline-verifiable, and usable only by
a holder that knows wallet-held secret material. Selective disclosure by itself
is insufficient when a stable issuer signature, credential identifier, or
holder public key remains visible.

## Decision

Use W3C Verifiable Credentials Data Model 2.0 credentials secured with the Data
Integrity BBS `bbs-2023` cryptosuite and its `anonymous_holder_binding` feature.
Use OpenID for Verifiable Credential Issuance 1.0 and OpenID for Verifiable
Presentations 1.0 as the transport protocols.

The credential contains only coarse, issuer-certified boolean claims such as
`age_over_18`; it does not contain a birth date, exact age, subject identifier,
credential identifier, or globally unique holder key. A presentation discloses
one requested threshold and the minimum issuer and validity data required by
policy. The OpenID4VP nonce and full client identifier are bound into the BBS
presentation header.

This is a conditional implementation decision. As of 2026-09-10, Data Integrity
BBS v1.0 is a W3C Candidate Recommendation Draft, and anonymous holder binding
is explicitly marked at risk because it depends on the IRTF Blind BBS draft and
independent implementation evidence. Production issuance, presentation, and
verification MUST remain disabled until those dependencies are stable and a
maintained, independently reviewed library passes the published test vectors.
No BBS, blind-signature, or proof implementation will be written in this
project.

## Alternatives

| Format | Decision | Reason |
| --- | --- | --- |
| SD-JWT VC | Rejected | Repeated presentations expose the stable issuer-signed JWT and holder public key. Batch issuance only approximates unlinkability with one-time credentials. |
| ISO mdoc | Rejected | Selective disclosure and session binding are strong, but the issuer authentication and device key can correlate repeated presentations. |
| Baseline BBS | Rejected alone | Derived proofs are randomized and unlinkable, but possession of the base credential is bearer-like and does not satisfy wallet-secret holder binding. |
| BBS anonymous holder binding | Selected conditionally | Blind issuance binds the credential to a hidden holder secret while retaining randomized derived proofs. Its dependencies are not stable enough to implement yet. |
| AnonCreds/CL | Reserved fallback | It provides link-secret binding, predicates, and unlinkable proofs, but has a less direct standards and interoperability path through OpenID4VCI/VP for this project. |

## Threat Model

The design must resist:

- Verifier-verifier collusion using proof bytes, holder keys, identifiers,
  timestamps, revealed claims, or credential structure.
- Issuer-verifier collusion using holder-specific issuer keys, online status
  lookups, or issuer-specific identifiers.
- Replay to the same or another verifier by binding every proof to the full
  verifier identifier, a fresh nonce, and a short expiry.
- Credential copying by requiring proof of the hidden holder secret committed
  during blind issuance.
- Fingerprinting through uncommon threshold combinations, precise issuance
  times, unique validity windows, status indexes, or rare issuer keys.

Network metadata, browser fingerprinting, compromised endpoints, and voluntary
account linkage are outside the cryptographic guarantee and require separate
transport and operational controls.

## Required Profile

- Use `featureOption = anonymous_holder_binding`; do not substitute baseline
  BBS and describe it as holder-bound.
- Use a random holder secret of at least 32 bytes and keep the secret and prover
  blind encrypted in wallet storage.
- Use broad issuer signing-key cohorts. Never assign signing keys per holder.
- Omit globally unique JSON-LD node identifiers for the holder and personal
  claims.
- Keep the credential schema small and uniform. Issue a fixed ecosystem-defined
  threshold set and coarse validity periods.
- Put the canonical verifier identifier, nonce, request expiry, and requested
  threshold in the presentation header or an equivalently proof-bound value.
- Use short-lived credentials and expiry-only lifecycle in the initial profile.
  Do not include a conventional status-list index: revealing the same index in
  each presentation would make the credential linkable.
- A future revocation mechanism must prove non-revocation without revealing a
  stable credential identifier and must use locally cached public material;
  presentation must not trigger a holder-specific issuer lookup.
- Reject proofs with unsupported feature options, extra revealed claims, stale
  nonces, mismatched audiences, expired credentials, or untrusted issuer keys.

## Interoperability Gate

Before enabling the format, the implementation must demonstrate with an
external library that:

1. Published base-proof, derived-proof, and anonymous-holder-binding vectors
   pass without project-specific exceptions.
2. Two proofs for the same claim and request differ at the byte level while both
   verify.
3. Proofs cannot be linked to each other or to the base credential using any
   protocol-visible field other than intentionally disclosed issuer cohorts.
4. A copied base credential cannot produce a valid proof without the holder
   secret.
5. Audience, nonce, threshold, expiry, issuer key, and disclosed-claim tampering
   all fail verification.
6. Any later status mechanism neither contacts a holder-specific URL nor exposes
  a unique status identifier to the verifier. Until then, credentials rely on
  short expiry and cannot be revoked immediately.

Expiry-only lifecycle is an explicit availability and fraud-response tradeoff.
The maximum lifetime must be set by ecosystem risk policy; increasing it to
avoid renewal is not an acceptable substitute for privacy-preserving status.

## References

- [W3C Data Integrity BBS Cryptosuites v1.0](https://www.w3.org/TR/vc-di-bbs/)
- [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [IETF SD-JWT VC draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)