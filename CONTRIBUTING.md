# Contributing

Thank you for contributing to Anonymous Identity. This project handles identity
and cryptographic material, so changes should remain narrow, testable, and clear
about their security and privacy assumptions.

## Before submitting a change

1. Open an issue for significant protocol, cryptographic, persistence, or API
   changes before implementation.
2. Do not commit wallet files, recovery phrases, private keys, identity evidence,
   access tokens, or production credentials.
3. Add focused tests for changed behavior and run the complete test suite.
4. Update the threat model or user documentation when a trust boundary changes.

Run the test suite with:

```bash
.venv/bin/python -m pytest -q
```

## Developer Certificate of Origin

This project uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
instead of a contributor license agreement. By adding a `Signed-off-by` line to
each commit, you certify that you have the right to submit the contribution under
this project's license.

Create a signed-off commit with:

```bash
git commit --signoff
```

The resulting commit message must contain your real or established project
identity and an email address:

```text
Signed-off-by: Contributor Name <contributor@example.com>
```

## Review expectations

Pull requests should explain the behavior being changed, its privacy or security
impact, and how it was validated. Protocol changes must avoid introducing stable
cross-service identifiers or disclosing additional personal information by
default.