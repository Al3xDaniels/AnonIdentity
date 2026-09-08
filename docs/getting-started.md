# Getting Started

This guide runs the identity provider and demo service, creates an encrypted
wallet, and completes a pairwise login.

## Prerequisites

- Docker with Docker Compose
- Python 3.11 or newer

## Start the services

Create a virtual environment, install the wallet CLI, and start the containers:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
docker compose up --build
```

The local endpoints are:

- Identity provider API: <http://localhost:8000/docs>
- Demo `forum.com` service: <http://localhost:8001/docs>

## Create and enroll a wallet

In another terminal, create the wallet and write its recovery phrase to an
owner-readable file:

```bash
.venv/bin/anon-wallet create alice.wallet.json --recovery-output alice.recovery.txt
.venv/bin/anon-wallet enroll alice.wallet.json --recovery-phrase-file alice.recovery.txt
```

Store the 24-word phrase separately from the encrypted wallet. Anyone with the
phrase controls the identity. The example recovery filename is ignored by Git,
but an offline backup is safer than leaving both files together.

When `--recovery-phrase-file` is omitted, the CLI uses
`ANON_IDENTITY_RECOVERY_PHRASE` if set or prompts without echoing the phrase.

## Complete a login

```bash
TOKEN=$(.venv/bin/anon-wallet login alice.wallet.json \
  --recovery-phrase-file alice.recovery.txt \
  --service forum.com \
  --token-only)

curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/session
```

The service response contains `forum.com` and its pairwise anonymous subject. To
inspect locally recorded service metadata:

```bash
.venv/bin/anon-wallet services alice.wallet.json \
  --recovery-phrase-file alice.recovery.txt
```

## Restore an identity

The recovery phrase recreates the same wallet ID and pairwise identities. A
phrase-only restore starts with an empty service catalog because labels and
timestamps are not derivable:

```bash
.venv/bin/anon-wallet restore restored.wallet.json \
  --recovery-phrase-file alice.recovery.txt
```

## Migrate a plaintext wallet

Encrypt an older prototype wallet in place while preserving its root identity:

```bash
.venv/bin/anon-wallet migrate old.wallet.json \
  --recovery-output old.recovery.txt
```

The command replaces the plaintext file with a version 1 encrypted envelope.
Securely remove any separate plaintext backups after confirming recovery.

## Optional KDE Wallet adapter

KDE Wallet is the secure-storage adapter currently implemented for this Linux
prototype. It demonstrates the adapter boundary and is not required by the
identity protocol or intended as the only production storage provider.

Enable a GUI-visible encrypted mirror in KDE Wallet:

```bash
.venv/bin/anon-wallet keyring-enable alice.wallet.json \
  --recovery-phrase-file alice.recovery.txt
```

The entry appears in KWallet Manager's `Passwords` folder with a name such as
`AnonIdentity - wallet_...`. KWallet receives the encrypted envelope, never the
plaintext root secret. Successful logins update both copies. To synchronize it
manually:

```bash
.venv/bin/anon-wallet keyring-sync alice.wallet.json \
  --recovery-phrase-file alice.recovery.txt
```

## Run the tests

```bash
.venv/bin/python -m pytest -q
```

## Stop the services

```bash
docker compose down
```

Use `docker compose down -v` only when the provider's SQLite volume should also
be deleted.