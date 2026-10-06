# Getting Started

This guide runs the identity provider and demo service, creates an encrypted
wallet, and completes a pairwise login.

## Prerequisites

- Docker with Docker Compose

## Start the services

Build and start the identity provider, relying service, and visual demo:

```bash
docker compose up --build --wait
```

The local endpoints are:

- Visual protocol demo: <http://localhost:8002>
- Identity provider API: <http://localhost:8000/docs>
- Demo `forum.com` service: <http://localhost:8001/docs>

The visual demo creates an ephemeral wallet in its own process and walks through
real enrollment, challenge signing, token issuance, and audience validation for
two services. This server-side wallet is only a POC convenience; a production
browser flow must perform wallet operations on the user's device.

## Create and enroll a wallet

The `wallet-cli` Compose service stores demo wallet files in a Docker volume.
Create an encrypted wallet and enroll its public key with the containerized
provider:

```bash
docker compose --profile tools run --rm wallet-cli \
  create alice.wallet.json --recovery-output alice.recovery.txt
docker compose --profile tools run --rm wallet-cli \
  enroll alice.wallet.json \
  --recovery-phrase-file alice.recovery.txt \
  --provider http://identity-provider:8000
```

Store the 24-word phrase separately from the encrypted wallet. Anyone with the
phrase controls the identity. Keeping both files in one Docker volume is suitable
only for this demonstration; production recovery material needs a separate,
offline backup.

When `--recovery-phrase-file` is omitted, the CLI uses
`ANON_IDENTITY_RECOVERY_PHRASE` if set or prompts without echoing the phrase.

## Complete a login

```bash
TOKEN=$(docker compose --profile tools run --rm --no-TTY wallet-cli \
  login alice.wallet.json \
  --recovery-phrase-file alice.recovery.txt \
  --service forum.com \
  --provider http://identity-provider:8000 \
  --token-only)

curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/session
```

The service response contains `forum.com` and its pairwise anonymous subject. To
inspect locally recorded service metadata:

```bash
docker compose --profile tools run --rm wallet-cli \
  services alice.wallet.json \
  --recovery-phrase-file alice.recovery.txt
```

## Restore an identity

The recovery phrase recreates the same wallet ID and pairwise identities. A
phrase-only restore starts with an empty service catalog because labels and
timestamps are not derivable:

```bash
docker compose --profile tools run --rm wallet-cli \
  restore restored.wallet.json \
  --recovery-phrase-file alice.recovery.txt
```

## Migrate a plaintext wallet

Encrypt an older prototype wallet in place while preserving its root identity:

```bash
docker compose --profile tools run --rm wallet-cli \
  migrate old.wallet.json \
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

KDE Wallet integration intentionally runs on the host because it needs the
user's desktop D-Bus session. Install the local development environment before
using those two commands.

## Connect an existing wallet to the visual demo

The optional localhost bridge supports encrypted files, KWallet, and external
secure-storage plugins through one interface. It intentionally runs on the host
so Docker and websites never receive wallet secrets. See the
[local wallet bridge guide](wallet-bridge.md) for setup and adapter details.

## Optional local development

Docker runs every portable demo component. A local environment is needed only
for development, tests, or host desktop integrations such as KDE Wallet:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```

## Stop the services

```bash
docker compose down
```

Use `docker compose down -v` only when the provider's SQLite volume should also
be deleted. It also removes the visual-demo database and containerized demo
wallet when the `wallet-demo-data` volume is included.