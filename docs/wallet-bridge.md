# Local Wallet Bridge

The local wallet bridge lets a browser use an existing encrypted wallet without
giving wallet secrets to the website, identity provider, or Docker containers.
It listens only on `127.0.0.1`, unlocks the wallet on the host, asks for consent
in its terminal, and returns only public proof material.

## Start with an encrypted wallet file

Install the host command, then allow the visual demo to request only its two
demonstration service identities:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/anon-wallet-bridge \
  --wallet-file my.wallet.json \
  --recovery-phrase-file my.recovery.txt \
  --allow http://localhost:8002=forum.example \
  --allow http://localhost:8002=shop.example
```

Open <http://localhost:8002>, select **Connect local**, and authenticate to a
service. The bridge terminal displays the exact browser origin and service ID
before each signature. The recovery phrase file is a development convenience;
omitting it prompts without echoing the phrase.

If the demo is opened at `http://127.0.0.1:8002`, use that exact origin in both
rules. Origins are not wildcarded.

## Start with KWallet

KWallet is one adapter, not part of the bridge protocol. Its configuration names
the existing encrypted mirror:

```bash
.venv/bin/anon-wallet-bridge \
  --storage-backend kwallet \
  --storage-config '{"backend":"kwallet","wallet":"kdewallet","folder":"Passwords","entry":"AnonIdentity - wallet_example"}' \
  --recovery-phrase-file my.recovery.txt \
  --allow http://localhost:8002=forum.example \
  --allow http://localhost:8002=shop.example
```

Replace `wallet_example` with the entry shown in KWallet Manager. KWallet gives
the bridge only the encrypted envelope; decryption still requires the recovery
phrase locally.

## Storage adapter contract

Backends implement `EncryptedEnvelopeStore` from
`anon_identity.secure_storage`. They read and write opaque envelope dictionaries
and must never request or receive the recovery phrase. External Python packages
can publish adapters without modifying this project:

```toml
[project.entry-points."anon_identity.secure_storage"]
secret-service = "my_wallet_adapter:SecretServiceStore"
```

An adapter exposes a stable `backend` name and `read(configuration)` and
`write(configuration, envelope)` methods. This can support Secret Service,
macOS Keychain, Windows Credential Manager, hardware wallets, or development
stores while leaving the browser API unchanged.

## Security boundary

- Recovery phrases and decrypted wallet documents are never accepted over HTTP.
- Browser origins are exact allowlist entries and are bound to service IDs.
- Every proof requires terminal approval.
- Expired or overly long challenges are rejected.
- A challenge is signed at most once per bridge process.
- The bridge does not expose wallet contents or private keys.

This remains a POC. Browser origin headers can be imitated by local software, so
terminal consent is the final authorization boundary. A production client should
use an authenticated native-messaging or operating-system broker and a graphical
consent surface. Restart the bridge after the encrypted wallet changes elsewhere;
the current process keeps the unlocked identity in memory until it exits.