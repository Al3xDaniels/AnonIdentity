# Encrypted Wallet Format

Version 1 is a portable JSON envelope designed to be stored locally, handled by
a platform secure-storage adapter, and eventually synchronized as an opaque
blob. Only the envelope is written outside wallet memory.

## Threat model

The format protects the root secret and service metadata from someone who reads
the wallet file, an export from device secure storage, or a future synchronization
backend. AES-GCM also detects a wrong phrase and modification of either the
ciphertext or its authenticated header.

It does not protect an unlocked device, a captured recovery phrase, process
memory, deletion, or rollback to an older valid envelope. The authenticated
`revision` field is the basis for sync conflict and rollback checks, but rollback
prevention requires a trusted latest-revision record on a device or service and
is not implemented yet. The identity provider can still correlate enrollment
and login traffic.

## Recovery

The 24 BIP39 English words encode the wallet's complete 256-bit root secret plus
a checksum. Restoring from the phrase recreates the root public key, wallet ID,
and every deterministic service identity. Service labels and usage timestamps
are not derivable and require an encrypted wallet backup.

The recovery phrase is also passed through scrypt with a random 16-byte salt to
derive the envelope key. The phrase must never be uploaded or stored beside the
encrypted wallet.

## Version 1 envelope

```json
{
  "format": "anon-identity-wallet",
  "version": 1,
  "revision": 1,
  "kdf": {
    "name": "scrypt",
    "salt": "base64url(16 bytes)",
    "n": 32768,
    "r": 8,
    "p": 1
  },
  "cipher": {
    "name": "aes-256-gcm",
    "nonce": "base64url(12 bytes)"
  },
  "ciphertext": "base64url(ciphertext and 16-byte tag)"
}
```

The canonical JSON encoding of every field except `ciphertext` is AES-GCM
additional authenticated data. The decrypted payload contains `root_secret`,
the service catalog, and optional local integration or future device metadata.
Future wallet-held credentials, including age assurance credentials, belong in
this encrypted payload and must never appear in the envelope header. Every write
uses a fresh salt and nonce and increments `revision`.

Readers reject unknown versions, algorithms, or scrypt parameters. Future format
changes must use a new version and an explicit migration rather than silently
reinterpreting version 1 data.