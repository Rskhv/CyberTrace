# Cryptography design

- Scan authorizations and evidence manifests use canonical UTF-8 JSON (sorted keys, compact separators) signed with Ed25519.
- Evidence byte envelopes use AES-256-GCM with a fresh 96-bit random nonce and the key identifier as associated data. The encoded authentication tag is stored separately from ciphertext. Never reuse a nonce with the same key.
- SHA-256 fingerprints cover evidence bytes. Passwords use salted scrypt via Python's standard library. Audit records use SHA-256 chaining; optional HMAC-SHA-256 is verified with constant-time comparison.
- Audit checkpoints can be signed with Ed25519. Keep a checkpoint and its private signing key outside the database host to resist full-database rewrite.
- RSA-PSS/SHA-256 helpers are provided for the Information Security Lab demonstration, separate from Ed25519 authorization.

Private keys are loaded from protected PEM files; AES keys can be loaded from base64 environment values or owner-only files. The metadata database contains public material and key identifiers, never secret key bytes. Key rotation requires re-encrypting retained evidence and updating manifests before revoking old keys; metadata helpers alone do not perform that operational migration.

The current helpers provide encryption primitives and an envelope format. They do not automatically encrypt every existing PCAP, report, backup or SQLite page. Existing artifacts remain plaintext until an operator explicitly wraps them. Standard SQLite is not encrypted; deploy SQLCipher separately if whole-database encryption is required.
