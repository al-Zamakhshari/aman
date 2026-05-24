# aman — أمان

> *quantum-safe team credential manager*

**aman** is a post-quantum credential manager for teams. Each secret is encrypted directly to its recipients' individual PQC public keys — no shared vault password exists, ever. The vault is a plain directory: commit it to git, review access changes in PRs, and sync it any way you like.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Why aman?

Most password managers encrypt everything to a shared master key. If that key leaks, everything leaks. And none of them are quantum-safe.

**aman** works differently:

| | Traditional | aman |
|---|---|---|
| Encryption | Shared vault key | Per-entry, per-recipient PQC key |
| Quantum resistance | ❌ | ✅ ML-KEM-768+X25519 hybrid |
| Per-entry access control | ❌ | ✅ |
| Add/remove recipients | Requires re-keying the vault | Single `grant`/`revoke` command |
| Git-native | ❌ binary database | ✅ plain JSON files |
| No shared secret | ❌ | ✅ |

---

## Crypto

| Primitive | Algorithm | Standard |
|---|---|---|
| Key encapsulation | ML-KEM-768 + X25519 hybrid (X-Wing) | NIST FIPS 203 |
| Entry signing | ML-DSA-87 | NIST FIPS 204 |
| Payload encryption | ChaCha20-Poly1305 | RFC 8439 |
| Key protection | Argon2id | RFC 9106 |

Each secret file contains one HPKE-sealed copy of the file encryption key (FEK) per recipient. Removing a recipient re-generates the FEK entirely — their wrapped copy becomes useless.

---

## Installation

```bash
# Homebrew (macOS / Linux)
brew install al-Zamakhshari/tap/aman

# From source
git clone https://github.com/al-Zamakhshari/aman
cd aman && go build -o aman .
```

---

## Quick Start

```bash
# 1. Generate your keypair (once per person)
aman keygen --name alice
# → ~/.aman/alice.key  (keep private)
# → alice.pub          (share with teammates)

# 2. Initialise a vault
mkdir team-vault && cd team-vault
aman init

# 3. Register team members
aman member add alice ../alice.pub
aman member add bob   ../bob.pub

# 4. Add a secret
aman add github --to alice,bob --user deploy@company.com --url https://github.com

# 5. Get a secret (copies to clipboard, clears in 30s)
export AMAN_IDENTITY=alice
aman get github

# 6. Get a TOTP code
aman get github --field totp

# 7. Inject into shell
eval $(aman env aws-prod)
```

---

## Access management

```bash
# Grant access to a new team member (re-encrypts with new FEK)
aman grant github --to carol

# Revoke access (generates new FEK — carol's old wrapped copy is discarded)
aman revoke github --from bob

# The change is a plain file diff — review it in a PR
git diff entries/github.enc
```

---

## Vault layout

```
team-vault/
  .qpm/
    config.toml          vault metadata
    members/
      alice.pub          ML-KEM-768+X25519 + ML-DSA-87 public key bundle
      bob.pub
  entries/
    github.enc           encrypted to: alice, bob
    stripe-live.enc      encrypted to: alice only
    aws-prod.enc         encrypted to: alice, bob, carol
  audit.log              hash-chained, tamper-evident operation log
```

Each `.enc` file is a self-contained JSON envelope:

```json
{
  "version": 1,
  "name": "github",
  "created_by": "alice",
  "recipients": ["alice", "bob"],
  "recipient_blocks": [
    { "id": "alice", "sealed_fek": "..." },
    { "id": "bob",   "sealed_fek": "..." }
  ],
  "nonce": "...",
  "ciphertext": "...",
  "signature": "..."
}
```

---

## Command reference

```
aman init [dir]                      initialise vault
aman keygen --name <n>               generate ML-KEM+ML-DSA keypair

aman member add <name> <pubkey>      register team member
aman member list
aman member remove <name>

aman add <name> --to <a,b> [opts]    add secret
aman get <name> [--field pass|user|url|totp|notes]
aman list [--all] [--tag <t>]
aman edit <name> [--password] [--user] [--url] [--notes] [--totp]
aman delete <name>

aman grant <name> --to <member>      add recipient
aman revoke <name> --from <member>   remove recipient

aman env <name> [--prefix PREFIX]    print as export KEY=VAL
aman log [--verify] [--action <a>]   audit trail

aman import <file> --to <a,b>        import from Bitwarden / 1Password / LastPass

aman mcp [--vault <dir>]             start MCP server for AI agent integration
```

---

## Importing from other managers

```bash
# Bitwarden
aman import bitwarden_export.json --to alice,bob

# 1Password
aman import 1p_export.json --from 1password --to alice

# LastPass
aman import lastpass_export.csv --from lastpass --to alice,bob

# Preview first
aman import export.json --to alice --dry-run
```

---

## Security model

- **No shared secret**: each recipient holds only their own private key
- **Revocation is cryptographic**: re-sealing with a fresh FEK makes old recipient blocks useless
- **Entry binding**: HPKE info = SHA-256(vault name + entry name) — ciphertexts can't be transplanted between entries
- **Signed entries**: every entry carries an ML-DSA-87 signature from its creator
- **Tamper-evident log**: `audit.log` is hash-chained — run `aman log --verify` to check integrity
- **Private keys never leave disk unencrypted**: Argon2id + ChaCha20-Poly1305, memguard for in-memory wiping

---

## AI Agent Integration (MCP)

aman exposes a read-only MCP (Model Context Protocol) server over stdio, letting AI agents
securely fetch credentials they are authorised to use — without exposing write operations
(add, grant, revoke) to the agent.

### Claude Desktop / Cursor setup

Add to `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aman": {
      "command": "/usr/local/bin/aman",
      "args": ["mcp", "--vault", "/path/to/team-vault"],
      "env": {
        "AMAN_IDENTITY": "alice",
        "AMAN_PASSPHRASE": "your-passphrase"
      }
    }
  }
}
```

### Available tools (3)

| Tool | Description |
|---|---|
| `list_credentials` | List credential names and metadata this identity can access. Never returns values. |
| `get_credential` | Decrypt and return a specific field (`password`, `user`, `url`, `notes`). |
| `check_access` | Check whether the identity can decrypt a given credential before attempting. |

### Example agent interaction

> **User:** Deploy the staging environment using the credentials from our vault.

The agent calls `list_credentials` to discover available entries, `check_access("staging-deploy")` to confirm access, then `get_credential("staging-deploy", "password")` and uses the value directly as an environment variable — never echoing it in the response.

### Security model for agents

**Prompt injection risk:** a malicious document could trick an agent into calling `get_credential` and leaking the result in visible output. Mitigations built into aman's MCP mode:

- **Read-only surface** — no `add`, `grant`, `revoke`, or `delete` tools are exposed
- **Identity scoping** — the server operates as a single named identity; it can only access entries that identity was explicitly granted
- **Deliberate vagueness on errors** — `get_credential` returns "access denied or not found" regardless of which condition applies, preventing enumeration
- **Audit trail** — every `get` is appended to `audit.log` with hash chaining; run `aman log --verify` to detect unexpected access
- **Passphrase in env, not args** — `AMAN_PASSPHRASE` is set at server startup, never passed per-call

Instruct your agent to use credential values directly (e.g. as HTTP headers or env vars) without including them in text returned to the user.

---

## Companion project

**aman** is built on the cryptographic primitives from [maknoon](https://github.com/al-Zamakhshari/maknoon) — a full post-quantum cryptographic engine and MCP gateway.

---

## License

MIT © al-Zamakhshari
