# SafeStack Verification Artifacts

This repository publishes detached factual cryptographic integrity data for external verification of artifacts across the SafeStack ecosystem.

---

## Purpose

The contents of this repository allow independent auditors, nodes, and operators to:
- Verify the integrity of external SafeStack releases, documents, and manifests.
- Confirm consistency against published cryptographic SHA-256 hashes.
- Validate authenticity independently of repository code branches.

No original source binaries or mutable operational states are stored here; this repository publishes factual integrity anchors only.

---

## Architectural Role in SafeStack

In accordance with SafeStack's layered trust architecture:
- **`safestack-validation-registry`:** Registers the formal validation status, compliance declarations, and audit records of SafeStack projects.
- **`Verification-artifacts`:** Publishes the raw, detached cryptographic checksum files and hash manifests against which builds and artifacts are verified.
- **`safestack-project-public-keys`:** Publishes the signed Ed25519 project identity keys and release-signing keys.

---

## Repository Structure

```
Verification-artifacts/
├── README.md
├── verify.sh
└── checksums/
    ├── safestack-ecosystem.sha256    # Master ecosystem checksum manifest
    ├── technical-canon.sha256        # Technical Canon SHA-256 hash
    ├── validation-registry.sha256     # Validation Registry root hash
    └── release-signing-keys.sha256   # Public release key checksum
```

---

## Verification Procedures

Checksums can be verified using standard Unix/macOS or Windows utilities.

### 1. Verify Master Ecosystem Checksums
```bash
shasum -a 256 -c checksums/technical-canon.sha256
shasum -a 256 -c checksums/validation-registry.sha256
```

### 2. Verify Detached Signatures
Where detached `.asc` or `.sig` signatures are present, verify using GnuPG or SSH:
```bash
# Verify GPG clear-signed or detached signature
gpg --verify <artifact>.asc

# Verify SSH Ed25519 signature
ssh-keygen -Y verify -f safestack-pi5-2026.pub -I "safestack-release" -n "file" -s <file>.sig <file>
```

---

## Notes & Guarantees

- This repository functions solely as a public reference for cryptographic verification.
- Trust is established through verification, not authority.
- No warranty or operational suitability is implied. Factual cryptographic data only.
