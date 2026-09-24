# SafeStack Verification Artifacts

This repository publishes detached factual cryptographic integrity data and verification tooling for external auditing of artifacts across the SafeStack ecosystem.

---

## Purpose

The contents of this repository allow independent auditors, nodes, and operators to:
- Verify the integrity of external SafeStack releases, documents, and manifests.
- Confirm consistency against published cryptographic SHA-256 hashes.
- Validate project identities, keys, and zero-leakage security invariants.
- Validate authenticity independently of repository code branches.

No original source binaries or mutable operational states are stored here; this repository publishes factual integrity anchors and verification engines only.

---

## Architectural Role in SafeStack

In accordance with SafeStack's layered trust architecture:
- **`safestack-validation-registry`:** Registers the formal validation status, compliance declarations, and audit records of SafeStack projects.
- **`Verification-artifacts`:** Publishes the detached cryptographic checksum files, hash manifests, and verification scripts.
- **`safestack-project-public-keys`:** Publishes the signed Ed25519 project identity keys and release-signing keys.

---

## Repository Structure

```
Verification-artifacts/
├── README.md
├── verify.sh                       # One-command ecosystem verification runner
├── verify_ecosystem.py             # Automated cryptographic verification engine
├── ECOSYSTEM_HEALTH_REPORT.json    # Machine-readable verification output
└── checksums/
    ├── safestack-ecosystem.sha256    # Master ecosystem checksum manifest
    ├── node-os.sha256                # NodeOS release and audit report hashes
    ├── technical-canon.sha256        # Technical Canon SHA-256 hash
    ├── validation-registry.sha256     # Validation Registry root hash
    └── release-signing-keys.sha256   # Public release key checksum
```

---

## Verification Procedures

### 1. Automated Ecosystem Verification
Run the unified verification engine to validate all manifests, verify project identities, and audit for zero secret leakage:
```bash
./verify.sh
# or directly:
python3 verify_ecosystem.py
```

### 2. Manual Manifest Verification
Checksums can also be verified using standard Unix/macOS utilities:
```bash
shasum -a 256 -c checksums/safestack-ecosystem.sha256
shasum -a 256 -c checksums/node-os.sha256
shasum -a 256 -c checksums/technical-canon.sha256
shasum -a 256 -c checksums/validation-registry.sha256
```

### 3. Verify Detached Signatures
Where detached `.asc` or `.sig` signatures are present, verify using SSH or GnuPG:
```bash
# Verify SSH Ed25519 signature
ssh-keygen -Y verify -f safestack-pi5-2026.pub -I "safestack-release" -n "file" -s <file>.sig <file>
```

---

## Notes & Guarantees

- This repository functions solely as a public reference for cryptographic verification.
- Trust is established through verification, not authority.
- No private keys or internal credentials are ever committed here.
