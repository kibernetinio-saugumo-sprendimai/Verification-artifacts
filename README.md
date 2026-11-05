# SafeStack Verification Artifacts

This repository publishes detached factual cryptographic integrity data, owner-signed SHA-256 manifests, and verification tooling for external auditing of artifacts across the [`kibernetinio-saugumo-sprendimai`](https://github.com/kibernetinio-saugumo-sprendimai) SafeStack ecosystem.

---

## Owner Cryptographic Signature Attestation (Savininko kriptografinis patvirtinimas)

- **Signer / Savininkas:** SafeStack Organization Owner (`safestack-labs` — Antanas Bistrajus, `<admin@safestack.tech>`)
- **Principal Identity:** `safestack-owner`
- **Public Key:** [`keys/safestack-owner-2026-11-05.pub`](keys/safestack-owner-2026-11-05.pub)
- **Allowed Signers File:** [`keys/allowed_signers`](keys/allowed_signers)
- **Algorithm:** OpenSSH Ed25519
- **Key Fingerprint:** `SHA256:jpM7K4+8hyAJo9qg4ISDbljuENZzx2UqMHu73+S9q48`
- **Reconciliation & Signing Date:** `2026-11-05`
- **Signed Artifacts:** `SHA256SUMS` (`SHA256SUMS.sig`) and all `checksums/*.sha256` manifests (`checksums/*.sha256.sig`)

**LT — Savininko patvirtinimas:** Visi šioje saugykloje paskelbti SHA-256 kontrolinių sumų manifestai (`SHA256SUMS` ir `checksums/*.sha256`) buvo sutikrinti su visomis `kibernetinio-saugumo-sprendimai` organizacijos saugyklomis ir naujai kriptografiškai pasirašyti organizacijos savininko (`safestack-labs` / Antanas Bistrajus, `<admin@safestack.tech>`) OpenSSH Ed25519 raktu (`SHA256:jpM7K4+8hyAJo9qg4ISDbljuENZzx2UqMHu73+S9q48`). Kiekvieną `.sha256` failą lydi atskirtas `.sig` parašas, kurį galima nepriklausomai patikrinti per `ssh-keygen -Y verify`.

---

## Purpose

The contents of this repository allow independent auditors, nodes, and operators to:
- Verify the integrity of external SafeStack releases, documents, and manifests.
- Confirm consistency against owner-signed cryptographic SHA-256 hashes.
- Validate project identities, canonical Ed25519 fingerprints, and zero-leakage security invariants.
- Validate authenticity independently of repository code branches.

No original source binaries or mutable operational states are stored here; this repository publishes factual integrity anchors, detached signatures, and verification engines only.

---

## Architectural Role in SafeStack

In accordance with SafeStack's layered trust architecture:
- **`safestack-validation-registry`:** Registers the formal validation status, compliance declarations, and audit records of SafeStack projects.
- **`Verification-artifacts`:** Publishes the detached cryptographic checksum files, owner-signed `.sha256.sig` manifests, and verification scripts.
- **`safestack-project-public-keys`:** Publishes the root-signed Ed25519 project identity keys and release-signing keys.

---

## Repository Structure

```
Verification-artifacts/
├── README.md
├── SHA256SUMS                              # Repository-level integrity manifest
├── SHA256SUMS.sig                          # Owner OpenSSH Ed25519 signature over SHA256SUMS
├── verify.sh                               # One-command ecosystem verification runner
├── verify_ecosystem.py                     # Automated hash, signature & secret verification engine
├── keys/
│   ├── allowed_signers                     # SSH allowed_signers for signature verification
│   └── safestack-owner-2026-11-05.pub      # SafeStack Owner SSH Ed25519 public key
├── scripts/
│   └── safestack-pre-commit.sh             # Zero-leakage pre-commit security gate
└── checksums/
    ├── safestack-ecosystem.sha256(.sig)    # Master ecosystem checksum manifest + owner signature
    ├── core-projects.sha256(.sig)          # Core validated project manifests & audit reports
    ├── node-os.sha256(.sig)                # NodeOS release and audit report hashes
    ├── technical-canon.sha256(.sig)        # Technical Canon SHA-256 hashes
    ├── validation-registry.sha256(.sig)    # Validation Registry root & manifest hashes
    └── release-signing-keys.sha256(.sig)   # Public release & owner signing key checksums
```

---

## Verification Procedures

### 1. Automated Ecosystem & Signature Verification
Run the unified verification engine to validate all SHA-256 manifests, verify all detached owner OpenSSH Ed25519 signatures, verify root-signed project identities, and audit for zero secret leakage:
```bash
./verify.sh
# or directly:
python3 verify_ecosystem.py
```

### 2. Verify Detached Owner Signatures Manually (`ssh-keygen`)
Verify that `SHA256SUMS` and any `checksums/*.sha256` manifest were signed by the SafeStack Owner (`SHA256:jpM7K4+8hyAJo9qg4ISDbljuENZzx2UqMHu73+S9q48`):
```bash
ssh-keygen -Y verify -f keys/allowed_signers -I safestack-owner \
  -n file -s SHA256SUMS.sig < SHA256SUMS

for f in checksums/*.sha256; do
  ssh-keygen -Y verify -f keys/allowed_signers -I safestack-owner \
    -n file -s "${f}.sig" < "${f}"
done
```

### 3. Manual SHA-256 Manifest Verification
Verify repository files directly or verify cross-repository ecosystem hashes from the parent workspace directory:
```bash
# Verify all files inside Verification-artifacts:
shasum -a 256 -c SHA256SUMS

# From the parent workspace directory containing cloned SafeStack repositories:
(cd .. && shasum -a 256 -c Verification-artifacts/checksums/safestack-ecosystem.sha256)
(cd .. && shasum -a 256 -c Verification-artifacts/checksums/core-projects.sha256)
```

---

## Notes & Guarantees

- This repository functions solely as a public reference for cryptographic verification.
- Trust is established through verification, not authority.
- No private keys or internal credentials are ever committed here.
