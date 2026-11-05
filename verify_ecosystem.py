#!/usr/bin/env python3
"""
SafeStack Ecosystem Integrity & Verification Engine
Validates cryptographic SHA-256 checksum manifests, detached OpenSSH Ed25519
owner signatures, root-signed project identities, and zero-leakage invariants
across SafeStack repositories.
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PUBLIC_REPOS = [
    'safestack-canon', 'safestack-technical-canon', 'safestack-project-public-keys',
    'safestack-validation-registry', 'Verification-artifacts', 'safestack-control-architecture',
    'node-os', 'Safestack-Zero-Trust', 'SafeStack-Zero-Trust-Platform', 'Safestack-Sentinel',
    'Safestack-suite', 'safestack-audit_system', 'safestack-OSINT', 'safestack-darbu-sauga',
    'AI-Tyreju-Komanda', 'freedom.manifesto.github.io', 'safestack-porfolio.github.io',
    'safestack-book', '.github', 'safestack-repo-map', 'safestack-partners',
    'safestack-media-library', 'safestack-music'
]

# Sensitive patterns that must NEVER be committed to any public repository
SECRET_PATTERNS = [
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----"
]

OWNER_SIGNER_IDENTITY = "safestack-owner"


def sha256_file(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def resolve_manifest_target(manifest_name: str, rel_path: str, script_dir: Path, base_dir: Path) -> Path | None:
    if manifest_name == 'SHA256SUMS':
        candidate = script_dir / rel_path
        return candidate if candidate.is_file() else None

    search_roots = [base_dir]
    if manifest_name == 'validation-registry.sha256':
        search_roots = [base_dir / 'safestack-validation-registry']
    elif manifest_name == 'technical-canon.sha256':
        search_roots = [base_dir / 'safestack-technical-canon']
    elif manifest_name == 'node-os.sha256':
        search_roots = [base_dir / 'node-os']
    elif manifest_name == 'release-signing-keys.sha256':
        search_roots = [
            script_dir / 'keys',
            base_dir / 'safestack-validation-registry' / 'release-signing',
            base_dir / 'safestack-project-public-keys' / 'release-signing',
        ]

    for root in search_roots:
        candidate = root / rel_path
        if candidate.is_file():
            return candidate
    return None


def verify_manifests(script_dir: Path, base_dir: Path) -> dict:
    checksums_dir = script_dir / 'checksums'
    if not checksums_dir.exists():
        return {'status': 'FAIL', 'error': 'checksums directory not found'}

    manifest_files = sorted(checksums_dir.glob('*.sha256'))
    top_sums = script_dir / 'SHA256SUMS'
    if top_sums.is_file():
        manifest_files.append(top_sums)

    results = {}
    for mf in manifest_files:
        valid_lines = 0
        verified_files = 0
        mismatches = []
        with open(mf, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2 and len(parts[0]) == 64:
                    expected_hash, rel_target = parts[0].lower(), parts[1].lstrip('*').strip()
                    valid_lines += 1
                    target = resolve_manifest_target(mf.name, rel_target, script_dir, base_dir)
                    if target is not None:
                        actual_hash = sha256_file(target)
                        if actual_hash == expected_hash:
                            verified_files += 1
                        else:
                            mismatches.append(f"{rel_target} (expected {expected_hash}, got {actual_hash})")
                else:
                    mismatches.append(f"malformed entry: {line}")

        status = 'VALID' if (valid_lines > 0 and not mismatches) else ('FAIL' if mismatches else 'EMPTY')
        results[mf.name] = {
            'entries': valid_lines,
            'verified_on_disk': verified_files,
            'mismatches': mismatches,
            'status': status
        }
    return results


def verify_owner_signatures(script_dir: Path) -> dict:
    allowed_signers = script_dir / 'keys' / 'allowed_signers'
    if not allowed_signers.is_file():
        return {'status': 'FAIL', 'error': 'keys/allowed_signers not found'}

    targets = sorted((script_dir / 'checksums').glob('*.sha256'))
    top_sums = script_dir / 'SHA256SUMS'
    if top_sums.is_file():
        targets.append(top_sums)

    verified = {}
    all_ok = True
    for target in targets:
        sig_file = Path(f"{target}.sig")
        rel_name = target.relative_to(script_dir).as_posix()
        if not sig_file.is_file():
            verified[rel_name] = {'status': 'MISSING_SIGNATURE'}
            all_ok = False
            continue

        with open(target, 'rb') as data_stream:
            proc = subprocess.run(
                [
                    'ssh-keygen', '-Y', 'verify',
                    '-f', str(allowed_signers),
                    '-I', OWNER_SIGNER_IDENTITY,
                    '-n', 'file',
                    '-s', str(sig_file),
                ],
                stdin=data_stream,
                capture_output=True,
                text=True,
            )
        if proc.returncode == 0:
            verified[rel_name] = {
                'status': 'VERIFIED',
                'signer': OWNER_SIGNER_IDENTITY,
                'detail': (proc.stdout.strip() or proc.stderr.strip()),
            }
        else:
            verified[rel_name] = {
                'status': 'FAIL',
                'error': (proc.stderr.strip() or proc.stdout.strip()),
            }
            all_ok = False

    return {
        'status': 'PASS' if (all_ok and len(verified) > 0) else 'FAIL',
        'signer_identity': OWNER_SIGNER_IDENTITY,
        'verified_count': sum(1 for v in verified.values() if v['status'] == 'VERIFIED'),
        'total_manifests': len(verified),
        'signatures': verified,
    }


def verify_project_keys(repo_dir: Path) -> dict:
    keys_file = repo_dir / 'safestack-project-public-keys' / 'public-project-keys.json'
    if not keys_file.exists():
        return {'status': 'SKIPPED', 'reason': 'public-project-keys.json not located locally'}

    with open(keys_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    root_sig_verified = None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        unsigned = dict(data)
        sig_b64 = unsigned.pop('signature', '')
        canonical_bytes = json.dumps(unsigned, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
        root_pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(data['root_public_key']))
        root_pub.verify(base64.b64decode(sig_b64), canonical_bytes)
        root_sig_verified = True
    except ImportError:
        root_sig_verified = 'SKIPPED_NO_CRYPTOGRAPHY'
    except Exception as exc:
        return {'status': 'FAIL', 'reason': f'root signature verification failed: {exc}'}

    projects = data.get('projects', {})
    fingerprints = {}
    for pid, pdata in sorted(projects.items()):
        pub_b64 = pdata.get('public_key', '')
        raw_bytes = base64.b64decode(pub_b64)
        fp = hashlib.sha256(raw_bytes).hexdigest()
        fingerprints[pid] = {
            'project': pdata.get('project_name'),
            'status': pdata.get('status'),
            'fingerprint': fp
        }
    return {
        'status': 'PASS',
        'root_signature_verified': root_sig_verified,
        'total_keys': len(projects),
        'keys': fingerprints
    }


def verify_no_secrets(base_dir: Path) -> dict:
    leaks = []
    ignored_dirs = {'.git', '.venv', 'venv', 'env', '__pycache__', 'node_modules', '.idea'}

    for r_name in PUBLIC_REPOS:
        target_dir = base_dir / r_name
        if not target_dir.exists():
            continue

        for p in target_dir.rglob('*'):
            if any(part in ignored_dirs for part in p.parts) or not p.is_file():
                continue
            if p.name in ['verify_ecosystem.py', 'safestack-pre-commit.sh']:
                continue

            try:
                if p.stat().st_size > 10 * 1024 * 1024:
                    continue
                content = p.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                continue

            for pattern in SECRET_PATTERNS:
                if pattern in content:
                    leaks.append(f"Private secret key pattern found in {p.relative_to(base_dir)}")

    return {
        'status': 'PASS' if len(leaks) == 0 else 'FAIL',
        'leak_count': len(leaks),
        'leaks': leaks
    }


def main():
    script_dir = Path(__file__).resolve().parent
    base_dir = script_dir.parent

    print("==================================================")
    print("      SafeStack Verifiable Ecosystem Engine       ")
    print("==================================================")
    print(f"Base Workspace: {base_dir}")
    print(f"Verification Artifacts: {script_dir}")
    print()

    print("[1/4] Verifying SHA-256 Checksum Manifests...")
    manifests = verify_manifests(script_dir, base_dir)
    for name, res in manifests.items():
        mark = "✓" if res['status'] == 'VALID' else "✗"
        print(f"  {mark} {name}: {res['entries']} entries, {res['verified_on_disk']} verified on disk ({res['status']})")
        for m in res.get('mismatches', []):
            print(f"      ! {m}")
    print()

    print("[2/4] Verifying Detached Owner OpenSSH Ed25519 Signatures...")
    sig_report = verify_owner_signatures(script_dir)
    for rel_name, sres in sig_report.get('signatures', {}).items():
        mark = "✓" if sres['status'] == 'VERIFIED' else "✗"
        print(f"  {mark} {rel_name}.sig: {sres['status']} ({sres.get('signer', sres.get('error', ''))})")
    print()

    print("[3/4] Verifying Root-Signed Public Key Registry...")
    keys_report = verify_project_keys(base_dir)
    print(f"  Status: {keys_report.get('status')}")
    if keys_report.get('status') == 'PASS':
        print(f"  Root Ed25519 Signature Verified: {keys_report.get('root_signature_verified')}")
        print(f"  Total Registered Keys: {keys_report['total_keys']}")
    print()

    print("[4/4] Scanning Public Repositories for Private Secrets...")
    leak_report = verify_no_secrets(base_dir)
    if leak_report['status'] == 'PASS':
        print("  ✓ Zero private keys committed across all public repositories.")
    else:
        print(f"  ✗ WARNING: {leak_report['leak_count']} potential private key leaks found:")
        for l in leak_report['leaks'][:5]:
            print(f"    - {l}")
    print()

    all_pass = (
        all(m['status'] == 'VALID' for m in manifests.values()) and
        sig_report.get('status') == 'PASS' and
        keys_report.get('status') in ('PASS', 'SKIPPED') and
        leak_report['status'] == 'PASS'
    )

    now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    report = {
        'timestamp': os.environ.get('CURRENT_TIME', now_iso),
        'overall_status': 'PASS' if all_pass else 'FAIL',
        'owner_signatures': sig_report,
        'manifests': manifests,
        'keys': keys_report,
        'secret_audit': leak_report
    }

    report_path = script_dir / 'ECOSYSTEM_HEALTH_REPORT.json'
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    print("==================================================")
    print(f"Overall Result: {'[PASS] ECOSYSTEM INTEGRITY & OWNER SIGNATURES VERIFIED' if all_pass else '[FAIL] VERIFICATION FAILED'}")
    print(f"Report written to: {report_path.name}")
    print("==================================================")

    sys.exit(0 if all_pass else 1)


if __name__ == '__main__':
    main()
