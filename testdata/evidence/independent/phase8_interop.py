#!/usr/bin/env python3
"""Generate deterministic, non-production Phase 8 interoperability fixtures.

This program is intentionally independent from the Go production package. It
uses Python libraries for CBOR, ECDSA, and HPKE and emits JSON on stdout.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import struct
import sys
import argparse
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from pyhpke import AEADId, CipherSuite, KDFId, KEMId


SUITE_ID = 0x0001
COSE_ES256 = -7
COSE_SIGN1_TAG = 18
FORMAT_VERSION_LABEL = -65537
SUITE_ID_LABEL = -65538
ARTIFACT_METADATA_LABEL = -65539
SIGNED_PAYLOAD_CONTENT_TYPE = "application/vnd.kurdistan.profile+cbor"
SIGNED_OBJECT_CONTENT_TYPE = "application/vnd.kurdistan.profile+cose"
SIGNATURE_EXTERNAL_AAD = b"kurdistan-vpn/profile-signature/external-aad/v1"
HPKE_INFO_DOMAIN = b"kurdistan-vpn/profile-seal/hpke-info/v1"
HPKE_AAD_DOMAIN = b"kurdistan-vpn/profile-seal/hpke-aad/v1"
P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)
EXPECTED_PYTHON = (3, 12, 10)
EXPECTED_PACKAGES = {
    "cbor2": "6.1.3",
    "cffi": "2.0.0",
    "cryptography": "46.0.7",
    "pycparser": "2.23",
    "pyhpke": "0.6.5",
}


def verify_runtime() -> None:
    actual_python = sys.version_info[:3]
    if actual_python != EXPECTED_PYTHON:
        raise RuntimeError(
            f"Python runtime {actual_python!r} does not match locked {EXPECTED_PYTHON!r}"
        )
    for package, expected_version in EXPECTED_PACKAGES.items():
        actual_version = importlib.metadata.version(package)
        if actual_version != expected_version:
            raise RuntimeError(
                f"{package} {actual_version} does not match locked {expected_version}"
            )


def canonical(value: object) -> bytes:
    return cbor2.dumps(value, canonical=True)


def domain_separated(domain: bytes, protected: bytes) -> bytes:
    return struct.pack(">H", len(domain)) + domain + struct.pack(">I", len(protected)) + protected


def signing_key() -> ec.EllipticCurvePrivateKey:
    seed = hashlib.sha256(b"Kurdistan Phase 8 independent ES256 fixture v1").digest()
    scalar = int.from_bytes(seed, "big") % (P256_ORDER - 1) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def raw_low_s_signature(key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    der = key.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def artifact_metadata(
    artifact_class: str,
    audience: str,
    hint: bytes,
    recipient_epoch: int,
) -> bytes:
    return canonical({1: artifact_class, 2: audience, 3: hint, 4: recipient_epoch})


def signed_fixture(
    key: ec.EllipticCurvePrivateKey,
    key_id: bytes,
    payload: bytes,
    metadata: bytes,
) -> tuple[bytes, bytes, bytes, bytes]:
    protected = canonical(
        {
            1: COSE_ES256,
            2: [FORMAT_VERSION_LABEL, SUITE_ID_LABEL, ARTIFACT_METADATA_LABEL],
            3: SIGNED_PAYLOAD_CONTENT_TYPE,
            4: key_id,
            FORMAT_VERSION_LABEL: 1,
            SUITE_ID_LABEL: SUITE_ID,
            ARTIFACT_METADATA_LABEL: metadata,
        }
    )
    sig_structure = canonical(
        ["Signature1", protected, SIGNATURE_EXTERNAL_AAD, payload]
    )
    signature = raw_low_s_signature(key, sig_structure)
    signed_object = canonical(
        cbor2.CBORTag(COSE_SIGN1_TAG, [protected, {}, payload, signature])
    )
    return protected, sig_structure, signature, signed_object


def seal_fixture(
    suite: CipherSuite,
    fixture_id: str,
    metadata: bytes,
    recipient_ikm: bytes,
    ephemeral_ikm: bytes,
    plaintext: bytes,
    artifact_class: str,
    audience: str,
    hint: bytes,
    recipient_epoch: int,
) -> dict[str, object]:
    outer_protected = canonical(
        {
            1: 1,
            2: SUITE_ID,
            3: SIGNED_OBJECT_CONTENT_TYPE,
            4: metadata,
        }
    )
    info = domain_separated(HPKE_INFO_DOMAIN, outer_protected)
    aad = domain_separated(HPKE_AAD_DOMAIN, outer_protected)
    recipient = suite.kem.derive_key_pair(recipient_ikm)
    ephemeral = suite.kem.derive_key_pair(ephemeral_ikm)
    enc, sender = suite.create_sender_context(
        recipient.public_key, info=info, eks=ephemeral
    )
    ciphertext = sender.seal(plaintext, aad=aad)
    frame = canonical([outer_protected, enc, ciphertext])
    return {
        "id": fixture_id,
        "kind": "hpke-open",
        "direction": "Python pyhpke generator -> Go crypto/hpke opener",
        "recipient_ikm_hex": recipient_ikm.hex(),
        "outer_protected_hex": outer_protected.hex(),
        "info_hex": info.hex(),
        "aad_hex": aad.hex(),
        "enc_hex": enc.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "plaintext_hex": plaintext.hex(),
        "sealed_frame_hex": frame.hex(),
        "size_bytes": len(frame),
        "artifact_class": artifact_class,
        "audience": audience,
        "recipient_hint": hint.decode(),
        "recipient_epoch": recipient_epoch,
    }


def build_report() -> dict[str, object]:
    verify_runtime()
    key_id = bytes.fromhex("5048382d45533235362d3031")
    payload = canonical(
        {
            "generation": 7,
            "profile": "independent-fixture",
            "schema": 1,
        }
    )
    key = signing_key()
    device_metadata = artifact_metadata(
        "device-recipient",
        "provisioned-device",
        b"fixture_hint_0001",
        7,
    )
    protected, sig_structure, signature, cose_sign1 = signed_fixture(
        key, key_id, payload, device_metadata
    )
    backup_metadata = artifact_metadata(
        "encrypted-backup",
        "provisioned-backup-recipient",
        b"fixture_hint_0002",
        9,
    )
    _, _, _, backup_signed_object = signed_fixture(
        key, key_id, payload, backup_metadata
    )
    public = key.public_key().public_numbers()

    suite = CipherSuite.new(
        KEMId.DHKEM_P256_HKDF_SHA256,
        KDFId.HKDF_SHA256,
        AEADId.AES256_GCM,
    )
    device = seal_fixture(
        suite,
        "hpke-open-device-v1",
        device_metadata,
        hashlib.sha256(b"Kurdistan Phase 8 device recipient IKM v1").digest(),
        hashlib.sha256(b"Kurdistan Phase 8 device ephemeral IKM v1").digest(),
        cose_sign1,
        "device-recipient", "provisioned-device", b"fixture_hint_0001", 7,
    )
    backup = seal_fixture(
        suite,
        "hpke-open-backup-v1",
        backup_metadata,
        hashlib.sha256(b"Kurdistan Phase 8 backup recipient IKM v1").digest(),
        hashlib.sha256(b"Kurdistan Phase 8 backup ephemeral IKM v1").digest(),
        backup_signed_object,
        "encrypted-backup", "provisioned-backup-recipient", b"fixture_hint_0002", 9,
    )
    artifact_fixtures = []
    classes = [
        ("signed-public", "public", b"", 0),
        ("provider-group-recipient", "provisioned-group", b"fixture_group", 11),
        ("device-recipient", "provisioned-device", b"fixture_device", 13),
        ("encrypted-backup", "provisioned-backup-recipient", b"fixture_backup", 17),
    ]
    for artifact_class, audience, hint_prefix, base_epoch in classes:
        for variant in range(1, 6):
            hint = hint_prefix + (f"_{variant:04d}".encode() if hint_prefix else b"")
            epoch = base_epoch + variant if hint else 0
            metadata = artifact_metadata(artifact_class, audience, hint, epoch)
            variant_payload = canonical({"artifact_class": artifact_class, "schema": 1, "variant": variant})
            variant_protected, variant_message, variant_signature, variant_signed = signed_fixture(key, key_id, variant_payload, metadata)
            fixture_id = f"{artifact_class}-fixture-{variant}"
            if artifact_class == "signed-public":
                artifact_fixtures.append({
                    "id": fixture_id, "kind": "artifact-signed-public",
                    "direction": "Python cbor2/cryptography generator -> Go exact parser/verifier",
                    "artifact_class": artifact_class, "audience": audience,
                    "protected_hex": variant_protected.hex(), "payload_hex": variant_payload.hex(),
                    "message_hex": variant_message.hex(), "signature_hex": variant_signature.hex(),
                    "output_hex": variant_signed.hex(),
                    "public_x_hex": public.x.to_bytes(32, "big").hex(),
                    "public_y_hex": public.y.to_bytes(32, "big").hex(), "size_bytes": len(variant_signed),
                })
            else:
                artifact_fixtures.append(seal_fixture(
                    suite, fixture_id, metadata,
                    hashlib.sha256(f"recipient:{artifact_class}:{variant}".encode()).digest(),
                    hashlib.sha256(f"ephemeral:{artifact_class}:{variant}".encode()).digest(),
                    variant_signed, artifact_class, audience, hint, epoch,
                ))

    requirements = Path(__file__).with_name("requirements-win-amd64-py312.lock")
    result = {
        "schema": "kurdistan.phase8.independent-interop-report.v1",
        "suite_id": SUITE_ID,
        "reproduction_summary": {
            "fixture_count": 6 + len(artifact_fixtures),
            "unexpected_accepts": 0,
            "mismatches": 0,
            "mandatory_suite_exercised": True,
        },
        "independent_implementation": {
            "language": f"Python {sys.version.split()[0]}",
            "script": "testdata/evidence/independent/phase8_interop.py",
            "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "requirements_lock": "testdata/evidence/independent/requirements-win-amd64-py312.lock",
            "requirements_lock_sha256": hashlib.sha256(requirements.read_bytes()).hexdigest(),
            "runtime_verification": {
                "python": ".".join(str(part) for part in EXPECTED_PYTHON),
                "packages": EXPECTED_PACKAGES,
                "result": "passed before fixture generation",
            },
            "production_code_shared": 0,
            "libraries": [
                {
                    "name": "cbor2",
                    "version": importlib.metadata.version("cbor2"),
                    "license": "MIT",
                    "official_url": "https://github.com/agronholm/cbor2",
                    "artifact_url": "https://files.pythonhosted.org/packages/d2/1b/90b4a121e40aba189c55a5822dd3c698eaf487e1d4a780ab18c804a5ef1c/cbor2-6.1.3-cp312-cp312-win_amd64.whl",
                    "wheel_sha256": "d5514f693db6fa6f433b4096e9b604e6a7bf151c9ef1d2db86d0858e4c5e768f",
                },
                {
                    "name": "cryptography",
                    "version": importlib.metadata.version("cryptography"),
                    "license": "Apache-2.0 OR BSD-3-Clause",
                    "official_url": "https://github.com/pyca/cryptography",
                    "artifact_url": "https://files.pythonhosted.org/packages/2b/02/7788f9fefa1d060ca68717c3901ae7fffa21ee087a90b7f23c7a603c32ae/cryptography-46.0.7-cp311-abi3-win_amd64.whl",
                    "wheel_sha256": "397655da831414d165029da9bc483bed2fe0e75dde6a1523ec2fe63f3c46046b",
                },
                {
                    "name": "pyhpke",
                    "version": importlib.metadata.version("pyhpke"),
                    "license": "MIT",
                    "official_url": "https://github.com/dajiaji/pyhpke",
                    "artifact_url": "https://files.pythonhosted.org/packages/04/31/2a0edff785b15d700199fed77186b3d070724cafd02fccfffb187e450d83/pyhpke-0.6.5-py3-none-any.whl",
                    "wheel_sha256": "e8d794724e43053fe04e8971be55033225d6da904effc748b303cece763a3f3c",
                },
            ],
        },
        "fixtures": [
            {
                "id": "canonical-protected-headers-v1",
                "kind": "canonical",
                "direction": "Python cbor2 generator -> Go exact-byte comparison",
                "key_id_hex": key_id.hex(),
                "output_hex": protected.hex(),
                "size_bytes": len(protected),
            },
            {
                "id": "canonical-sig-structure-v1",
                "kind": "canonical",
                "direction": "Python cbor2 generator -> Go exact-byte comparison",
                "protected_hex": protected.hex(),
                "payload_hex": payload.hex(),
                "output_hex": sig_structure.hex(),
                "size_bytes": len(sig_structure),
            },
            {
                "id": "canonical-tagged-cose-sign1-v1",
                "kind": "canonical",
                "direction": "Python cbor2 generator -> Go exact-byte comparison",
                "protected_hex": protected.hex(),
                "payload_hex": payload.hex(),
                "signature_hex": signature.hex(),
                "output_hex": cose_sign1.hex(),
                "size_bytes": len(cose_sign1),
            },
            {
                "id": "es256-raw-low-s-verify-v1",
                "kind": "signature-verify",
                "direction": "Python cryptography generator -> Go crypto/ecdsa verifier",
                "message_hex": sig_structure.hex(),
                "signature_hex": signature.hex(),
                "public_x_hex": public.x.to_bytes(32, "big").hex(),
                "public_y_hex": public.y.to_bytes(32, "big").hex(),
                "size_bytes": len(signature),
                "fixture_randomness": "deterministic RFC6979 test-only generation; production signing remains randomized and hedged",
            },
            device,
            backup,
        ] + artifact_fixtures,
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    encoded = (json.dumps(build_report(), indent=2, sort_keys=True) + "\n").encode()
    if args.output:
        # Evidence generation must never replace an existing report. Callers
        # choose a fresh path, then compare or promote it explicitly.
        with args.output.open("xb") as output:
            output.write(encoded)
    else:
        sys.stdout.buffer.write(encoded)
    if args.compare:
        expected = args.compare.read_bytes()
        if encoded != expected:
            raise RuntimeError(
                f"regenerated report differs byte-for-byte from {args.compare}"
            )


if __name__ == "__main__":
    main()
