from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Dict, Iterable

deps_dir = Path(__file__).resolve().parents[1] / ".deps"
deps_str = str(deps_dir)
if deps_dir.exists() and deps_str not in sys.path:
    sys.path.insert(0, deps_str)

from pqcrypto.sign import ml_dsa_44
from pqcrypto.sign import ml_dsa_65
from pqcrypto.sign import ml_dsa_87
from pqcrypto.sign import sphincs_sha2_128s_simple
from pqcrypto.sign import sphincs_sha2_192s_simple
from pqcrypto.sign import sphincs_sha2_256s_simple

from algorithms import get_scheme
from firmware_package import FirmwarePackage, SignatureRecord, attach_signature


@dataclass(frozen=True)
class PQCKeyPair:
    scheme_id: str
    public_key: bytes
    secret_key: bytes


@dataclass(frozen=True)
class PQCBackendInfo:
    scheme_id: str
    implementation_label: str

BACKENDS: Dict[str, PQCBackendInfo] = {
    "ml_dsa_44": PQCBackendInfo(
        scheme_id="ml_dsa_44",
        implementation_label="pqcrypto ML-DSA-44",
    ),
    "ml_dsa_65": PQCBackendInfo(
        scheme_id="ml_dsa_65",
        implementation_label="pqcrypto ML-DSA-65",
    ),
    "ml_dsa_87": PQCBackendInfo(
        scheme_id="ml_dsa_87",
        implementation_label="pqcrypto ML-DSA-87",
    ),
    # Some Author notes: pqcrypto still exposes the pre-FIPS SPHINCS+ names. These map directly to the
    # standardized SLH-DSA family used in the paper.
    "slh_dsa_128s": PQCBackendInfo(
        scheme_id="slh_dsa_128s",
        implementation_label="pqcrypto SPHINCS+-SHA2-128s-simple",
    ),
    "slh_dsa_192s": PQCBackendInfo(
        scheme_id="slh_dsa_192s",
        implementation_label="pqcrypto SPHINCS+-SHA2-192s-simple",
    ),
    "slh_dsa_256s": PQCBackendInfo(
        scheme_id="slh_dsa_256s",
        implementation_label="pqcrypto SPHINCS+-SHA2-256s-simple",
    ),
}

BACKEND_MODULES = {
    "ml_dsa_44": ml_dsa_44,
    "ml_dsa_65": ml_dsa_65,
    "ml_dsa_87": ml_dsa_87,
    "slh_dsa_128s": sphincs_sha2_128s_simple,
    "slh_dsa_192s": sphincs_sha2_192s_simple,
    "slh_dsa_256s": sphincs_sha2_256s_simple,
}

def supported_pqc_schemes() -> tuple[str, ...]: return tuple(BACKENDS)
def _backend_module(scheme_id: str):
    if scheme_id not in BACKEND_MODULES:
        raise ValueError(f"Unsupported PQC scheme: {scheme_id}")
    return BACKEND_MODULES[scheme_id]


def backend_label(scheme_id: str) -> str: return BACKENDS[scheme_id].implementation_label
def generate_keypair(scheme_id: str) -> PQCKeyPair:
    module = _backend_module(scheme_id)
    public_key, secret_key = module.generate_keypair()
    _validate_lengths(scheme_id, public_key, secret_key, None)
    return PQCKeyPair(scheme_id=scheme_id, public_key=public_key, secret_key=secret_key)

def sign_message(scheme_id: str, secret_key: bytes, message: bytes) -> bytes:
    module = _backend_module(scheme_id)
    signature = module.sign(secret_key, message)
    _validate_lengths(scheme_id, None, None, signature)
    return signature

def verify_message(scheme_id: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    module = _backend_module(scheme_id)
    try:
        module.verify(public_key, message, signature)
    except Exception:
        return False
    return True

def sign_firmware_package(
    package: FirmwarePackage,
    scheme_id: str,
    keypair: PQCKeyPair,
) -> FirmwarePackage:
    if keypair.scheme_id != scheme_id:
        raise ValueError("Keypair scheme does not match requested signing scheme.")
    signature = sign_message(scheme_id, keypair.secret_key, package.manifest_digest_bytes())
    record = SignatureRecord(
        algorithm_id=scheme_id,
        signature_bytes=len(signature),
        signature_blob=signature,
        public_key=keypair.public_key,
    )
    return attach_signature(package, record)

def verify_firmware_package(package: FirmwarePackage) -> dict[str, bool]:
    results: dict[str, bool] = {}
    digest = package.manifest_digest_bytes()
    for record in package.signatures:
        if record.algorithm_id not in BACKENDS:
            continue
        if record.signature_blob is None or record.public_key is None:
            results[record.algorithm_id] = False
            continue
        results[record.algorithm_id] = verify_message(
            record.algorithm_id,
            record.public_key,
            digest,
            record.signature_blob,
        )
    return results

def summarize_runtime_support() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for scheme_id in supported_pqc_schemes():
        scheme = get_scheme(scheme_id)
        rows.append(
            {
                "scheme_id": scheme_id,
                "standard_name": scheme.name,
                "backend": backend_label(scheme_id),
                "public_key_bytes": str(scheme.public_key_bytes),
                "private_key_bytes": str(scheme.private_key_bytes),
                "signature_bytes": str(scheme.signature_bytes),
            }
        )
    return rows

def _validate_lengths(
    scheme_id: str,
    public_key: bytes | None,
    secret_key: bytes | None,
    signature: bytes | None,
) -> None:
    scheme = get_scheme(scheme_id)
    if public_key is not None and len(public_key) != scheme.public_key_bytes:
        raise ValueError(
            f"Unexpected public key size for {scheme_id}: {len(public_key)} != {scheme.public_key_bytes}"
        )
    if secret_key is not None and len(secret_key) != scheme.private_key_bytes:
        raise ValueError(
            f"Unexpected private key size for {scheme_id}: {len(secret_key)} != {scheme.private_key_bytes}"
        )
    if signature is not None and len(signature) != scheme.signature_bytes:
        raise ValueError(
            f"Unexpected signature size for {scheme_id}: {len(signature)} != {scheme.signature_bytes}"
        )