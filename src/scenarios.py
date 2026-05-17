from dataclasses import dataclass
from typing import Tuple

from firmware_package import FirmwarePackage, SignatureRecord, attach_signature, build_metadata
from policy import DeviceState
from pqc_signatures import PQCKeyPair, generate_keypair, sign_firmware_package


@dataclass(frozen=True)
class PolicyScenario:
    name: str
    package: FirmwarePackage
    device_state: DeviceState
    rationale: str


_PQC_KEY_CACHE: dict[str, PQCKeyPair] = {}

def _payload(size: int, seed: int) -> bytes: return bytes((seed + index) % 251 for index in range(size))
def _keypair_for(scheme_id: str) -> PQCKeyPair:
    if scheme_id not in _PQC_KEY_CACHE:
        _PQC_KEY_CACHE[scheme_id] = generate_keypair(scheme_id)
    return _PQC_KEY_CACHE[scheme_id]

def _package(
    *,
    device_id: str,
    firmware_version: int,
    minimum_bootloader_version: int,
    policy_version: int,
    signature_algorithms: Tuple[str, ...],
    payload_seed: int,
    override_declared_algorithms: Tuple[str, ...] | None = None,
) -> FirmwarePackage:
    firmware_payload = _payload(4096, payload_seed)
    metadata = build_metadata(
        device_id=device_id,
        vendor_id="ITB-LAB",
        firmware_version=firmware_version,
        minimum_bootloader_version=minimum_bootloader_version,
        policy_version=policy_version,
        release_timestamp="2026-05-16T09:00:00Z",
        firmware_payload=firmware_payload,
        accepted_algorithms=override_declared_algorithms or signature_algorithms,
    )
    package = FirmwarePackage(metadata=metadata, firmware_payload=firmware_payload)

    for algorithm_id in signature_algorithms:
        if algorithm_id.startswith("ml_dsa") or algorithm_id.startswith("slh_dsa"):
            package = sign_firmware_package(package, algorithm_id, _keypair_for(algorithm_id))
        else:
            package = attach_signature(
                package,
                SignatureRecord(algorithm_id=algorithm_id, signature_bytes=0),
            )

    return package

def policy_scenarios() -> tuple[PolicyScenario, ...]:
    legacy_state = DeviceState(
        device_id="sensor-a",
        bootloader_version=2,
        minimum_allowed_firmware_version=5,
        migration_policy_version=2,
    )
    migrated_state = DeviceState(
        device_id="sensor-a",
        bootloader_version=3,
        minimum_allowed_firmware_version=8,
        migration_policy_version=3,
    )

    return (
        PolicyScenario(
            name="Legacy classical package before migration",
            package=_package(
                device_id="sensor-a",
                firmware_version=7,
                minimum_bootloader_version=2,
                policy_version=2,
                signature_algorithms=("ecdsa_p256",),
                payload_seed=11,
            ),
            device_state=legacy_state,
            rationale="Classical verification is still the active policy for pre-migration devices.",
        ),
        PolicyScenario(
            name="PQC-only package after migration",
            package=_package(
                device_id="sensor-a",
                firmware_version=9,
                minimum_bootloader_version=3,
                policy_version=3,
                signature_algorithms=("ml_dsa_44",),
                payload_seed=23,
            ),
            device_state=migrated_state,
            rationale="Post-migration bootloaders should accept authenticated PQ firmware.",
        ),
        PolicyScenario(
            name="Classical-only package after migration",
            package=_package(
                device_id="sensor-a",
                firmware_version=9,
                minimum_bootloader_version=3,
                policy_version=3,
                signature_algorithms=("ecdsa_p256",),
                payload_seed=31,
            ),
            device_state=migrated_state,
            rationale="Either-valid still accepts this package, which models downgrade exposure.",
        ),
        PolicyScenario(
            name="Dual-signed package after migration",
            package=_package(
                device_id="sensor-a",
                firmware_version=9,
                minimum_bootloader_version=3,
                policy_version=3,
                signature_algorithms=("ecdsa_p256", "ml_dsa_44"),
                payload_seed=41,
            ),
            device_state=migrated_state,
            rationale="Both classical and PQ signatures are present for a controlled transition.",
        ),
        PolicyScenario(
            name="Tampered algorithm declaration",
            package=_package(
                device_id="sensor-a",
                firmware_version=9,
                minimum_bootloader_version=3,
                policy_version=3,
                signature_algorithms=("ml_dsa_44",),
                override_declared_algorithms=("ecdsa_p256",),
                payload_seed=53,
            ),
            device_state=migrated_state,
            rationale="Signed metadata and actual signature set disagree, so the package is rejected.",
        ),
        PolicyScenario(
            name="Rollback firmware package",
            package=_package(
                device_id="sensor-a",
                firmware_version=6,
                minimum_bootloader_version=2,
                policy_version=2,
                signature_algorithms=("ecdsa_p256",),
                payload_seed=61,
            ),
            device_state=migrated_state,
            rationale="The version counter blocks reinstallation of older authenticated firmware.",
        ),
    )