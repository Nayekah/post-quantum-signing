from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Set

from firmware_package import FirmwarePackage
from pqc_signatures import verify_firmware_package


class VerificationPolicy(str, Enum):
    CLASSICAL_ONLY = "classical_only"
    PQC_ONLY = "pqc_only"
    EITHER_VALID = "either_valid"
    BOTH_REQUIRED = "both_required"
    VERSION_GATED = "version_gated"

CLASSICAL_ALGS = {"rsa_pss_2048", "ecdsa_p256"}
PQC_ALGS = {
    "ml_dsa_44",
    "ml_dsa_65",
    "ml_dsa_87",
    "slh_dsa_128s",
    "slh_dsa_192s",
    "slh_dsa_256s",
}


@dataclass(frozen=True)
class DeviceState:
    device_id: str
    bootloader_version: int
    minimum_allowed_firmware_version: int
    migration_policy_version: int


def _signature_algorithms(package: FirmwarePackage) -> Set[str]: return {record.algorithm_id for record in package.signatures}
def _has_classical(package: FirmwarePackage) -> bool: return bool(_signature_algorithms(package) & CLASSICAL_ALGS)
def _has_pqc(package: FirmwarePackage) -> bool: return bool(_verified_pqc_algorithms(package))

def _verified_pqc_algorithms(package: FirmwarePackage) -> Set[str]:
    verification = verify_firmware_package(package)
    return {
        algorithm_id
        for algorithm_id, verified in verification.items()
        if verified and algorithm_id in PQC_ALGS
    }

def _metadata_consistent(package: FirmwarePackage, device_state: DeviceState) -> bool:
    metadata = package.metadata
    if metadata.device_id != device_state.device_id:
        return False
    if metadata.firmware_version < device_state.minimum_allowed_firmware_version:
        return False
    if metadata.minimum_bootloader_version > device_state.bootloader_version:
        return False
    if metadata.policy_version < device_state.migration_policy_version:
        return False
    declared = set(metadata.accepted_algorithms)
    actual = _signature_algorithms(package)
    return actual.issubset(declared)

def evaluate_policy(
    package: FirmwarePackage,
    device_state: DeviceState,
    policy: VerificationPolicy,
) -> bool:
    if not _metadata_consistent(package, device_state):
        return False

    has_classical = _has_classical(package)
    has_pqc = _has_pqc(package)

    if policy == VerificationPolicy.CLASSICAL_ONLY:
        return has_classical
    if policy == VerificationPolicy.PQC_ONLY:
        return has_pqc
    if policy == VerificationPolicy.EITHER_VALID:
        return has_classical or has_pqc
    if policy == VerificationPolicy.BOTH_REQUIRED:
        return has_classical and has_pqc
    if policy == VerificationPolicy.VERSION_GATED:
        if package.metadata.firmware_version >= 8 or device_state.bootloader_version >= 3:
            return has_pqc and package.metadata.policy_version >= 3
        return has_classical
    raise ValueError(f"Unsupported policy: {policy}")

def policy_names() -> Iterable[VerificationPolicy]: return tuple(VerificationPolicy)