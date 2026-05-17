from dataclasses import dataclass, field, replace
from hashlib import sha256
from typing import Iterable, List


@dataclass(frozen=True)
class SignatureRecord:
    algorithm_id: str
    signature_bytes: int
    signature_blob: bytes | None = None
    public_key: bytes | None = None


@dataclass(frozen=True)
class FirmwareMetadata:
    device_id: str
    vendor_id: str
    firmware_version: int
    minimum_bootloader_version: int
    policy_version: int
    release_timestamp: str
    firmware_size: int
    firmware_hash_hex: str
    accepted_algorithms: tuple[str, ...]

    def canonical_fields(self) -> List[str]:
        return [
            self.device_id,
            self.vendor_id,
            str(self.firmware_version),
            str(self.minimum_bootloader_version),
            str(self.policy_version),
            self.release_timestamp,
            str(self.firmware_size),
            self.firmware_hash_hex,
            ",".join(self.accepted_algorithms),
        ]

    def canonical_bytes(self) -> bytes:
        return "|".join(self.canonical_fields()).encode("utf-8")


@dataclass(frozen=True)
class FirmwarePackage:
    metadata: FirmwareMetadata
    firmware_payload: bytes
    signatures: tuple[SignatureRecord, ...] = field(default_factory=tuple)

    def signed_material(self) -> bytes:
        return self.metadata.canonical_bytes() + self.firmware_payload

    def manifest_digest_bytes(self) -> bytes:
        return sha256(self.signed_material()).digest()

    def manifest_digest_hex(self) -> str:
        return self.manifest_digest_bytes().hex()

    def with_signature(self, record: SignatureRecord) -> "FirmwarePackage":
        return replace(self, signatures=self.signatures + (record,))

def build_metadata(
    *,
    device_id: str,
    vendor_id: str,
    firmware_version: int,
    minimum_bootloader_version: int,
    policy_version: int,
    release_timestamp: str,
    firmware_payload: bytes,
    accepted_algorithms: Iterable[str],
) -> FirmwareMetadata:
    firmware_hash_hex = sha256(firmware_payload).hexdigest()
    return FirmwareMetadata(
        device_id=device_id,
        vendor_id=vendor_id,
        firmware_version=firmware_version,
        minimum_bootloader_version=minimum_bootloader_version,
        policy_version=policy_version,
        release_timestamp=release_timestamp,
        firmware_size=len(firmware_payload),
        firmware_hash_hex=firmware_hash_hex,
        accepted_algorithms=tuple(accepted_algorithms),
    )

def attach_signature(package: FirmwarePackage, record: SignatureRecord) -> FirmwarePackage: return package.with_signature(record)