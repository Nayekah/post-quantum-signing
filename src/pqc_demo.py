from firmware_package import build_metadata, FirmwarePackage
from pqc_signatures import generate_keypair, sign_firmware_package, verify_firmware_package

def _demo_package() -> FirmwarePackage:
    firmware_payload = bytes((17 + idx) % 251 for idx in range(2048))
    metadata = build_metadata(
        device_id="sensor-a",
        vendor_id="ITB-LAB",
        firmware_version=9,
        minimum_bootloader_version=3,
        policy_version=3,
        release_timestamp="2026-05-16T09:00:00Z",
        firmware_payload=firmware_payload,
        accepted_algorithms=("ml_dsa_44", "slh_dsa_128s"),
    )
    return FirmwarePackage(metadata=metadata, firmware_payload=firmware_payload)

def main() -> None:
    package = _demo_package()
    ml_keypair = generate_keypair("ml_dsa_44")
    slh_keypair = generate_keypair("slh_dsa_128s")

    package = sign_firmware_package(package, "ml_dsa_44", ml_keypair)
    package = sign_firmware_package(package, "slh_dsa_128s", slh_keypair)

    verification = verify_firmware_package(package)
    print("manifest_digest_hex", package.manifest_digest_hex())
    print("signature_algorithms", [record.algorithm_id for record in package.signatures])
    print("verification", verification)

if __name__ == "__main__":
    main()