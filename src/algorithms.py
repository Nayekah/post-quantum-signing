from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class SignatureScheme:
    name: str
    family: str
    public_key_bytes: int
    private_key_bytes: int
    signature_bytes: int
    quantum_safe: bool
    security_basis: str
    verifier_profile: str
    deployment_note: str

SCHEMES: Dict[str, SignatureScheme] = {
    "rsa_pss_2048": SignatureScheme(
        name="RSA-PSS-2048",
        family="classical",
        public_key_bytes=256,
        private_key_bytes=1190,
        signature_bytes=256,
        quantum_safe=False,
        security_basis="Integer factorization",
        verifier_profile="mature, moderate code size",
        deployment_note="Baseline widely used in legacy firmware manifests.",
    ),
    "ecdsa_p256": SignatureScheme(
        name="ECDSA P-256",
        family="classical",
        public_key_bytes=64,
        private_key_bytes=32,
        signature_bytes=64,
        quantum_safe=False,
        security_basis="Elliptic-curve discrete logarithm",
        verifier_profile="small signature, mature embedded support",
        deployment_note="Representative raw x||y public key and raw r||s signature.",
    ),
    "ml_dsa_44": SignatureScheme(
        name="ML-DSA-44",
        family="post-quantum",
        public_key_bytes=1312,
        private_key_bytes=2560,
        signature_bytes=2420,
        quantum_safe=True,
        security_basis="Module-LWE / SelfTargetMSIS",
        verifier_profile="practical default for general-purpose PQ signing",
        deployment_note="Primary PQ candidate with comparatively compact signatures.",
    ),
    "ml_dsa_65": SignatureScheme(
        name="ML-DSA-65",
        family="post-quantum",
        public_key_bytes=1952,
        private_key_bytes=4032,
        signature_bytes=3309,
        quantum_safe=True,
        security_basis="Module-LWE / SelfTargetMSIS",
        verifier_profile="higher strength, moderate footprint growth",
        deployment_note="Suitable when policy requires a stronger margin than ML-DSA-44.",
    ),
    "ml_dsa_87": SignatureScheme(
        name="ML-DSA-87",
        family="post-quantum",
        public_key_bytes=2592,
        private_key_bytes=4896,
        signature_bytes=4627,
        quantum_safe=True,
        security_basis="Module-LWE / SelfTargetMSIS",
        verifier_profile="largest ML-DSA profile in the standard",
        deployment_note="Intended for the highest standardized ML-DSA security category.",
    ),
    "slh_dsa_128s": SignatureScheme(
        name="SLH-DSA-SHA2-128s",
        family="post-quantum",
        public_key_bytes=32,
        private_key_bytes=64,
        signature_bytes=7856,
        quantum_safe=True,
        security_basis="Hash-based stateless hypertrees",
        verifier_profile="tiny public key, very large signature",
        deployment_note="Conservative backup candidate with small-signature parameter set.",
    ),
    "slh_dsa_192s": SignatureScheme(
        name="SLH-DSA-SHA2-192s",
        family="post-quantum",
        public_key_bytes=48,
        private_key_bytes=96,
        signature_bytes=16224,
        quantum_safe=True,
        security_basis="Hash-based stateless hypertrees",
        verifier_profile="larger signature than category-1 style set",
        deployment_note="Higher security category with substantial package expansion.",
    ),
    "slh_dsa_256s": SignatureScheme(
        name="SLH-DSA-SHA2-256s",
        family="post-quantum",
        public_key_bytes=64,
        private_key_bytes=128,
        signature_bytes=29792,
        quantum_safe=True,
        security_basis="Hash-based stateless hypertrees",
        verifier_profile="extreme signature footprint for constrained firmware",
        deployment_note="Mostly appropriate only when conservative assumptions dominate size cost.",
    ),
}

def get_scheme(identifier: str) -> SignatureScheme: return SCHEMES[identifier]
def hybrid_signature_bytes(*identifiers: str) -> int: return sum(get_scheme(identifier).signature_bytes for identifier in identifiers)