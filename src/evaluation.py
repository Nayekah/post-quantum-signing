import csv
from pathlib import Path
from statistics import mean
from time import perf_counter
from typing import Dict, Iterable, List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from algorithms import get_scheme, hybrid_signature_bytes
from policy import evaluate_policy, policy_names
from pqc_signatures import generate_keypair, sign_message, verify_firmware_package, verify_message
from scenarios import policy_scenarios

FIRMWARE_SIZES = [64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024]
METADATA_BYTES = 256
HASH_BYTES = 32
PQC_BENCHMARK_SCHEMES = ("ml_dsa_44", "slh_dsa_128s")
PQC_BENCHMARK_TRIALS = 3

def signature_overhead_percent(signature_bytes: int, firmware_size: int) -> float: return 100.0 * signature_bytes / firmware_size
def bootloader_staging_bytes(public_key_bytes: int, signature_bytes: int) -> int: return public_key_bytes + signature_bytes + METADATA_BYTES + HASH_BYTES

def algorithm_rows() -> List[Dict[str, str]]:
    ordered = [
        "rsa_pss_2048",
        "ecdsa_p256",
        "ml_dsa_44",
        "ml_dsa_65",
        "ml_dsa_87",
        "slh_dsa_128s",
        "slh_dsa_192s",
        "slh_dsa_256s",
    ]
    rows: List[Dict[str, str]] = []
    for identifier in ordered:
        scheme = get_scheme(identifier)
        row = {
            "scheme": scheme.name,
            "family": scheme.family,
            "public_key_bytes": str(scheme.public_key_bytes),
            "private_key_bytes": str(scheme.private_key_bytes),
            "signature_bytes": str(scheme.signature_bytes),
            "bootloader_staging_bytes": str(
                bootloader_staging_bytes(scheme.public_key_bytes, scheme.signature_bytes)
            ),
            "security_basis": scheme.security_basis,
            "verifier_profile": scheme.verifier_profile,
        }
        rows.append(row)
    return rows

def overhead_rows() -> List[Dict[str, str]]:
    entries = [
        ("ECDSA P-256", get_scheme("ecdsa_p256").signature_bytes),
        ("RSA-PSS-2048", get_scheme("rsa_pss_2048").signature_bytes),
        ("ML-DSA-44", get_scheme("ml_dsa_44").signature_bytes),
        ("ML-DSA-65", get_scheme("ml_dsa_65").signature_bytes),
        ("SLH-DSA-SHA2-128s", get_scheme("slh_dsa_128s").signature_bytes),
        ("ECDSA + ML-DSA-44", hybrid_signature_bytes("ecdsa_p256", "ml_dsa_44")),
        ("ECDSA + SLH-DSA-128s", hybrid_signature_bytes("ecdsa_p256", "slh_dsa_128s")),
    ]
    rows: List[Dict[str, str]] = []
    for scheme_name, signature_bytes in entries:
        row: Dict[str, str] = {
            "scheme": scheme_name,
            "signature_bytes": str(signature_bytes),
        }
        for firmware_size in FIRMWARE_SIZES:
            key = f"overhead_{firmware_size}_bytes_percent"
            row[key] = f"{signature_overhead_percent(signature_bytes, firmware_size):.4f}"
        rows.append(row)
    return rows

def policy_rows() -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for scenario in policy_scenarios():
        row: Dict[str, str] = {
            "scenario": scenario.name,
            "firmware_version": str(scenario.package.metadata.firmware_version),
            "bootloader_version": str(scenario.device_state.bootloader_version),
            "signed_algorithms": ",".join(
                record.algorithm_id for record in scenario.package.signatures
            ),
            "verified_pqc_algorithms": ",".join(
                algorithm_id
                for algorithm_id, verified in verify_firmware_package(scenario.package).items()
                if verified
            ),
        }
        for policy in policy_names():
            row[policy.value] = "accept" if evaluate_policy(scenario.package, scenario.device_state, policy) else "reject"
        row["rationale"] = scenario.rationale
        rows.append(row)
    return rows

def pqc_benchmark_rows(trials: int = PQC_BENCHMARK_TRIALS) -> List[Dict[str, str]]:
    benchmark_message = b"post-quantum firmware signing benchmark message"
    rows: List[Dict[str, str]] = []

    for scheme_id in PQC_BENCHMARK_SCHEMES:
        keygen_samples_ms: List[float] = []
        sign_samples_ms: List[float] = []
        verify_samples_ms: List[float] = []
        public_key_bytes = 0
        private_key_bytes = 0
        signature_bytes = 0

        for _ in range(trials):
            start = perf_counter()
            keypair = generate_keypair(scheme_id)
            keygen_samples_ms.append((perf_counter() - start) * 1000.0)

            public_key_bytes = len(keypair.public_key)
            private_key_bytes = len(keypair.secret_key)

            start = perf_counter()
            signature = sign_message(scheme_id, keypair.secret_key, benchmark_message)
            sign_samples_ms.append((perf_counter() - start) * 1000.0)

            signature_bytes = len(signature)

            start = perf_counter()
            verified = verify_message(scheme_id, keypair.public_key, benchmark_message, signature)
            verify_samples_ms.append((perf_counter() - start) * 1000.0)

            if not verified:
                raise ValueError(f"Benchmark verification failed for {scheme_id}")

        rows.append(
            {
                "scheme": get_scheme(scheme_id).name,
                "trials": str(trials),
                "message_bytes": str(len(benchmark_message)),
                "public_key_bytes": str(public_key_bytes),
                "private_key_bytes": str(private_key_bytes),
                "signature_bytes": str(signature_bytes),
                "mean_keygen_ms": f"{mean(keygen_samples_ms):.3f}",
                "mean_sign_ms": f"{mean(sign_samples_ms):.3f}",
                "mean_verify_ms": f"{mean(verify_samples_ms):.3f}",
            }
        )

    return rows

def write_csv(path: Path, rows: Iterable[Dict[str, str]]) -> None:
    rows = list(rows)
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

def generate_overhead_plot(path: Path) -> None:
    rows = overhead_rows()
    x_values_kb = [size // 1024 for size in FIRMWARE_SIZES]
    selected_schemes = {
        "ECDSA P-256": {"color": "#1f77b4", "marker": "o"},
        "ML-DSA-44": {"color": "#d62728", "marker": "s"},
        "SLH-DSA-SHA2-128s": {"color": "#2ca02c", "marker": "^"},
    }

    fig, ax = plt.subplots(figsize=(7.2, 4.0))
    for row in rows:
        scheme = row["scheme"]
        if scheme not in selected_schemes:
            continue
        y_values = [
            float(row[f"overhead_{firmware_size}_bytes_percent"])
            for firmware_size in FIRMWARE_SIZES
        ]
        style = selected_schemes[scheme]
        ax.plot(
            x_values_kb,
            y_values,
            label=scheme,
            color=style["color"],
            marker=style["marker"],
            linewidth=2.0,
            markersize=6,
        )

    ax.set_xscale("log", base=2)
    ax.set_xlabel("Firmware Size (KB)")
    ax.set_ylabel("Signature Overhead (%)")
    ax.set_xticks(x_values_kb, labels=[str(value) for value in x_values_kb])
    ax.grid(True, which="both", linestyle="--", linewidth=0.6, alpha=0.5)
    ax.legend(frameon=False)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=200)
    plt.close(fig)

def generate_runtime_plot(path: Path) -> None:
    rows = pqc_benchmark_rows()
    schemes = [row["scheme"] for row in rows]
    keygen_values = [float(row["mean_keygen_ms"]) for row in rows]
    sign_values = [float(row["mean_sign_ms"]) for row in rows]
    verify_values = [float(row["mean_verify_ms"]) for row in rows]

    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    x_positions = range(len(schemes))
    width = 0.24

    ax.bar([x - width for x in x_positions], keygen_values, width=width, label="KeyGen", color="#1f77b4")
    ax.bar(list(x_positions), sign_values, width=width, label="Sign", color="#d62728")
    ax.bar([x + width for x in x_positions], verify_values, width=width, label="Verify", color="#2ca02c")

    ax.set_yscale("log")
    ax.set_ylabel("Latency (ms, log scale)")
    ax.set_xticks(list(x_positions), labels=schemes)
    ax.grid(True, axis="y", which="both", linestyle="--", linewidth=0.6, alpha=0.5)
    ax.legend(frameon=False)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=200)
    plt.close(fig)