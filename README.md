# Post-Quantum Signing

Implementation for the paper:

**A Comparative Study of ML-DSA and SLH-DSA for Post-Quantum Firmware Signing in Secure Firmware Updates**

## Requirements

- Python 3.12 or newer is recommended

Python dependencies:

```text
pqcrypto==0.4.0
matplotlib==3.8.4
```

## Setup

From the repository root, install dependencies into the local `.deps` directory:

```powershell
py -3.12 -m pip install --target .deps -r requirements.txt
```

## Running the Prototype

Run the end-to-end PQC signing demo:

```powershell
py -3.12 src/pqc_demo.py
```

Generate the evaluation tables and plots used by the paper:

```powershell
py -3.12 src/generate_tables.py
```

Outputs:
- `paper/data/algorithm_comparison.csv`
- `paper/data/firmware_overhead.csv`
- `paper/data/policy_outcomes.csv`
- `paper/data/pqc_runtime_benchmarks.csv`
- `images/firmware_overhead_plot.png`
- `images/pqc_runtime_plot.png`

## Citation

If you use this repository, please cite the accompanying paper.

Suggested BibTeX entry:

```bibtex
@misc{subrata2026postquantumsigning,
  author       = {Nayaka Ghana Subrata},
  title        = {A Comparative Study of ML-DSA and SLH-DSA for Post-Quantum Firmware Signing in Secure Firmware Updates},
  year         = {2026},
  howpublished = {\url{https://github.com/Nayekah/post-quantum-signing}},
  note         = {Cryptography paper, Institut Teknologi Bandung}
}
```

## Contact

If you have any questions related to this implementation, please contact:

- Nayaka Ghana Subrata â€” `13523090@std.stei.itb.ac.id`
- Nayaka Ghana Subrata â€” `nayakaghana39@gmail.com`

## Notes

- The local PQC backend uses `pqcrypto` loaded from the repository-local `.deps` directory.
- The prototype is intended for study, evaluation, and experimentation with migration-aware firmware-signing policies.
