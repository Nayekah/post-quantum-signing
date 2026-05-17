from pathlib import Path

from evaluation import (
    algorithm_rows,
    generate_overhead_plot,
    generate_runtime_plot,
    overhead_rows,
    policy_rows,
    pqc_benchmark_rows,
    write_csv,
)

def main() -> None:
    base_dir = Path(__file__).resolve().parents[1] / "paper" / "data"
    image_dir = Path(__file__).resolve().parents[1] / "images"
    write_csv(base_dir / "algorithm_comparison.csv", algorithm_rows())
    write_csv(base_dir / "firmware_overhead.csv", overhead_rows())
    write_csv(base_dir / "policy_outcomes.csv", policy_rows())
    write_csv(base_dir / "pqc_runtime_benchmarks.csv", pqc_benchmark_rows())
    generate_overhead_plot(image_dir / "firmware_overhead_plot.png")
    generate_runtime_plot(image_dir / "pqc_runtime_plot.png")
    print(f"Wrote CSV tables to {base_dir}")

if __name__ == "__main__":
    main()