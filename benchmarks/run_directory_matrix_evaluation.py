#!/usr/bin/env python3
"""Run GitVault directory-count and total-dataset-size experiments.

The directory-count cases hold file count, file size, and total bytes fixed
while changing smallfile's files-per-directory setting. The dataset-size cases
hold file count and directory layout fixed while changing file size. Each case
delegates to run_single_client_load_evaluation.py, so Dropbox, Nostr R=2/W=2,
single-replica execution, failure capture, and cleanup behavior stay identical.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
import subprocess
import sys


OPERATIONS = [
    "init",
    "status",
    "list",
    "tree",
    "cat",
    "quick-scan",
    "deep-scan",
]


def read_single_row(path: Path) -> dict[str, str]:
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != 1:
        raise RuntimeError(f"expected exactly one row in {path}, got {len(rows)}")
    return rows[0]


def read_scale_summary(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    return {row["operation"]: row for row in rows}


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    fields = [
        "experiment",
        "case",
        "requested_files",
        "actual_directories",
        "file_size_kib",
        "dataset_bytes",
        "retry_events",
        "successful_commands",
        "attempted_commands",
        *[f"{operation}_ms" for operation in OPERATIONS],
    ]
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="./build-release/gitvault")
    parser.add_argument("--smallfile-script", required=True)
    parser.add_argument("--base-runner", default=None)
    parser.add_argument("--output", required=True)
    parser.add_argument("--relay", action="append", required=True)
    parser.add_argument("--seed", type=int, default=20260817)
    args = parser.parse_args()

    if len(args.relay) != 3:
        parser.error("exactly three --relay options are required")

    base_runner = (
        Path(args.base_runner).resolve()
        if args.base_runner
        else Path(__file__).with_name("run_single_client_load_evaluation.py")
    )
    if not base_runner.is_file():
        parser.error(f"base runner not found: {base_runner}")

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)

    cases = [
        {
            "experiment": "directory-count",
            "case": "dirs-low",
            "files": 20,
            "file_size_kib": 8,
            "files_per_dir": 20,
        },
        {
            "experiment": "directory-count",
            "case": "dirs-medium",
            "files": 20,
            "file_size_kib": 8,
            "files_per_dir": 5,
        },
        {
            "experiment": "directory-count",
            "case": "dirs-high",
            "files": 20,
            "file_size_kib": 8,
            "files_per_dir": 1,
        },
        {
            "experiment": "dataset-size",
            "case": "size-80kib",
            "files": 10,
            "file_size_kib": 8,
            "files_per_dir": 10,
        },
        {
            "experiment": "dataset-size",
            "case": "size-2.5mib",
            "files": 10,
            "file_size_kib": 256,
            "files_per_dir": 10,
        },
        {
            "experiment": "dataset-size",
            "case": "size-40mib",
            "files": 10,
            "file_size_kib": 4096,
            "files_per_dir": 10,
        },
    ]

    aggregate_rows: list[dict[str, object]] = []
    for index, case in enumerate(cases, start=1):
        case_name = str(case["case"])
        case_output = output / case_name
        command = [
            sys.executable,
            str(base_runner),
            "--binary",
            str(Path(args.binary).resolve()),
            "--smallfile-script",
            str(Path(args.smallfile_script).resolve()),
            "--output",
            str(case_output),
            "--file-counts",
            str(case["files"]),
            "--file-size-kib",
            str(case["file_size_kib"]),
            "--files-per-dir",
            str(case["files_per_dir"]),
            "--dirs-per-dir",
            "10",
            "--read-samples",
            "1",
            "--workload-operations",
            "0",
            "--seed",
            str(args.seed),
        ]
        for relay in args.relay:
            command.extend(["--relay", relay])

        print(
            f"[{index}/{len(cases)}] {case_name}: "
            f"files={case['files']} size_kib={case['file_size_kib']} "
            f"files_per_dir={case['files_per_dir']}",
            flush=True,
        )
        completed = subprocess.run(command, text=True, check=False)
        if completed.returncode != 0:
            raise RuntimeError(f"case failed: {case_name}; see {case_output}")

        dataset = read_single_row(case_output / "datasets.csv")
        operations = read_scale_summary(case_output / "scale_summary.csv")
        scale_rows = [
            row for row in operations.values() if row["operation"] in OPERATIONS
        ]
        log_text = (case_output / "commands.log").read_text(encoding="utf-8")
        aggregate: dict[str, object] = {
            "experiment": case["experiment"],
            "case": case_name,
            "requested_files": dataset["actual_files"],
            "actual_directories": dataset["directories"],
            "file_size_kib": case["file_size_kib"],
            "dataset_bytes": dataset["dataset_bytes"],
            "retry_events": log_text.count(
                "Conditional upload rate limited; retrying after"
            ),
            "successful_commands": sum(
                int(row["successes"]) for row in scale_rows
            ),
            "attempted_commands": sum(int(row["n"]) for row in scale_rows),
        }
        for operation in OPERATIONS:
            aggregate[f"{operation}_ms"] = operations.get(operation, {}).get(
                "median_ms", ""
            )
        aggregate_rows.append(aggregate)
        write_csv(output / "matrix_summary.csv", aggregate_rows)

    print(output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"matrix benchmark error: {error}", file=sys.stderr)
        raise SystemExit(1)
