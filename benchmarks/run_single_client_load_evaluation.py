#!/usr/bin/env python3
"""Run a single-replica GitVault scale and sustained-load evaluation.

smallfile generates reproducible metadata-heavy input trees. GitVault then
imports each tree and measures read, metadata, and scan operations with its
normal Dropbox and Nostr R=2/W=2 protocol enabled. On the largest tree, the
runner additionally executes sequential workloads modeled after YCSB A, B,
and C. This deliberately uses one GitVault replica and one outstanding command
at a time; it measures scale and sustained use without multi-replica races.

The runner creates uniquely named Dropbox Vaults and removes them, along with
their local metadata, in a finally block. Public Nostr events are not deletable.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
from pathlib import Path
import platform
import random
import re
import secrets
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any


TRACE = re.compile(r"GITVAULT_BENCH phase=([^ ]+) ms=([0-9.]+)")
WORKLOAD_UPDATE_RATIOS = {
    "ycsb-c": 0.0,
    "ycsb-b": 0.05,
    "ycsb-a": 0.5,
}


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def parse_positive_ints(value: str) -> list[int]:
    try:
        parsed = [int(item.strip()) for item in value.split(",") if item.strip()]
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected comma-separated integers") from error
    if not parsed or any(item < 1 for item in parsed):
        raise argparse.ArgumentTypeError("all values must be positive integers")
    if len(set(parsed)) != len(parsed):
        raise argparse.ArgumentTypeError("values must not be repeated")
    return parsed


def classify_error(stderr: str) -> str:
    lowered = stderr.lower()
    if "http 429" in lowered or "too_many" in lowered:
        return "dropbox_rate_limit"
    if "another gitvault process" in lowered:
        return "local_process_lock"
    if "cas conflict" in lowered:
        return "dropbox_cas_conflict"
    if "quorum" in lowered or "r=2" in lowered or "w=2" in lowered:
        return "nostr_quorum"
    if "timeout" in lowered or "timed out" in lowered:
        return "timeout"
    if "network/tls" in lowered or "network error" in lowered:
        return "network_tls"
    return "other"


def git_revision_for_script(script: Path) -> str | None:
    current = script.parent.resolve()
    for candidate in (current, *current.parents):
        if not (candidate / ".git").exists():
            continue
        completed = subprocess.run(
            ["git", "-C", str(candidate), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode == 0:
            return completed.stdout.strip()
    return None


def read_smallfile_result(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        document = json.load(stream)
    return dict(document.get("results", {}))


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="./build-release/gitvault")
    parser.add_argument("--smallfile-script", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--relay", action="append", required=True)
    parser.add_argument("--file-counts", type=parse_positive_ints, default=[10, 100])
    parser.add_argument("--file-size-kib", type=int, default=8)
    parser.add_argument("--files-per-dir", type=int, default=100)
    parser.add_argument("--dirs-per-dir", type=int, default=10)
    parser.add_argument("--read-samples", type=int, default=3)
    parser.add_argument("--workload-operations", type=int, default=20)
    parser.add_argument(
        "--workload",
        action="append",
        choices=sorted(WORKLOAD_UPDATE_RATIOS),
        help="default: ycsb-c, ycsb-b, ycsb-a",
    )
    parser.add_argument("--seed", type=int, default=20260817)
    args = parser.parse_args()

    if len(args.relay) != 3:
        parser.error("exactly three --relay options are required")
    if args.file_size_kib < 1 or args.files_per_dir < 1 or args.dirs_per_dir < 1:
        parser.error("file and directory sizing values must be positive")
    if args.read_samples < 1 or args.workload_operations < 0:
        parser.error("read samples must be positive and workload operations non-negative")

    binary = Path(args.binary).resolve()
    smallfile_script = Path(args.smallfile_script).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error(f"GitVault binary is not executable: {binary}")
    if not smallfile_script.is_file():
        parser.error(f"smallfile script not found: {smallfile_script}")

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    log_path = output / "commands.log"
    password = "gitvault-load-evaluation-" + secrets.token_hex(12)
    suffix = (
        dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S")
        + "-"
        + secrets.token_hex(3)
    )
    workloads = args.workload or ["ycsb-c", "ycsb-b", "ycsb-a"]
    randomizer = random.Random(args.seed)
    environment = os.environ.copy()
    environment["GITVAULT_BENCHMARK_TRACE"] = "1"

    command_rows: list[dict[str, object]] = []
    phase_rows: list[dict[str, object]] = []
    dataset_rows: list[dict[str, object]] = []
    workload_rows: list[dict[str, object]] = []
    created_vaults: list[str] = []
    vault_files: dict[str, list[str]] = {}
    successful_scale_vaults: dict[int, str] = {}
    sequence = 0

    def run_gitvault(
        scenario: str,
        operation: str,
        dataset_files: int,
        arguments: list[str],
        *,
        stdout_to_null: bool = False,
        stdin: str | None = None,
        require_success: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal sequence
        sequence += 1
        started = time.perf_counter_ns()
        completed = subprocess.run(
            [str(binary), *arguments, "--password", password],
            input=stdin,
            text=True,
            stdout=subprocess.DEVNULL if stdout_to_null else subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        total_ms = (time.perf_counter_ns() - started) / 1_000_000
        error_class = "" if completed.returncode == 0 else classify_error(completed.stderr)
        command_rows.append({
            "scenario": scenario,
            "operation": operation,
            "dataset_files": dataset_files,
            "file_size_bytes": args.file_size_kib * 1024,
            "sequence": sequence,
            "total_ms": round(total_ms, 3),
            "success": int(completed.returncode == 0),
            "return_code": completed.returncode,
            "error_class": error_class,
        })
        traces: dict[str, float] = {}
        for phase, milliseconds in TRACE.findall(completed.stderr):
            traces[phase] = traces.get(phase, 0.0) + float(milliseconds)
        for phase, milliseconds in sorted(traces.items()):
            phase_rows.append({
                "scenario": scenario,
                "operation": operation,
                "dataset_files": dataset_files,
                "sequence": sequence,
                "phase": phase,
                "phase_ms": round(milliseconds, 3),
            })
        with log_path.open("a", encoding="utf-8") as stream:
            stream.write(
                f"scenario={scenario} operation={operation} "
                f"dataset_files={dataset_files} sequence={sequence} "
                f"returncode={completed.returncode} total_ms={total_ms:.3f}\n"
            )
            if not stdout_to_null and completed.stdout:
                stream.write(completed.stdout)
                if not completed.stdout.endswith("\n"):
                    stream.write("\n")
            if completed.stderr:
                stream.write(completed.stderr)
                if not completed.stderr.endswith("\n"):
                    stream.write("\n")
            stream.write("\n")
        if require_success and completed.returncode != 0:
            raise RuntimeError(
                f"{scenario}/{operation} failed; see {log_path}"
            )
        return completed

    try:
        with tempfile.TemporaryDirectory(prefix="gitvault-load-") as temporary:
            temporary_root = Path(temporary)
            for file_count in args.file_counts:
                scenario = f"scale-{file_count}"
                top = temporary_root / scenario
                top.mkdir()
                smallfile_json = output / f"smallfile-{file_count}.json"
                smallfile_command = [
                    sys.executable,
                    str(smallfile_script),
                    "--operation", "create",
                    "--top", str(top),
                    "--threads", "1",
                    "--files", str(file_count),
                    "--file-size", str(args.file_size_kib),
                    "--files-per-dir", str(args.files_per_dir),
                    "--dirs-per-dir", str(args.dirs_per_dir),
                    "--incompressible", "Y",
                    "--verify-read", "Y",
                    "--output-json", str(smallfile_json),
                ]
                smallfile_started = time.perf_counter_ns()
                generated = subprocess.run(
                    smallfile_command,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                smallfile_ms = (time.perf_counter_ns() - smallfile_started) / 1_000_000
                with log_path.open("a", encoding="utf-8") as stream:
                    stream.write(
                        f"scenario={scenario} operation=smallfile-create "
                        f"returncode={generated.returncode} total_ms={smallfile_ms:.3f}\n"
                    )
                    stream.write(generated.stdout)
                    stream.write(generated.stderr)
                    stream.write("\n")
                if generated.returncode != 0:
                    raise RuntimeError(f"smallfile generation failed; see {log_path}")

                dataset_root = top / "file_srcdir"
                local_files = sorted(item for item in dataset_root.rglob("*") if item.is_file())
                if len(local_files) != file_count:
                    raise RuntimeError(
                        f"smallfile produced {len(local_files)} files; expected {file_count}"
                    )
                remote_files = [item.relative_to(dataset_root).as_posix() for item in local_files]
                directory_count = sum(1 for item in dataset_root.rglob("*") if item.is_dir())
                dataset_bytes = sum(item.stat().st_size for item in local_files)
                smallfile_result = read_smallfile_result(smallfile_json)

                vault = f"gitvault-load-{suffix}-{file_count}"
                created_vaults.append(vault)
                vault_files[vault] = remote_files
                init_result = run_gitvault(
                    scenario,
                    "init",
                    file_count,
                    [
                        "init", vault, str(dataset_root),
                        *sum((["--relay", relay] for relay in args.relay), []),
                    ],
                    require_success=False,
                )
                init_ms = float(command_rows[-1]["total_ms"])
                dataset_rows.append({
                    "scenario": scenario,
                    "requested_files": file_count,
                    "actual_files": len(local_files),
                    "directories": directory_count,
                    "file_size_bytes": args.file_size_kib * 1024,
                    "dataset_bytes": dataset_bytes,
                    "smallfile_elapsed_ms": round(smallfile_ms, 3),
                    "smallfile_files_per_sec": round(
                        float(smallfile_result.get("filesPerSec", 0.0)), 3
                    ),
                    "gitvault_init_ms": round(init_ms, 3),
                    "gitvault_init_success": int(init_result.returncode == 0),
                })
                if init_result.returncode != 0:
                    continue
                successful_scale_vaults[file_count] = vault

                run_gitvault(
                    scenario, "status", file_count, ["status", vault],
                    require_success=False,
                )
                run_gitvault(
                    scenario, "list", file_count, ["list", vault],
                    stdout_to_null=True, require_success=False,
                )
                run_gitvault(
                    scenario, "tree", file_count, ["tree", vault],
                    stdout_to_null=True, require_success=False,
                )
                sample_count = min(args.read_samples, len(remote_files))
                for sample_index, remote_path in enumerate(
                    randomizer.sample(remote_files, sample_count), start=1
                ):
                    run_gitvault(
                        scenario,
                        f"cat-sample-{sample_index}",
                        file_count,
                        ["cat", vault, remote_path],
                        stdout_to_null=True,
                        require_success=False,
                    )
                run_gitvault(
                    scenario, "quick-scan", file_count,
                    ["quick-scan", vault], stdout_to_null=True,
                    require_success=False,
                )
                run_gitvault(
                    scenario, "deep-scan", file_count,
                    ["deep-scan", vault], stdout_to_null=True,
                    require_success=False,
                )

            if args.workload_operations > 0 and successful_scale_vaults:
                largest_count = max(successful_scale_vaults)
                workload_vault = successful_scale_vaults[largest_count]
                remote_files = vault_files[workload_vault]
                update_payload = temporary_root / "workload-update.bin"
                update_payload.write_bytes(os.urandom(args.file_size_kib * 1024))

                for workload in workloads:
                    ratio = WORKLOAD_UPDATE_RATIOS[workload]
                    update_count = round(args.workload_operations * ratio)
                    if ratio > 0 and update_count == 0:
                        update_count = 1
                    operations = ["update"] * update_count
                    operations.extend(
                        ["read"] * (args.workload_operations - update_count)
                    )
                    randomizer.shuffle(operations)
                    workload_started = time.perf_counter_ns()
                    successes = 0
                    latencies: list[float] = []
                    for operation in operations:
                        remote_path = randomizer.choice(remote_files)
                        if operation == "update":
                            update_payload.write_bytes(
                                os.urandom(args.file_size_kib * 1024)
                            )
                            completed = run_gitvault(
                                workload,
                                "update",
                                largest_count,
                                ["add", workload_vault, str(update_payload), remote_path],
                                require_success=False,
                            )
                        else:
                            completed = run_gitvault(
                                workload,
                                "read",
                                largest_count,
                                ["cat", workload_vault, remote_path],
                                stdout_to_null=True,
                                require_success=False,
                            )
                        successes += int(completed.returncode == 0)
                        latencies.append(float(command_rows[-1]["total_ms"]))
                    workload_ms = (time.perf_counter_ns() - workload_started) / 1_000_000
                    workload_rows.append({
                        "workload": workload,
                        "dataset_files": largest_count,
                        "operations": len(operations),
                        "reads": len(operations) - update_count,
                        "updates": update_count,
                        "successes": successes,
                        "failures": len(operations) - successes,
                        "elapsed_ms": round(workload_ms, 3),
                        "attempted_ops_per_sec": round(
                            len(operations) / (workload_ms / 1000), 6
                        ),
                        "goodput_ops_per_sec": round(
                            successes / (workload_ms / 1000), 6
                        ),
                        "mean_ms": round(statistics.mean(latencies), 3),
                        "median_ms": round(statistics.median(latencies), 3),
                        "p95_ms": round(percentile(latencies, 0.95), 3),
                        "p99_ms": round(percentile(latencies, 0.99), 3),
                        "min_ms": round(min(latencies), 3),
                        "max_ms": round(max(latencies), 3),
                    })

        with (output / "environment.json").open("w", encoding="utf-8") as stream:
            json.dump({
                "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "platform": platform.platform(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "single_replica": True,
                "max_outstanding_gitvault_commands": 1,
                "relays": args.relay,
                "read_quorum": 2,
                "write_quorum": 2,
                "file_counts": args.file_counts,
                "file_size_kib": args.file_size_kib,
                "files_per_dir": args.files_per_dir,
                "dirs_per_dir": args.dirs_per_dir,
                "read_samples": args.read_samples,
                "workloads": workloads,
                "workload_operations": args.workload_operations,
                "random_seed": args.seed,
                "smallfile_script": str(smallfile_script),
                "smallfile_git_revision": git_revision_for_script(smallfile_script),
                "gitvault_git_revision": git_revision_for_script(Path(__file__)),
                "benchmark_vault_prefix": f"gitvault-load-{suffix}",
            }, stream, indent=2, sort_keys=True)

        write_csv(
            output / "datasets.csv",
            dataset_rows,
            [
                "scenario", "requested_files", "actual_files", "directories",
                "file_size_bytes", "dataset_bytes", "smallfile_elapsed_ms",
                "smallfile_files_per_sec", "gitvault_init_ms",
                "gitvault_init_success",
            ],
        )
        write_csv(
            output / "raw_commands.csv",
            command_rows,
            [
                "scenario", "operation", "dataset_files", "file_size_bytes",
                "sequence", "total_ms", "success", "return_code", "error_class",
            ],
        )
        write_csv(
            output / "raw_phases.csv",
            phase_rows,
            [
                "scenario", "operation", "dataset_files", "sequence", "phase",
                "phase_ms",
            ],
        )
        write_csv(
            output / "workload_summary.csv",
            workload_rows,
            [
                "workload", "dataset_files", "operations", "reads", "updates",
                "successes", "failures", "elapsed_ms", "attempted_ops_per_sec",
                "goodput_ops_per_sec", "mean_ms", "median_ms", "p95_ms",
                "p99_ms", "min_ms", "max_ms",
            ],
        )

        scale_groups: dict[tuple[str, str, int], list[dict[str, object]]] = {}
        for row in command_rows:
            scenario = str(row["scenario"])
            if not scenario.startswith("scale-"):
                continue
            operation = str(row["operation"])
            if operation.startswith("cat-sample-"):
                operation = "cat"
            key = (scenario, operation, int(row["dataset_files"]))
            scale_groups.setdefault(key, []).append(row)
        scale_summary_rows: list[dict[str, object]] = []
        for (scenario, operation, dataset_files), rows in sorted(scale_groups.items()):
            latencies = [float(row["total_ms"]) for row in rows]
            scale_summary_rows.append({
                "scenario": scenario,
                "operation": operation,
                "dataset_files": dataset_files,
                "n": len(rows),
                "successes": sum(int(row["success"]) for row in rows),
                "mean_ms": round(statistics.mean(latencies), 3),
                "median_ms": round(statistics.median(latencies), 3),
                "p95_ms": round(percentile(latencies, 0.95), 3),
                "p99_ms": round(percentile(latencies, 0.99), 3),
                "min_ms": round(min(latencies), 3),
                "max_ms": round(max(latencies), 3),
            })
        write_csv(
            output / "scale_summary.csv",
            scale_summary_rows,
            [
                "scenario", "operation", "dataset_files", "n", "successes",
                "mean_ms", "median_ms", "p95_ms", "p99_ms", "min_ms", "max_ms",
            ],
        )

        phase_groups: dict[tuple[str, str, int, str], list[float]] = {}
        for row in phase_rows:
            scenario = str(row["scenario"])
            if scenario == "cleanup":
                continue
            operation = str(row["operation"])
            if operation.startswith("cat-sample-"):
                operation = "cat"
            key = (
                scenario,
                operation,
                int(row["dataset_files"]),
                str(row["phase"]),
            )
            phase_groups.setdefault(key, []).append(float(row["phase_ms"]))
        phase_summary_rows: list[dict[str, object]] = []
        for (scenario, operation, dataset_files, phase), values in sorted(
            phase_groups.items()
        ):
            phase_summary_rows.append({
                "scenario": scenario,
                "operation": operation,
                "dataset_files": dataset_files,
                "phase": phase,
                "n": len(values),
                "mean_ms": round(statistics.mean(values), 3),
                "median_ms": round(statistics.median(values), 3),
                "p95_ms": round(percentile(values, 0.95), 3),
                "p99_ms": round(percentile(values, 0.99), 3),
            })
        write_csv(
            output / "phase_summary.csv",
            phase_summary_rows,
            [
                "scenario", "operation", "dataset_files", "phase", "n",
                "mean_ms", "median_ms", "p95_ms", "p99_ms",
            ],
        )
    finally:
        for vault in created_vaults:
            run_gitvault(
                "cleanup", "destroy", 0, ["destroy", vault],
                stdin="y\n", require_success=False,
            )
        if command_rows:
            write_csv(
                output / "raw_commands.csv",
                command_rows,
                [
                    "scenario", "operation", "dataset_files", "file_size_bytes",
                    "sequence", "total_ms", "success", "return_code", "error_class",
                ],
            )
        if phase_rows:
            write_csv(
                output / "raw_phases.csv",
                phase_rows,
                [
                    "scenario", "operation", "dataset_files", "sequence", "phase",
                    "phase_ms",
                ],
            )

    print(output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"benchmark error: {error}", file=sys.stderr)
        raise SystemExit(1)
