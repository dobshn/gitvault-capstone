#!/usr/bin/env python3
"""Run a small, reproducible GitVault WAN evaluation.

The script creates uniquely named Dropbox Vaults, publishes checkpoints with a
fresh Vault identity, records five runs per operation, and destroys all Dropbox
and local benchmark Vaults at the end. Public relay events are not deletable.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import sys
import time


TRACE = re.compile(r"GITVAULT_BENCH phase=([^ ]+) ms=([0-9.]+)")


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="./build/gitvault")
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--output", required=True)
    parser.add_argument("--relay", action="append", required=True)
    args = parser.parse_args()
    if len(args.relay) != 3 or args.repetitions < 1:
        parser.error("exactly three --relay options and a positive repetition count are required")

    binary = str(Path(args.binary).resolve())
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    data_dir = output / "payloads"
    data_dir.mkdir()
    log_path = output / "commands.log"
    password = "gitvault-evaluation-" + secrets.token_hex(12)
    suffix = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    vaults = [f"gitvault-eval-{suffix}-{index + 1}" for index in range(args.repetitions)]
    command_rows: list[dict[str, object]] = []
    phase_rows: list[dict[str, object]] = []

    environment = os.environ.copy()
    environment["GITVAULT_BENCHMARK_TRACE"] = "1"

    def run(operation: str, iteration: int, size: int, arguments: list[str],
            stdout_to_null: bool = False, stdin: str | None = None,
            accept_failure: bool = False) -> subprocess.CompletedProcess[str]:
        started = time.perf_counter_ns()
        completed = subprocess.run(
            [binary, *arguments, "--password", password],
            input=stdin,
            text=True,
            stdout=subprocess.DEVNULL if stdout_to_null else subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        total_ms = (time.perf_counter_ns() - started) / 1_000_000
        traces: dict[str, float] = {}
        for phase, milliseconds in TRACE.findall(completed.stderr):
            traces[phase] = traces.get(phase, 0.0) + float(milliseconds)
        command_rows.append({
            "operation": operation,
            "size_bytes": size,
            "iteration": iteration,
            "total_ms": round(total_ms, 3),
            "success": int(completed.returncode == 0),
        })
        for phase, milliseconds in sorted(traces.items()):
            phase_rows.append({
                "operation": operation,
                "size_bytes": size,
                "iteration": iteration,
                "phase": phase,
                "phase_ms": round(milliseconds, 3),
            })
        with log_path.open("a", encoding="utf-8") as stream:
            stream.write(f"operation={operation} size={size} iteration={iteration} "
                         f"returncode={completed.returncode} total_ms={total_ms:.3f}\n")
            if not stdout_to_null and completed.stdout:
                stream.write(completed.stdout)
                if not completed.stdout.endswith("\n"):
                    stream.write("\n")
            stream.write(completed.stderr)
            stream.write("\n")
        if completed.returncode != 0 and not accept_failure:
            raise RuntimeError(
                f"{operation} iteration {iteration} failed; see {log_path}")
        return completed

    try:
        for iteration, vault in enumerate(vaults, start=1):
            run("init", iteration, 0,
                ["init", vault, *sum((["--relay", relay] for relay in args.relay), [])])

        primary = vaults[0]
        for iteration in range(1, args.repetitions + 1):
            run("status", iteration, 0, ["status", primary])

        for iteration in range(1, args.repetitions + 1):
            run("mkdir", iteration, 0,
                ["mkdir", primary, f"directory-{iteration}"])

        for size in (8 * 1024, 1024 * 1024, 10 * 1024 * 1024):
            for iteration in range(1, args.repetitions + 1):
                payload = data_dir / f"payload-{size}-{iteration}.bin"
                with payload.open("wb") as stream:
                    remaining = size
                    while remaining:
                        block = os.urandom(min(1024 * 1024, remaining))
                        stream.write(block)
                        remaining -= len(block)
                remote = f"payload-{size}-{iteration}.bin"
                run("add", iteration, size,
                    ["add", primary, str(payload), remote])
                run("cat", iteration, size,
                    ["cat", primary, remote], stdout_to_null=True)
                run("remove", iteration, size,
                    ["remove", primary, remote])

        local_trust = Path.home() / ".gitvault" / primary / "trust"
        local_metadata_bytes = sum(
            item.stat().st_size for item in local_trust.rglob("*") if item.is_file())
        witness_count = sum(1 for item in (local_trust / "witnesses").glob("*.json"))

        with (output / "environment.json").open("w", encoding="utf-8") as stream:
            json.dump({
                "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "platform": platform.platform(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "repetitions": args.repetitions,
                "relays": args.relay,
                "payload_sizes_bytes": [8192, 1048576, 10485760],
                "local_trust_bytes_after_operations": local_metadata_bytes,
                "local_witness_files_after_operations": witness_count,
                "benchmark_vault_prefix": f"gitvault-eval-{suffix}",
            }, stream, indent=2, sort_keys=True)

        with (output / "raw_commands.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream, fieldnames=list(command_rows[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows(command_rows)
        with (output / "raw_phases.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream, fieldnames=list(phase_rows[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows(phase_rows)

        grouped: dict[tuple[str, int], list[float]] = {}
        for row in command_rows:
            key = (str(row["operation"]), int(row["size_bytes"]))
            grouped.setdefault(key, []).append(float(row["total_ms"]))
        with (output / "summary_commands.csv").open("w", newline="", encoding="utf-8") as stream:
            fields = ["operation", "size_bytes", "n", "mean_ms", "median_ms", "p95_ms", "min_ms", "max_ms"]
            writer = csv.DictWriter(
                stream, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            for (operation, size), values in sorted(grouped.items()):
                writer.writerow({
                    "operation": operation,
                    "size_bytes": size,
                    "n": len(values),
                    "mean_ms": round(sum(values) / len(values), 3),
                    "median_ms": round(percentile(values, 0.5), 3),
                    "p95_ms": round(percentile(values, 0.95), 3),
                    "min_ms": round(min(values), 3),
                    "max_ms": round(max(values), 3),
                })

        grouped_phases: dict[tuple[str, int, str], list[float]] = {}
        for row in phase_rows:
            key = (str(row["operation"]), int(row["size_bytes"]), str(row["phase"]))
            grouped_phases.setdefault(key, []).append(float(row["phase_ms"]))
        with (output / "summary_phases.csv").open("w", newline="", encoding="utf-8") as stream:
            fields = ["operation", "size_bytes", "phase", "n", "mean_ms", "median_ms", "p95_ms"]
            writer = csv.DictWriter(
                stream, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            for (operation, size, phase), values in sorted(grouped_phases.items()):
                writer.writerow({
                    "operation": operation,
                    "size_bytes": size,
                    "phase": phase,
                    "n": len(values),
                    "mean_ms": round(sum(values) / len(values), 3),
                    "median_ms": round(percentile(values, 0.5), 3),
                    "p95_ms": round(percentile(values, 0.95), 3),
                })
    finally:
        for vault in vaults:
            run("cleanup", 0, 0, ["destroy", vault], stdin="y\n",
                accept_failure=True)
        shutil.rmtree(data_dir, ignore_errors=True)

    print(output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"benchmark error: {error}", file=sys.stderr)
        raise SystemExit(1)
