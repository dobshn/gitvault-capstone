#!/usr/bin/env python3

import argparse
import csv
from pathlib import Path
import statistics
import subprocess
import time


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", default="build")
    parser.add_argument("--output", required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    build = Path(args.build).resolve()

    detection = subprocess.run(
        [str(build / "gitvault_checkpoint_detection_benchmark"),
         str(args.repetitions)], text=True, capture_output=True, check=True)
    (output / "checkpoint_detection.csv").write_text(
        detection.stdout, encoding="utf-8")
    detection_rows = list(csv.DictReader(detection.stdout.splitlines()))
    detection_groups: dict[str, list[float]] = {}
    detection_successes: dict[str, int] = {}
    expected_states = {
        "rollback": "ROLLBACK_DETECTED",
        "fork": "FORKED",
    }
    for row in detection_rows:
        scenario = row["scenario"]
        detection_groups.setdefault(scenario, []).append(float(row["latency_us"]))
        detection_successes[scenario] = detection_successes.get(scenario, 0) + int(
            row["state"] == expected_states[scenario])
    with (output / "checkpoint_detection_summary.csv").open(
            "w", newline="", encoding="utf-8") as stream:
        fields = ["scenario", "n", "successes", "median_us", "p95_us",
                  "min_us", "max_us"]
        writer = csv.DictWriter(
            stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for scenario, values in detection_groups.items():
            writer.writerow({
                "scenario": scenario,
                "n": len(values),
                "successes": detection_successes[scenario],
                "median_us": round(statistics.median(values), 3),
                "p95_us": round(percentile(values, 0.95), 3),
                "min_us": round(min(values), 3),
                "max_us": round(max(values), 3),
            })

    rows = []
    for iteration in range(1, args.repetitions + 1):
        started = time.perf_counter_ns()
        completed = subprocess.run(
            [str(build / "gitvault_anchor_coordinator_integration_tests")],
            text=True, capture_output=True, check=False)
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        rows.append({
            "iteration": iteration,
            "latency_ms": round(elapsed_ms, 3),
            "success": int(completed.returncode == 0),
        })
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr)
    with (output / "controlled_protocol_runs.csv").open(
            "w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    values = [float(row["latency_ms"]) for row in rows]
    with (output / "controlled_protocol_summary.csv").open(
            "w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["n", "successes", "median_ms", "p95_ms",
                         "min_ms", "max_ms"])
        writer.writerow([len(rows), sum(int(row["success"]) for row in rows),
                         round(statistics.median(values), 3),
                         round(percentile(values, 0.95), 3),
                         round(min(values), 3), round(max(values), 3)])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
