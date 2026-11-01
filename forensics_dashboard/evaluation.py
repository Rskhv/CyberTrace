"""Compare exported baseline/proposed outcomes against evaluation-only labels.

The correlation engines remain owned by their module. They export one row per
timeline stage using the CSV contract documented in README.md; this tool scores
those exports and never imports or calls ground truth from runtime code.
"""
from __future__ import annotations

import argparse
import csv
import json
import time
from collections import defaultdict
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def _read_csv(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def _read_ground_truth(path: str | Path, database: str | None = None) -> list[dict[str, str]]:
    """Read the Attack Range JSONL contract or the existing evaluation CSV contract."""
    source = Path(path)
    if source.suffix.lower() != ".jsonl":
        rows = _read_csv(source)
    else:
        from shared.event_model import EVENT_TYPE_TO_STAGE
        from cybertrace_forensics.stage_model import StageGraph

        raw = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines() if line.strip()]
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in raw:
            if row.get("status", "completed") == "completed" and row.get("expected_event_type"):
                grouped[str(row.get("run_id", "run"))].append(row)
        rows = []
        graph = StageGraph()
        for run_id, actions in grouped.items():
            actions.sort(key=lambda item: float(item.get("start_epoch", 0)))
            stages: list[str] = []
            for action in actions:
                stage = EVENT_TYPE_TO_STAGE.get(action.get("expected_event_type", ""))
                if stage and (not stages or stage != stages[-1]):
                    if stages:
                        stages.extend(graph.intermediate_stages(stages[-1], stage))
                    stages.append(stage)
            expected = ">".join(stages)
            for action in actions:
                start = action.get("start_utc") or _dt(str(action["start_epoch"])).isoformat()
                end = action.get("end_utc") or action.get("start_utc") or start
                rows.append({
                    "scenario_id": run_id,
                    "attack_type": action["expected_event_type"],
                    "start_time": start,
                    "end_time": end,
                    "expected_sequence": expected,
                    "source_ip": action.get("src_ip", ""),
                    "destination_ip": action.get("dst_ip", ""),
                    "dst_ports": json.dumps(action.get("dst_ports", [])),
                })
    if database:
        import sqlite3
        with closing(sqlite3.connect(f"file:{Path(database).resolve().as_posix()}?mode=ro", uri=True)) as conn:
            if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='packets'").fetchone():
                baselines = conn.execute(
                    """SELECT pcap_file, MIN(timestamp), MAX(timestamp) FROM packets
                       WHERE lower(coalesce(pcap_file, '')) LIKE '%baseline%'
                       GROUP BY pcap_file"""
                ).fetchall()
                for filename, start, end in baselines:
                    if start is not None and end is not None:
                        rows.append({
                            "scenario_id": f"BENIGN:{filename}",
                            "attack_type": "BENIGN",
                            "start_time": datetime.fromtimestamp(start, timezone.utc).isoformat(),
                            "end_time": datetime.fromtimestamp(end, timezone.utc).isoformat(),
                            "expected_sequence": "",
                        })
    return rows


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))


def _kind(value: str) -> str:
    return value.strip().upper().replace(" ", "_")


def _within(event: dict[str, str], start: str, end: str) -> bool:
    try:
        stamp = _dt(event["timestamp"])
        return _dt(start) <= stamp <= _dt(end)
    except (KeyError, ValueError):
        return False


def _context_matches(event: dict[str, str], action: dict[str, str]) -> bool:
    for event_key, action_key in (("source_ip", "source_ip"), ("destination_ip", "destination_ip")):
        expected = action.get(action_key, "")
        if expected and event.get(event_key) and event[event_key] != expected:
            return False
    expected_ports = action.get("dst_ports", "")
    actual_port = event.get("destination_port")
    if expected_ports and actual_port:
        try:
            ports = json.loads(expected_ports) if expected_ports.startswith("[") else [int(expected_ports)]
            if ports and int(actual_port) not in [int(port) for port in ports]:
                return False
        except (ValueError, TypeError):
            pass
    return True


def evaluate_method(ground_truth: list[dict[str, str]], predictions: list[dict[str, str]]) -> dict[str, Any]:
    """Compute detection, sequence and recovery metrics for one exported method.

    GT rows describe either an attack action or a BENIGN observation window.
    Prediction rows use one row per detected or inferred timeline stage.
    """
    actions = [r for r in ground_truth if _kind(r.get("attack_type", "")) != "BENIGN"]
    benign = [r for r in ground_truth if _kind(r.get("attack_type", "")) == "BENIGN"]
    claimed: set[int] = set()
    matched_latency: list[float] = []
    true_positives = 0
    for action in actions:
        candidates = [(i, p) for i, p in enumerate(predictions)
                      if i not in claimed and _kind(p.get("event_type", p.get("attack_stage", ""))) == _kind(action.get("attack_type", ""))
                      and _within(p, action.get("start_time", ""), action.get("end_time", ""))
                      and _context_matches(p, action)]
        if candidates:
            idx, event = candidates[0]
            claimed.add(idx)
            true_positives += 1
            try:
                matched_latency.append(max(0.0, (_dt(event["timestamp"]) - _dt(action["start_time"])).total_seconds()))
            except (KeyError, ValueError):
                pass
    false_negative = len(actions) - true_positives
    # Count each unmatched detection once; inferential timeline entries are not alerts.
    false_positive = sum(1 for i, p in enumerate(predictions)
                         if i not in claimed and _kind(p.get("status", "DETECTED")) != "INFERRED")
    benign_flagged = sum(1 for window in benign if any(_within(p, window.get("start_time", ""), window.get("end_time", ""))
                                                       and _kind(p.get("status", "DETECTED")) != "INFERRED"
                                                       for p in predictions))
    tn = len(benign) - benign_flagged
    # Include out-of-window false alerts in FP and use labeled observation windows for FPR.
    precision = true_positives / (true_positives + false_positive) if true_positives + false_positive else 0.0
    recall = true_positives / (true_positives + false_negative) if true_positives + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = benign_flagged / (benign_flagged + tn) if benign_flagged + tn else 0.0

    by_incident: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in predictions:
        by_incident[row.get("incident_id", "unassigned")].append(row)
    exact = 0
    recovered_values: list[float] = []
    cases: dict[str, tuple[dict[str, str], list[str]]] = {}
    for action in actions:
        sequence = [s.strip().upper().replace(" ", "_") for s in action.get("expected_sequence", "").split(">") if s.strip()]
        if sequence:
            cases.setdefault(action.get("scenario_id", ""), (action, sequence))
    expected_count = len(cases)
    for scenario, (action, sequence) in cases.items():
        seq_rows = by_incident.get(scenario, []) or by_incident.get(action.get("incident_id", ""), [])
        if not seq_rows:
            case_actions = [item for item in actions if item.get("scenario_id", "") == scenario]
            matched_incidents = {
                predictions[i].get("incident_id", "")
                for i in claimed
                if any(_kind(predictions[i].get("event_type", "")) == _kind(item.get("attack_type", ""))
                       and _within(predictions[i], item.get("start_time", ""), item.get("end_time", ""))
                       and _context_matches(predictions[i], item) for item in case_actions)
            }
            seq_rows = [row for incident_id in matched_incidents for row in by_incident.get(incident_id, [])]
        observed = [_kind(r.get("attack_stage", r.get("event_type", ""))) for r in seq_rows]
        # Exact ordered stage reconstruction, including INFERRED stages.
        if observed == sequence:
            exact += 1
        observed_detected = {_kind(r.get("attack_stage", r.get("event_type", ""))) for r in seq_rows
                             if _kind(r.get("status", "DETECTED")) != "INFERRED"}
        missing = set(sequence) - observed_detected
        inferred = {_kind(r.get("attack_stage", r.get("event_type", ""))) for r in seq_rows
                    if _kind(r.get("status", "")) == "INFERRED"}
        if missing:
            recovered_values.append(len(missing & inferred) / len(missing))
    return {
        "precision": precision, "recall": recall, "f1": f1, "false_positive_rate": fpr,
        "reconstruction_accuracy": exact / expected_count if expected_count else None,
        "missing_step_recovery_accuracy": sum(recovered_values) / len(recovered_values) if recovered_values else None,
        "detection_latency_seconds": sum(matched_latency) / len(matched_latency) if matched_latency else None,
        "tp": true_positives, "fp": false_positive, "fn": false_negative,
        "benign_windows": len(benign), "benign_flagged": benign_flagged,
        "reconstruction_cases": expected_count,
    }


def evaluate(ground_truth: list[dict[str, str]], baseline: list[dict[str, str]], proposed: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
    return {"baseline": evaluate_method(ground_truth, baseline),
            "proposed": evaluate_method(ground_truth, proposed)}


def write_results(results: dict[str, dict[str, Any]], output: str | Path,
                  parsing_total: int | None = None, parsing_correct: int | None = None,
                  query_seconds: float | None = None) -> None:
    rows = []
    for metric in ("precision", "recall", "f1", "false_positive_rate", "reconstruction_accuracy",
                   "missing_step_recovery_accuracy", "detection_latency_seconds", "tp", "fp", "fn",
                   "benign_windows", "benign_flagged", "reconstruction_cases"):
        rows.append({"metric": metric, "baseline": results["baseline"].get(metric), "proposed": results["proposed"].get(metric)})
    parsing_accuracy = parsing_correct / parsing_total if parsing_total else None
    rows.append({"metric": "pcap_parsing_accuracy", "baseline": parsing_accuracy, "proposed": parsing_accuracy})
    rows.append({"metric": "average_sqlite_read_query_seconds", "baseline": query_seconds, "proposed": query_seconds})
    with Path(output).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("metric", "baseline", "proposed"))
        writer.writeheader()
        writer.writerows(rows)


def _db_query_time(database: str | None) -> float | None:
    if not database:
        return None
    import sqlite3
    with closing(sqlite3.connect(f"file:{Path(database).resolve().as_posix()}?mode=ro", uri=True)) as db:
        tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        durations = []
        for table in tables:
            # Identifiers are quoted and originate only from sqlite_master.
            start = time.perf_counter()
            db.execute(f'SELECT COUNT(*) FROM "{table.replace(chr(34), chr(34) * 2)}"').fetchone()
            durations.append(time.perf_counter() - start)
    return sum(durations) / len(durations) if durations else None


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", required=True, help="Evaluation-only labeled actions/windows CSV or Attack Range JSONL")
    parser.add_argument("--baseline", required=True, help="Baseline timeline export CSV")
    parser.add_argument("--proposed", required=True, help="Evidence-aware timeline export CSV")
    parser.add_argument("--output", default="evaluation_results.csv")
    parser.add_argument("--parsing-total", type=int, help="Packet count in independent tshark baseline")
    parser.add_argument("--parsing-correct", type=int, help="Packets correctly represented by the parser")
    parser.add_argument("--database", help="Optional shared SQLite DB to time a read-only schema query")
    args = parser.parse_args(argv)
    if (args.parsing_total is None) != (args.parsing_correct is None):
        parser.error("--parsing-total and --parsing-correct must be supplied together")
    if args.parsing_total is not None and (args.parsing_total < 0 or not 0 <= args.parsing_correct <= args.parsing_total):
        parser.error("parsing counts must satisfy 0 <= correct <= total")
    started = time.perf_counter()
    result = evaluate(_read_ground_truth(args.ground_truth, args.database),
                      _read_csv(args.baseline), _read_csv(args.proposed))
    analysis_seconds = time.perf_counter() - started
    write_results(result, args.output, args.parsing_total, args.parsing_correct, _db_query_time(args.database))
    print(json.dumps({"output": str(Path(args.output)), "analysis_seconds": analysis_seconds, "metrics": result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
