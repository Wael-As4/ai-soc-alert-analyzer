import json
import csv
from pathlib import Path


def load_logs(file_path):
    """
    Load security logs from JSON or CSV and normalize them.
    Returns a list of dictionaries.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    if path.suffix == ".json":
        return _load_json(path)
    elif path.suffix == ".csv":
        return _load_csv(path)
    else:
        raise ValueError("Unsupported file format. Use .json or .csv")


def _load_json(path):
    with open(path, "r") as f:
        data = json.load(f)

    normalized_logs = []

    for entry in data:
        normalized_logs.append(_normalize_entry(entry))

    return normalized_logs


def _load_csv(path):
    normalized_logs = []

    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            normalized_logs.append(_normalize_entry(row))

    return normalized_logs


def _normalize_entry(entry):
    """
    Convert a raw log entry into a normalized format.
    Missing fields are set to None.
    """
    return {
        "timestamp": entry.get("timestamp"),
        "source_ip": entry.get("source_ip") or entry.get("src_ip"),
        "destination_port": _safe_int(entry.get("destination_port") or entry.get("port")),
        "event": entry.get("event") or entry.get("action"),
        "username": entry.get("username"),
    }


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

Add log parser and normalization logic
