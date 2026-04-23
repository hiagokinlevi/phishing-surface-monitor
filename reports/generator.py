from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ReportValidationError(ValueError):
    """Raised when a report payload does not match its JSON schema."""


def _load_schema(schema_name: str) -> dict[str, Any]:
    schema_path = Path(__file__).resolve().parent.parent / "schemas" / schema_name
    with schema_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _validate_required_fields(payload: dict[str, Any], schema: dict[str, Any], schema_name: str) -> None:
    required = schema.get("required", [])
    missing = [field for field in required if field not in payload or payload.get(field) is None]
    if missing:
        raise ReportValidationError(
            f"Invalid report payload for {schema_name}: missing required field(s): {', '.join(missing)}"
        )


def _validate_payload(payload: dict[str, Any], schema_name: str) -> None:
    schema = _load_schema(schema_name)
    _validate_required_fields(payload, schema, schema_name)


def write_case_json_report(payload: dict[str, Any], output_path: str | Path) -> Path:
    _validate_payload(payload, "case.schema.json")
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return out


def write_finding_json_report(payload: dict[str, Any], output_path: str | Path) -> Path:
    _validate_payload(payload, "finding.schema.json")
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return out
