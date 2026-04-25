import argparse
import json
from datetime import datetime, timezone

from monitors.ct_monitor import monitor_ct_for_domain


def _event_to_jsonl_record(event: dict) -> dict:
    domain = event.get("domain") or event.get("matched_domain") or event.get("name_value")
    reason = event.get("reason") or event.get("alert_reason") or event.get("risk_reason")
    seen_ts = event.get("seen_at") or event.get("timestamp")
    if isinstance(seen_ts, datetime):
        seen_ts = seen_ts.astimezone(timezone.utc).isoformat()

    return {
        "domain": domain,
        "fingerprint": event.get("fingerprint") or event.get("cert_fingerprint"),
        "serial": event.get("serial") or event.get("serial_number"),
        "wildcard": bool(event.get("wildcard", False)),
        "seen_at": seen_ts,
        "reason": reason,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    sub = parser.add_subparsers(dest="command")

    ct = sub.add_parser("ct-monitor", help="Monitor certificate transparency events")
    ct.add_argument("domain", help="Base domain to monitor")
    ct.add_argument("--jsonl", action="store_true", help="Emit one JSON object per event line")

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "ct-monitor":
        events = monitor_ct_for_domain(args.domain)
        if args.jsonl:
            for ev in events:
                print(json.dumps(_event_to_jsonl_record(ev), sort_keys=True))
        else:
            for ev in events:
                domain = ev.get("domain") or ev.get("matched_domain") or ev.get("name_value")
                reason = ev.get("reason") or ev.get("alert_reason") or "ct-event"
                print(f"[CT] {domain} :: {reason}")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
