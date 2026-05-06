import argparse
import json
from datetime import datetime, timezone


def _serialize_ct_findings(findings):
    serialized = []
    for f in findings or []:
        matched_domain = f.get("matched_domain") or f.get("domain")
        fingerprint = (
            f.get("certificate_fingerprint")
            or f.get("cert_fingerprint")
            or f.get("fingerprint")
            or f.get("certificate_id")
            or f.get("cert_id")
            or f.get("id")
        )
        risk_score = f.get("risk_score", 0)
        detected_at = f.get("detected_at") or f.get("detection_timestamp")
        if not detected_at:
            detected_at = datetime.now(timezone.utc).isoformat()

        serialized.append(
            {
                "matched_domain": matched_domain,
                "certificate_fingerprint": fingerprint,
                "risk_score": risk_score,
                "detection_timestamp": detected_at,
            }
        )
    return serialized


def build_parser():
    parser = argparse.ArgumentParser(prog="phishing-monitor")
    subparsers = parser.add_subparsers(dest="command")

    ct_parser = subparsers.add_parser("ct-monitor")
    ct_parser.add_argument("domain")
    ct_parser.add_argument(
        "--ct-json-stdout",
        action="store_true",
        help="Print CT monitor findings as JSON to stdout",
    )

    return parser


def _run_ct_monitor(domain):
    # Existing CT monitor execution path would live here in the real project.
    # Kept simple/compatible for focused feature implementation.
    return []


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "ct-monitor":
        findings = _run_ct_monitor(args.domain)
        if args.ct_json_stdout:
            print(json.dumps(_serialize_ct_findings(findings)))
            return 0
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
