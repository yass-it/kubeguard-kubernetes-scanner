"""Command-line entry point."""
import argparse
import sys
from pathlib import Path
from . import __version__
from .reporter import as_json, as_text
from .scanner import ManifestError, scan_path

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kubeguard", description="Offline Kubernetes YAML manifest security scanner prototype.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Scan a YAML manifest file or directory.")
    scan.add_argument("--path", required=True, help="YAML file or directory containing .yaml/.yml files.")
    scan.add_argument("--format", choices=("text", "json"), default="text", help="Output format.")
    scan.add_argument("--output", help="Write the report to this file instead of stdout.")
    return parser

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        findings, documents_scanned = scan_path(args.path)
    except (FileNotFoundError, ValueError, ManifestError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    report = as_json(findings, documents_scanned) if args.format == "json" else as_text(findings, documents_scanned)
    if args.output:
        output_path = Path(args.output)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Error writing report: {exc}", file=sys.stderr)
            return 2
        print(f"Report written to {output_path}")
    else:
        print(report)
    return 1 if findings else 0

if __name__ == "__main__":
    raise SystemExit(main())
