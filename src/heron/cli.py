"""Command-line interface: `python -m heron <folder>`"""

import argparse
import os
import json
import sys
from dataclasses import asdict

from heron.scorer import triage
from heron.parser import parse_eml
from heron.models import TriageResult


def build_parser() -> argparse.ArgumentParser:
    """Return the parser of the CLI arguments.

    Returns
    -------
    argparse.ArgumentParser
        The parser of the CLI arguments.
    """
    parser = argparse.ArgumentParser(prog="heron", description="Triage of phishing emails.")
    parser.add_argument("folder", help="a folder containing `.eml` files")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    return parser


def check_mail(folder: str) -> list[TriageResult]:
    """Score every email file in the given folder.
    Return (file name, verdict, score) tuples.

    Parameters
    ----------
    folder : str
        The folder containing the `.eml` files.

    Returns
    -------
    list[TriageResult]
        A list of TriageResult objects containing the email ID, verdict, and score.
    """
    verdicts = []
    files = os.listdir(folder)
    for fn in files:
        if not fn.endswith(".eml"):
            continue
        with open(os.path.join(folder, fn), encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        parsed_email = parse_eml(raw, fn)
        result = triage(parsed_email)
        verdicts.append(result)
    return verdicts


def report(verdicts: list[TriageResult]) -> None:
    """Prints the verdicts."""
    for v in verdicts:
        print(f"{v.email_id:<28} {v.verdict} score={v.score}")


def main(argv: list[str] | None = None):
    """Entry point of the CLI.

    Parameters
    ----------

    argv : list[str] | None
        The command-line arguments. If None, sys.argv[1:] is used.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        verdicts = check_mail(args.folder)
        if args.json:
            with open("output.json", "w") as f:
                json.dump([asdict(v) for v in verdicts], f)
        report(verdicts)
    except FileNotFoundError:
        print("error: no such folder", file=sys.stderr)