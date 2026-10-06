# heron

A small toolkit to triage suspicious emails: parse `.eml` files, extract
phishing indicators (authentication failures, sender impersonation,
deceptive links, urgency language, risky attachments) and produce a
verdict: benign, suspicious, or phishing.

> Course project for *Industrial Software Development*. This repository
> evolves throughout the semester; see the tags for each stage.

## Usage

The code is a package under `src/heron/`. From the repository root:

```bash
PYTHONPATH=src python -m heron data/samples
```

It prints each verdict with the findings behind it, then a summary. The path
can also be one `.eml` file; `--json` gives machine-readable output, `--help`
lists the options.

## Status

Modular code: a package under `src/heron/` with one module per
responsibility (models, parser, features, scorer, cli). Not packaged yet:
there is no `pyproject.toml` and nothing to install.
