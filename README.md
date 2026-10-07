# heron

A small toolkit to triage suspicious emails: parse `.eml` files, extract
phishing indicators (authentication failures, sender impersonation,
deceptive links, urgency language, risky attachments) and produce a
verdict: benign, suspicious, or phishing.

> Course project for *Industrial Software Development*. This repository
> evolves throughout the semester; see the tags for each stage.

## Usage

Install heron and the dev tools with uv, then run it from the repository root:

```bash
uv sync                       # create .venv from uv.lock (heron + dev tools)
uv run heron data/samples
```

It prints each verdict with the findings behind it, then a summary. The path
can also be one `.eml` file; `--json` gives machine-readable output, `--help`
lists the options.

## Status

Packaged (`pyproject.toml`, src layout, committed `uv.lock`), formatted and
linted (ruff), typed (mypy strict), with a pre-commit hook and an API
reference built from the docstrings by Sphinx
(`uv run sphinx-build -W docs docs/_build`).
