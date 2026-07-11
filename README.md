# heron

A small toolkit to triage suspicious emails: parse `.eml` files, extract
phishing indicators (authentication failures, sender impersonation,
deceptive links, urgency language, risky attachments) and produce a
verdict: benign, suspicious, or phishing.

> Course project for *Industrial Software Development*. This repository
> evolves throughout the semester; see the tags for each stage.

## Usage

```bash
python triage.py data/samples
```

Results are printed to stdout and written to `results.txt`.

## Status

Legacy research code, currently being industrialized. Known issues are
tracked in the issue tracker.
