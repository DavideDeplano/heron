# heron

heron is a phishing triage tool. It reads a folder of `.eml` files, looks for
phishing indicators in each email and gives a verdict (`ok`, `suspicious` or
`PHISHING`) with a score.

## How to run it

    python3 triage.py data/samples