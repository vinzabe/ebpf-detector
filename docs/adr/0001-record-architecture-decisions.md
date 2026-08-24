# 1. Record architecture decisions

Date: 2026-08-23
Status: Accepted

## Context
This project makes design calls that are not obvious from the code alone.
Reviewers — and future maintainers — need the reasoning and, critically, the
options that were rejected and why.

## Decision
Keep lightweight ADRs (one file per decision) in `docs/adr/`.

## Consequences
Any change to a core model, contract, or state layer lands with an ADR in the
same commit as the code that implements it.
