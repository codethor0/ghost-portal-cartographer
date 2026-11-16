# Ghost Portal Cartographer 1.0.0

The released object is a finite, metadata-only graph analysis kernel and its research paper, not an operational DLP or detection system.

- Research author: Thor Thor.
- Three nested evidence relations (`E_O ⊆ E_R ⊆ E_P`) with independently budgeted searches; a positive witness is never erased by another search's cap.
- The returned witness is re-verified and labeled by the strongest relation it satisfies; an exhaustive negative possible search is decisive for all relations.
- Trace and parent identifiers are diagnostic only; W3C-invalid all-zero identifiers are rejected.
- Transformation claims are authenticated with a local HMAC demonstration bound to the source and output artifacts and their trust domains; no claim, valid or not, removes an edge.
- 171 tests on CPython 3.9 through 3.15, two separately coded oracles, exhaustive small-graph enumeration, eleven deliberate mutants detected.
- Not available: authenticated collection, byte-level digest verification, cross-run replay protection, real-world or canary validation, machine-checked proofs.

## Archived files

`GPC_Research_Paper.pdf`, `GPC_Source.zip`, `GPC_Conceptual_Cover.png` and `SHA256SUMS.txt`.

## Publication

- Published on Zenodo on 2026-11-15: version DOI [10.5281/zenodo.24267416](https://doi.org/10.5281/zenodo.24267416); all-versions DOI [10.5281/zenodo.24267415](https://doi.org/10.5281/zenodo.24267415).
- The archived Zenodo files are unchanged. This repository adds the DOI to `README.md`, `CITATION.cff` and these release notes, and includes two editorial changes to the paper; the kernel, tests and fixtures are identical to the archived `GPC_Source.zip`.
