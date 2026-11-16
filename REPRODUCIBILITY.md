# Reproducibility and independent inspection

All experiments use invented graph metadata, with no network, real credentials or customer information.

## Requirements

- Python 3.9+ using its standard library; the suite was run on CPython 3.9.6 through 3.15.2, macOS 27.2 arm64, with network access denied.
- Optional LaTeX build: `latexmk -pdf -interaction=nonstopmode -halt-on-error GPC_Research_Paper.tex` with `newtxtext`, `amsmath`, `tikz`, `hyperref` and the standard packages listed at manuscript start.
- SHA-256 CLI: `sha256sum`, or `shasum -a 256` on macOS.

## Recommended full reproduction

```sh
sh RUN_AUDIT.sh
```

The audit verifies the source-hash manifest, runs all tests and the synthetic demo, creates eleven faulty test-only mutants in temporary directories and runs synthetic benchmarks into a temporary file. It does not modify production data or source files.

Individual commands:

```sh
python -m unittest -v test_gpc.py
python run_demo.py
python mutation_check.py MUTATION_RESULTS.json
python benchmark.py BENCHMARK_DATA.csv
sha256sum -c SOURCE_HASHES.sha256
```

## Test accounting

- 171 `unittest` methods, all successful in the captured runs.
- Two distinct existing oracle methods each cover 1,200 fixed-seed synthetic graphs.
- One additional method compares the kernel and both oracles on 400 fixed-seed mixed-flow graphs containing `declassified` edges.
- Two exhaustive small-graph methods enumerate 512 possible-edge graphs and 625 observation mappings.
- Three edge-addition methods cover 1,000 fixed-seed cases; another checks 500 budget combinations.
- Eleven deliberately incorrect mutants are caught in isolated temporary directories. See `MUTATION_RESULTS.json` and `mutation_check.py`.

A method count is not a case count; these totals overlap only as specified in the test source. The two oracles verify their encoded graph predicates, not the truth of reported telemetry, signed artifacts or semantic sanitization.

## HMAC test construction

`DeclassificationClaim` is synthetic metadata. Tests use only in-process test keys, canonical sorted compact JSON, a fixed domain-separation prefix, and `hmac.compare_digest`. The test output distinguishes `AUTHENTICATED_METADATA_CLAIM` from `UNVERIFIED_CLAIM`, but **neither status suppresses any graph path**. Digests are compared to declared node digests, not independently hashed from actual input/output bytes. A current epoch must be explicitly provided. Duplicate nonces are rejected only within the one analyzed graph, not across previous runs.

## Benchmarks and limits

`benchmark.py` records synthetic line/star/dense graph timings and `tracemalloc` traced peak KiB for one run per shape, including graph construction and analysis, excluding source file parsing, PDF build, OS allocations and JSON serialization. These are environment dependent, not production throughput. The source graph can consume memory before the popped-state caps apply. See `BENCHMARK_DATA.csv`.

## Integrity

`SOURCE_HASHES.sha256` names fixed archive members except itself. `sha256sum -c SOURCE_HASHES.sha256` validates extracted source and PDF bytes. The outer `SHA256SUMS.txt` shipped next to the archive identifies the archive bytes; the PDF inside the archive is the distributed PDF.

## What would falsify the claims?

Use independent reviewer-created tests for: an exhaustive-search miss, a positive result erased by another search limit, a parent ID wrongly upgrading scalar order, any declassification claim deleting an edge, or a mismatched policy/digest/expiry/tag passing claim verification. A meaningful real-world study requires independent actual-byte ground truth, a documented observation boundary, controlled collectors and appropriately assessed privacy and consent.

## Independent re-audit precision notes

- Test methods: 171. Witness re-verification, decisive negatives, claim binding and validation boundaries are covered by `SelectionBindingAndBoundaryTests`.
- `Cartographer(..., attestation_trust=..., verification_epoch=...)` receives caller-owned in-memory trust settings, not JSON. No key is serialized or printed. Missing trust yields `UNVERIFIED_CLAIM` with reason `UNTRUSTED_ATTESTER`; absent epoch yields `NO_VERIFICATION_TIME`.
- Duplicate nonces are detected within one `analyze()` invocation after lexical edge-ID sorting, using `(attester_id, nonce)`. There is no cross-invocation persistence, key rotation or revocation mechanism. A replay in a later invocation may pass again; this is an explicit limitation of the demonstration.
- Reported trace metadata has optional `trace_id`, `span_id`, and `parent_span_id`. A claimed edge predecessor has diagnostic precedence over the parent-span test; neither affects scalar ordering or path eligibility.
- The table of benchmark values in the PDF is a rounded selection from `BENCHMARK_DATA.csv`, regenerated on the revised kernel (CPython 3.15.2, macOS arm64). All nine rows are negative, full-exploration queries. A later `RUN_AUDIT.sh` benchmark is independent and writes to a temporary CSV.
