# Security model and non-guarantees

**Purpose.** Bounded, read-only analysis of caller-supplied metadata about possible indirect sensitive-data paths. It does not monitor a live environment, capture content, enforce policy, authenticate collector telemetry or prove physical disclosure.

**Input adversary.** An attacker may forge or omit edges, invent evidence locators, alter version identifiers and clock/trace/parent metadata, change declared digests, and falsely claim sanitization. A graph algorithm cannot reconstruct a wholly omitted edge or determine if content was transferred when input metadata is unfaithful.

**Positive evidence:** `REPORTED_ORDERED_LINEAGE` means a reported locator-backed path with strictly increasing scalar metadata. `REPORTED_ORDER_UNRESOLVED` means reported topology exists, no ordered witness was found in the bounded run, and the selected reported witness itself fails the strict-order predicate. `POSSIBLE_ROUTE` means a data/unknown/declassified flow path in the declared graph. All are **conditional graph results**. Declared provenance trust is always `unauthenticated`.

**Negative evidence:** `NO_ROUTE_IN_DECLARED_GRAPH` is only about exhaustive search of the finite supplied graph. `UNKNOWN_LIMIT` means there was no positive witness before at least one search cap and the possible search did not finish (an exhaustive negative possible search is reported as `NO_ROUTE_IN_DECLARED_GRAPH`). Neither asserts real-world safety.

**Ordering and parentage:** Trace ID, span ID, parent span ID and `causal_parent_id` are correlation claims. Matching values do not override strict scalar ordering, certify distributed causality, or establish sensitive-byte carriage. Conflicts are retained as diagnostic information, not dismissed.

**Transformation metadata:** A local HMAC-SHA256 checker authenticates synthetic metadata relative to an in-process symmetric test key, configured policy, declared digests, category and supplied epoch. This is not a public-key signature, DSSE, in-toto, source byte verification, artifact sanitization proof or production credential workflow. The MAC binds the claim to the source and output artifact versions and their declared domains of the edge carrying it, so a valid claim cannot be transplanted to a different artifact pair or trust boundary. A good MAC does not suppress candidate flow. A syntactically malformed claim causes the whole input to be rejected (fail-closed), which also means a single malformed claim from any party prevents analysis. All declared `declassified` edges remain traversable for every category. A failed MAC, missing claim, wrong scope or time window cannot cause a false negative by edge removal.

**Authorization:** Path-policy annotations refer to the selected witness only. They do not prove that all graph paths are authorized or that legal requirements are met. A configured permission is not proof of physical transfer.

**Resource attacks:** All three searches have bounded popped-state budgets. Graph construction, untrusted evidence strings, huge inputs and Python memory allocation are not globally resource bounded. External importers must size-limit, validate and authenticate metadata before production use.

**Privacy:** The tool does no probing or network access, but even metadata about routes can expose system topology. Production collection, access control, retention and secure secret handling are out of scope.

**Evaluation boundary:** Unit, randomized, exhaustive small-graph and mutation tests verify graph semantics under synthetic inputs. Field precision/recall, detection latency, real-world attacker resilience, independent peer review and formal machine verification remain unestablished.

## HMAC trust and replay boundary

`attestation_trust` is passed in process by the caller; it binds attester IDs to a demonstration symmetric key and permitted policy, categories and transforms. The `verification_epoch` is supplied by the caller and is not independently established by a clock service. The kernel does not fetch trust, persist keys, record cross-run nonce use, revoke identities, or verify actual source/output artifact bytes. Within one `analyze()` invocation, reuse of the same `(attester_id, nonce)` after the first edge in lexicographic edge-ID order produces `DUPLICATE_NONCE_IN_GRAPH`. That limitation must not be called production replay protection.

Trace metadata is an optional `trace_id`, `span_id`, `parent_span_id` tuple. A claimed edge-parent field takes precedence in contextual diagnostics; matching trace-parent IDs cannot establish causality and never override strict scalar ordering. All-zero trace and span identifiers are rejected as W3C-invalid. See `SelectionBindingAndBoundaryTests` in `test_gpc.py`.
