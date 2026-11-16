# Formal specification: Ghost Portal Cartographer

## Graph and query

Let `G=(V,E)` be a finite directed graph of declared artifact versions. Each vertex has a declared trust domain and surface, an unverified inventory-coverage claim and optionally a declared SHA-256 digest. Each edge has a unique identifier, endpoints, mode `observed|inferred`, flow `data|unknown|control|declassified`, an optional nonnegative scalar sequence and optional evidence locator. Additional optional parent/trace identifiers and transformation claims are metadata annotations, **not** verified proof of lineage.

For a query `q=(s,c,d)` with `domain(s) != d`, define the three relations:

```
E_P = {e | flow(e) in {data, unknown, declassified}}
E_R = {e in E_P | mode(e)=observed AND flow(e) in {data,declassified}
                 AND evidence(e) is a nonblank string}
E_O = {e in E_R | sequence(e) is present}
```

`P(q)` means a directed path from `s` to a different vertex in destination domain `d` in `E_P`. `R(q)` means the same in `E_R`. `O(q)` means a path in `E_O` whose sequence values strictly increase. Hence `O(q) => R(q) => P(q)` in the declared graph. These predicates are about graph metadata only, not bytes or transfer.

## Search and priority

`OrderedRoute` applies BFS to states `(vertex,last_sequence)`, starting at `(s,-1)`; a transition is eligible when the next sequence exceeds the prior. `ReportedRoute` and `PossibleRoute` apply ordinary vertex BFS. Every search has an independent positive popped-state cap. Witnesses use parent-pointer reconstruction.

Positive results are prioritized `ordered > reported > possible`. The returned witness is then re-verified against the stronger predicates (edge eligibility and strict order on the returned edges only), so a witness returned by the reported or possible search that already satisfies a stronger predicate receives the stronger status; the result records `witness_source` and `witness_reclassified`. If no search found a witness and the possible search was exhaustive, report `NO_ROUTE_IN_DECLARED_GRAPH` (by containment this is decisive for all three relations). Otherwise, if any search was capped, report `UNKNOWN_LIMIT`. A capped search cannot erase another search's positive witness. Search outcomes separately record resolved, exhaustive, cap reached, examined/discovered states, evidence path, and declared coverage gaps.

## Reported correlation context

For consecutive path edges `e_i` and `e_(i+1)`, `claimed_parent_match` is the input equality `causal_parent_id(e_(i+1)) == id(e_i)`. A trace-parent match additionally compares reported trace IDs and preceding span IDs. These equalities do not change `E_O`, `E_R` or `E_P` and never upgrade authentication. A scalar inversion can remain `REPORTED_ORDER_UNRESOLVED` with a matched-context annotation. Correlation is not proof of causation or information movement.

## HMAC metadata-claim demonstration

For a declared `declassified` edge, a local in-process trust policy may authenticate a synthetic metadata claim by requiring:

- A configured attester and matching policy ID, allowed category and transform;
- A correct HMAC-SHA256 tag over domain-separated, sorted compact JSON containing all non-MAC claim fields **and** the bound source artifact, output artifact, source domain and output domain of the edge carrying the claim (the tag is checked immediately after the attester lookup, before any field-specific reason is reported);
- Exact matching of **declared** source/output digest fields with **declared** node digests;
- A supplied verification epoch within the claim's validity interval;
- No repeated `(attester_id, nonce)` already encountered in the current graph.

The claim is then `AUTHENTICATED_METADATA_CLAIM`. Missing/untrusted/invalid claims are `UNVERIFIED_CLAIM` with reason. The HMAC only authenticates a claim relative to the supplied test key, not the physical artifact bytes. No semantic sanitization is established; **no edge is excluded based on any declassification metadata**. This rule is deliberate: `ExcludeForClaim(e,c)=false` for all candidate edges and categories. The trust key is never serialized or emitted as part of a result. Historical replay outside a graph snapshot is not detected.

## Propositions and proof sketches

1. **Containment:** `O => R => P`. Each narrower witness consists solely of edges admitted by the broader relation; the order restriction can only reduce reachability.
2. **Priority preservation:** Positive status branches precede the limited-search branch. The decision rule cannot return `UNKNOWN_LIMIT` when any positive result is present.
2a. **Strongest-tier labeling of the returned witness:** the status is the strongest relation whose predicate the selected witness satisfies. Re-verification never relaxes the strict-order guard and never consults parentage or claims.
2b. **Decisive negative:** if the possible search is exhaustive without a witness, Proposition 1 gives `not P(q)`, hence `not R(q)` and `not O(q)`.
2c. **Simple witnesses:** a minimum-hop ordered walk returned by BFS is vertex-simple (a repeated vertex admits a strictly shorter ordered walk).
3. **Exhaustive correctness:** With no cap, vertex BFS decides finite reachability and `(vertex,last_sequence)` BFS decides the finite strict-order predicate; equal states have identical admissible continuations.
4. **Conditional edge-addition monotonicity:** With existing edge metadata, topology, domain labels and query fixed, adding edges cannot remove an existent route in a relation. Budgeted results need not be monotonic.
5. **Metadata-claim non-suppression:** Altering authentication of an unchanged, well-formed `declassified` claim cannot change the graph relation sets (a syntactically malformed claim causes the entire input to be rejected with `ValueError`, so no partial result is produced); no valid graph route is removed by such a change. This is **not** a theorem about physical sanitization.

## Complexity

Sorting all adjacency lists costs `O(m log(m+1))` in the worst case. Vertex-only BFS is `O(n+m)` time with `O(n)` auxiliary memory (excluding graph storage). Ordered search has at most `m+1` distinguishable post-edge states, worst-case `O(n+m^2)` time and `O(n+m)` graph-plus-search memory. A successful witness reconstructs in `O(path length)`. The metadata-claim scan has `O(m)` records with bounded-length checks. Physical input loading, Python object overhead, logs and serialization are outside these abstract graph bounds.

## Falsification conditions

Find an exhaustive-search counterexample; show a positive witness erased by an independent budget; show a parent ID upgrading ordered status despite an unchanged non-increasing sequence; show any transformation claim suppressing a candidate edge; show a metadata MAC accepted under altered policy/digest/category, wrong test key, repeated nonce or expired epoch. These are concrete counterexamples to the implemented, conditional claims. They do not amount to testing real-world leak-detection accuracy.

## Precise boundaries established by independent re-audit

The optional trace tuple is `tau(e) = (trace_id(e), span_id(e), parent_span_id(e))`; each field may be absent. All-zero trace and span identifiers, which W3C Trace Context defines as invalid, are rejected. The claimed parent-span match requires the next edge to have no explicit claimed edge-parent, equal nonmissing declared trace IDs, and `next.parent_span_id == previous.span_id` with both span IDs nonmissing. The implementation emits contextual annotations only and never uses this predicate as a graph-transition guard.

For a declassified edge, `NonceFirst_G(e)` is true exactly when no previously processed declassified edge with a claim, in sorted edge-ID order within the same `analyze()` invocation, has the same `(attester_id, nonce)` pair. It is not a global nonce invariant. `AttestationTrust` and `verification_epoch` are supplied separately to the constructor; all artifact digests remain caller-declared.

For fixed other edge attributes, replacing `flow=data` with `flow=declassified` preserves the path relations exactly, while adding an optional separate HMAC diagnostic. Proposition 5 applies only when graph topology, edge types, and reported evidence metadata remain fixed.
