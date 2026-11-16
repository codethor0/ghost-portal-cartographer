"""Ghost Portal Cartographer: bounded read-only mapping of declared artifact lineage.

This standard-library-only reference kernel processes caller-supplied metadata.
It neither authenticates provenance nor confirms transfer of sensitive content.
It performs no collection, probing, network access, or egress prevention.
A synthetic HMAC checker authenticates metadata claims, never sanitization or provenance.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import re
from typing import Literal

Surface = Literal[
    'application', 'log', 'telemetry', 'trace', 'memory', 'cache',
    'backup', 'integration', 'external', 'other'
]
Mode = Literal['observed', 'inferred']
Flow = Literal['data', 'unknown', 'control', 'declassified']
Coverage = Literal['complete', 'partial', 'unknown']
Decision = Literal['DENIED', 'PERMITTED', 'UNSPECIFIED']
Status = Literal[
    'REPORTED_ORDERED_LINEAGE', 'REPORTED_ORDER_UNRESOLVED',
    'POSSIBLE_ROUTE', 'NO_ROUTE_IN_DECLARED_GRAPH', 'UNKNOWN_LIMIT'
]
Relation = Literal['ordered', 'reported', 'possible']
PathPolicyStatus = Literal['CONTAINS_DENIED', 'UNSPECIFIED', 'ALL_PERMITTED', 'NO_PATH']
SURFACES = frozenset(('application', 'log', 'telemetry', 'trace', 'memory',
                      'cache', 'backup', 'integration', 'external', 'other'))
COVERAGES = frozenset(('complete', 'partial', 'unknown'))
DIGEST_PATTERN = re.compile(r'^[0-9a-f]{64}$')
TRACE_PATTERN = re.compile(r'^[0-9a-f]{32}$')
SPAN_PATTERN = re.compile(r'^[0-9a-f]{16}$')
INVALID_TRACE_ID = '0' * 32  # W3C Trace Context: all-zero trace-id is invalid.
INVALID_SPAN_ID = '0' * 16  # W3C Trace Context: all-zero parent-id is invalid.
MAC_DOMAIN = b'GPC-DECLASSIFICATION-HMAC-DEMO\x00'


def _claim_payload(claim: 'DeclassificationClaim', source: str, output: str,
                   source_domain: str, output_domain: str) -> bytes:
    # An illustrative local HMAC message, NOT a DSSE or in-toto signature.
    # The claim is bound to the source and output artifact versions and their
    # declared domains, so a valid claim cannot be transplanted to an edge
    # between different artifacts or across a different trust boundary.
    values = asdict(claim)
    del values['mac_hex']
    values['bound_source'] = source
    values['bound_output'] = output
    values['bound_source_domain'] = source_domain
    values['bound_output_domain'] = output_domain
    return MAC_DOMAIN + json.dumps(values, sort_keys=True, separators=(',', ':'),
                                   ensure_ascii=True).encode('utf-8')



@dataclass(frozen=True)
class Node:
    id: str
    domain: str
    surface: Surface
    coverage: Coverage = 'unknown'
    sha256_digest: str | None = None  # Caller-provided digest; artifact bytes not verified.


@dataclass(frozen=True)
class DeclassificationClaim:
    attester_id: str
    category: str
    policy_id: str
    transform: str
    source_digest: str
    output_digest: str
    nonce: str
    issued_at: int
    expires_at: int
    mac_hex: str


@dataclass(frozen=True, repr=False)
class AttestationTrust:
    # In-process demonstration trust configuration. Never serialize secret_key.
    attester_id: str
    policy_id: str
    secret_key: bytes
    categories: tuple[str, ...]
    transforms: tuple[str, ...]

    def __repr__(self) -> str:
        return f'AttestationTrust(attester_id={self.attester_id!r}, key=<hidden>)'


@dataclass(frozen=True)
class Edge:
    id: str
    src: str
    dst: str
    mode: Mode
    flow: Flow
    sequence: int | None = None
    evidence: str | None = None
    causal_parent_id: str | None = None  # Claimed predecessor edge ID, not authenticated.
    trace_id: str | None = None
    span_id: str | None = None
    parent_span_id: str | None = None
    declassification: DeclassificationClaim | None = None

    @property
    def possible(self) -> bool:
        return self.flow in ('data', 'unknown', 'declassified')

    @property
    def reported(self) -> bool:
        # This is an unauthenticated input claim, NOT a verified observation.
        return (self.mode == 'observed' and self.flow in ('data', 'declassified')
                and isinstance(self.evidence, str) and bool(self.evidence.strip()))

    @property
    def ordered_eligible(self) -> bool:
        return self.reported and self.sequence is not None


@dataclass(frozen=True)
class Query:
    source: str
    destination_domain: str
    category: str  # Operator assertion, used by policy; not content classification.


@dataclass(frozen=True)
class SearchResult:
    relation: Relation
    path: tuple[str, ...] | None
    resolved: bool  # Positive witness found, or finite search exhausted.
    exhaustive: bool  # Entire reachable state space explored without a sink.
    limit_reached: bool
    examined_states: int
    discovered_states: int
    declared_coverage_gaps: tuple[str, ...]

    @property
    def found(self) -> bool:
        return self.path is not None


@dataclass(frozen=True)
class OrderIssue:
    edge_id: str
    position: int
    reason: Literal['MISSING_SEQUENCE', 'NON_INCREASING_SEQUENCE']
    previous_sequence: int | None
    sequence: int | None


@dataclass(frozen=True)
class CausalAnnotation:
    edge_id: str
    position: int
    claim: Literal['NO_PARENT_CLAIM', 'MATCHED_UNAUTHENTICATED_PARENT',
                   'CONFLICTING_PARENT', 'UNSCOPED_TRACE', 'TRACE_PARENT_MATCH',
                   'TRACE_PARENT_MISMATCH']
    claimed_parent_edge_id: str | None
    previous_edge_id: str | None
    provenance_trust: Literal['unauthenticated'] = 'unauthenticated'


@dataclass(frozen=True)
class DeclassificationAssessment:
    edge_id: str
    category: str | None
    status: Literal['AUTHENTICATED_METADATA_CLAIM', 'UNVERIFIED_CLAIM']
    reason: str
    edge_suppressed: Literal[False] = False


@dataclass(frozen=True)
class PolicyHop:
    node_id: str
    domain: str
    decision: Decision


@dataclass(frozen=True)
class Finding:
    status: Status
    policy: Decision  # Destination policy only; NOT a verdict on data movement.
    path: tuple[str, ...]
    ordered: SearchResult
    reported: SearchResult
    possible: SearchResult
    reported_path_order_issues: tuple[OrderIssue, ...]
    policy_hops: tuple[PolicyHop, ...]
    policy_path_status: PathPolicyStatus
    declared_coverage_gap_nodes: tuple[str, ...]  # Declared 'partial' or 'unknown' coverage.
    provenance_trust: Literal['unauthenticated']
    causal_annotations: tuple[CausalAnnotation, ...]
    declassification_assessments: tuple[DeclassificationAssessment, ...]
    caveat: str
    examined_states: int
    witness_source: Relation | None  # Search that returned the selected path.
    witness_reclassified: bool  # Selected path satisfies a stronger predicate than its search.

    def to_dict(self) -> dict:
        """JSON-safe, stable representation, including nested independent outcomes."""
        return asdict(self)


class Cartographer:
    """Search a finite, directed, version-identity graph without side effects.

    Sorted adjacency makes witnesses deterministic under input reordering.
    Each search independently uses `max_states` POPPED states as its budget.
    A returned positive witness is never erased by another search's limit.
    """

    def __init__(self, nodes: list[Node], edges: list[Edge],
                 policy: dict[tuple[str, str], Literal['DENIED', 'PERMITTED']] | None = None,
                 attestation_trust: dict[str, AttestationTrust] | None = None,
                 verification_epoch: int | None = None):
        if not isinstance(nodes, (list, tuple)) or not isinstance(edges, (list, tuple)):
            raise ValueError('nodes and edges must be sequences')
        if any(not isinstance(n, Node) for n in nodes):
            raise ValueError('nodes must contain Node records')
        if any(not isinstance(e, Edge) for e in edges):
            raise ValueError('edges must contain Edge records')
        if not isinstance(policy if policy is not None else {}, dict):
            raise ValueError('policy must be a mapping')
        if not isinstance(attestation_trust if attestation_trust is not None else {}, dict):
            raise ValueError('attestation_trust must be a mapping')
        if verification_epoch is not None and (type(verification_epoch) is not int or verification_epoch < 0):
            raise ValueError('verification_epoch must be a nonnegative integer or absent')
        self.verification_epoch = verification_epoch
        self.attestation_trust = dict(attestation_trust or {})
        for key, trust in self.attestation_trust.items():
            if (not _nonblank(key) or not isinstance(trust, AttestationTrust)
                    or key != trust.attester_id or not _nonblank(trust.policy_id)
                    or type(trust.secret_key) is not bytes or len(trust.secret_key) < 16
                    or type(trust.categories) is not tuple
                    or type(trust.transforms) is not tuple
                    or not trust.categories or not trust.transforms
                    or any(not _nonblank(x) for x in trust.categories + trust.transforms)):
                raise ValueError('invalid in-process attestation trust configuration')
        for n in nodes:
            if not _nonblank(n.id) or not _nonblank(n.domain):
                raise ValueError('invalid node identifier or domain')
            if not isinstance(n.surface, str) or not isinstance(n.coverage, str) \
                    or n.surface not in SURFACES or n.coverage not in COVERAGES:
                raise ValueError('invalid surface or declared coverage')
            if n.sha256_digest is not None and not _digest(n.sha256_digest):
                raise ValueError('invalid declared artifact digest')
        if len({n.id for n in nodes}) != len(nodes):
            raise ValueError('duplicate node id')
        for e in edges:
            if not _nonblank(e.id):
                raise ValueError('invalid edge identifier')
        if len({e.id for e in edges}) != len(edges):
            raise ValueError('duplicate edge id')
        self.nodes = {n.id: n for n in nodes}
        self.edges = {e.id: e for e in edges}
        self.policy: dict[tuple[str, str], Literal['DENIED', 'PERMITTED']] = dict(policy or {})
        for key, decision in self.policy.items():
            if (not isinstance(key, tuple) or len(key) != 2
                    or not all(_nonblank(item) for item in key)
                    or decision not in ('DENIED', 'PERMITTED')):
                raise ValueError('invalid explicit policy rule')
        self.out: dict[str, list[Edge]] = defaultdict(list)
        for e in edges:
            if not _nonblank(e.id):
                raise ValueError('invalid edge identifier')
            if not _nonblank(e.src) or not _nonblank(e.dst):
                raise ValueError(f'invalid edge endpoint: {e.id}')
            if e.src not in self.nodes or e.dst not in self.nodes:
                raise ValueError(f'dangling edge: {e.id}')
            if e.mode not in ('observed', 'inferred') or e.flow not in ('data', 'unknown', 'control', 'declassified'):
                raise ValueError('invalid edge type or mode')
            if e.sequence is not None and (type(e.sequence) is not int or e.sequence < 0):
                raise ValueError('sequence must be a nonnegative integer or absent')
            if e.evidence is not None and not isinstance(e.evidence, str):
                raise ValueError('evidence reference must be text or absent')
            if (e.causal_parent_id is not None and not _short_id(e.causal_parent_id)):
                raise ValueError('invalid claimed causal parent ID')
            if e.trace_id is not None and (not isinstance(e.trace_id, str)
                                           or not TRACE_PATTERN.fullmatch(e.trace_id)
                                           or e.trace_id == INVALID_TRACE_ID):
                raise ValueError('trace_id must be 32 lowercase hex characters, not all zero')
            for identifier in (e.span_id, e.parent_span_id):
                if identifier is not None and (not isinstance(identifier, str)
                                               or not SPAN_PATTERN.fullmatch(identifier)
                                               or identifier == INVALID_SPAN_ID):
                    raise ValueError('span IDs must be 16 lowercase hex characters, not all zero')
            if e.parent_span_id is not None and (e.trace_id is None or e.span_id is None):
                raise ValueError('parent span requires trace_id and span_id')
            if e.declassification is not None:
                if e.flow != 'declassified' or not isinstance(e.declassification, DeclassificationClaim):
                    raise ValueError('declassification claim requires declassified flow')
                _validate_declassification(e.declassification)
            elif e.flow == 'declassified':
                # Retain the edge and expose missing claim in the assessment.
                pass
            self.out[e.src].append(e)
        for adjacency in self.out.values():
            adjacency.sort(key=lambda e: e.id)

    def _search(self, relation: Relation, source: str, destination: str,
                budget: int) -> SearchResult:
        # Parent pointers encode ONE shared predecessor for every distinct
        # state, rather than copying each path on every queue expansion.
        start: tuple[str, int] | str = (source, -1) if relation == 'ordered' else source
        pending = deque([start])
        parent: dict[tuple[str, int] | str, tuple[tuple[str, int] | str, str] | None] = {start: None}
        examined = 0
        coverage_gaps: set[str] = set()
        while pending:
            if examined == budget:
                return SearchResult(relation, None, False, False, True, examined,
                                    len(parent), tuple(sorted(coverage_gaps)))
            state = pending.popleft()
            examined += 1
            vertex = state[0] if relation == 'ordered' else state
            if self.nodes[vertex].coverage != 'complete':
                coverage_gaps.add(vertex)
            if vertex != source and self.nodes[vertex].domain == destination:
                return SearchResult(relation, _reconstruct(parent, state), True,
                                    False, False, examined, len(parent),
                                    tuple(sorted(coverage_gaps)))
            for edge in self.out[vertex]:
                if relation == 'ordered':
                    if not edge.ordered_eligible or edge.sequence <= state[1]:
                        continue
                    next_state: tuple[str, int] | str = (edge.dst, edge.sequence)
                elif relation == 'reported':
                    if not edge.reported:
                        continue
                    next_state = edge.dst
                else:
                    if not edge.possible:
                        continue
                    next_state = edge.dst
                if next_state not in parent:
                    parent[next_state] = (state, edge.id)
                    pending.append(next_state)
        return SearchResult(relation, None, True, True, False, examined,
                            len(parent), tuple(sorted(coverage_gaps)))

    def _witness_satisfies(self, relation: Relation, source: str,
                           path: tuple[str, ...]) -> bool:
        """Check one returned path against the ordered or reported predicate."""
        if relation not in ('ordered', 'reported'):
            raise ValueError('witness re-verification applies to ordered or reported only')
        vertex, last = source, -1
        for edge_id in path:
            edge = self.edges[edge_id]
            if edge.src != vertex:
                return False
            if relation == 'ordered':
                if not edge.ordered_eligible or edge.sequence <= last:
                    return False
                last = edge.sequence
            elif not edge.reported:
                return False
            vertex = edge.dst
        return len(path) > 0 and vertex != source

    def _issues_on_reported_path(self, path: tuple[str, ...] | None) -> tuple[OrderIssue, ...]:
        if path is None:
            return ()
        problems = []
        previous = None
        for position, identifier in enumerate(path, start=1):
            edge = self.edges[identifier]
            seq = edge.sequence
            if seq is None:
                problems.append(OrderIssue(identifier, position, 'MISSING_SEQUENCE', previous, seq))
            elif previous is not None and seq <= previous:
                problems.append(OrderIssue(identifier, position, 'NON_INCREASING_SEQUENCE', previous, seq))
            previous = seq
        return tuple(problems)

    def _path_policy(self, source: str, path: tuple[str, ...],
                     category: str) -> tuple[tuple[PolicyHop, ...], PathPolicyStatus]:
        if not path:
            return (), 'NO_PATH'
        vertex = source
        hops = []
        for edge_id in path:
            edge = self.edges[edge_id]
            if edge.src != vertex:
                raise AssertionError('broken reconstructed path')
            vertex = edge.dst
            domain = self.nodes[vertex].domain
            hops.append(PolicyHop(vertex, domain, self.policy.get((category, domain), 'UNSPECIFIED')))
        if any(h.decision == 'DENIED' for h in hops):
            interpretation: PathPolicyStatus = 'CONTAINS_DENIED'
        elif any(h.decision == 'UNSPECIFIED' for h in hops):
            interpretation = 'UNSPECIFIED'
        else:
            interpretation = 'ALL_PERMITTED'
        return tuple(hops), interpretation

    def _causal_annotations(self, path: tuple[str, ...]) -> tuple[CausalAnnotation, ...]:
        items = []
        prev: Edge | None = None
        for pos, edge_id in enumerate(path, start=1):
            edge = self.edges[edge_id]
            claim = 'NO_PARENT_CLAIM'
            if edge.causal_parent_id is not None:
                if prev is not None and edge.causal_parent_id == prev.id:
                    claim = 'MATCHED_UNAUTHENTICATED_PARENT'
                else:
                    claim = 'CONFLICTING_PARENT'
            elif edge.parent_span_id is not None:
                if prev is None or prev.span_id is None or prev.trace_id is None:
                    claim = 'UNSCOPED_TRACE'
                elif prev.trace_id == edge.trace_id and prev.span_id == edge.parent_span_id:
                    claim = 'TRACE_PARENT_MATCH'
                else:
                    claim = 'TRACE_PARENT_MISMATCH'
            items.append(CausalAnnotation(edge.id, pos, claim,
                                          edge.causal_parent_id,
                                          prev.id if prev else None))
            prev = edge
        return tuple(items)

    def _assess_declassification(self, category: str) -> tuple[DeclassificationAssessment, ...]:
        assessments = []
        nonces: set[tuple[str, str]] = set()
        for edge in sorted(self.edges.values(), key=lambda edge: edge.id):
            if edge.flow != 'declassified':
                continue
            claim = edge.declassification
            reason = 'MISSING_CLAIM'
            authenticated = False
            if claim is not None:
                nonce = (claim.attester_id, claim.nonce)
                if nonce in nonces:
                    reason = 'DUPLICATE_NONCE_IN_GRAPH'
                else:
                    nonces.add(nonce)
                    rule = self.attestation_trust.get(claim.attester_id)
                    payload = _claim_payload(claim, edge.src, edge.dst,
                                             self.nodes[edge.src].domain,
                                             self.nodes[edge.dst].domain)
                    if rule is None:
                        reason = 'UNTRUSTED_ATTESTER'
                    elif not hmac.compare_digest(hmac.new(rule.secret_key, payload,
                                                          hashlib.sha256).hexdigest(), claim.mac_hex):
                        reason = 'MAC_MISMATCH'
                    elif claim.category != category:
                        reason = 'CATEGORY_MISMATCH'
                    elif claim.policy_id != rule.policy_id or category not in rule.categories \
                            or claim.transform not in rule.transforms:
                        reason = 'POLICY_MISMATCH'
                    elif self.verification_epoch is None:
                        reason = 'NO_VERIFICATION_TIME'
                    elif not claim.issued_at <= self.verification_epoch <= claim.expires_at:
                        reason = 'OUTSIDE_VALIDITY_WINDOW'
                    elif (self.nodes[edge.src].sha256_digest != claim.source_digest
                          or self.nodes[edge.dst].sha256_digest != claim.output_digest):
                        reason = 'ARTIFACT_DIGEST_MISMATCH'
                    else:
                        reason = 'MAC_VERIFIED_METADATA_ONLY'
                        authenticated = True
            assessments.append(DeclassificationAssessment(
                edge.id, claim.category if claim else None,
                'AUTHENTICATED_METADATA_CLAIM' if authenticated else 'UNVERIFIED_CLAIM',
                reason))
        return tuple(assessments)

    def analyze(self, query: Query, max_states: int = 10000) -> Finding:
        if not isinstance(query, Query):
            raise ValueError('expected Query record')
        if not _nonblank(query.source) or query.source not in self.nodes:
            raise ValueError('source not in inventory')
        if not _nonblank(query.category) or not _nonblank(query.destination_domain):
            raise ValueError('category and destination domain are required')
        if type(max_states) is not int or max_states < 1:
            raise ValueError('max_states must be a positive integer')
        if self.nodes[query.source].domain == query.destination_domain:
            raise ValueError('destination must be a different domain from the source')
        destination_policy: Decision = self.policy.get(
            (query.category, query.destination_domain), 'UNSPECIFIED')
        ordered = self._search('ordered', query.source, query.destination_domain, max_states)
        reported = self._search('reported', query.source, query.destination_domain, max_states)
        possible = self._search('possible', query.source, query.destination_domain, max_states)

        # Witness-first selection. A returned witness is re-verified against
        # the stronger predicates, so a capped stronger search cannot cause a
        # weaker label for a witness that already satisfies the stronger one.
        # Re-verification only inspects the returned edges; it never relaxes
        # the strict-order guard and never consults parentage or claims.
        source_relation: Relation | None = None
        if ordered.found:
            source_relation, chosen = 'ordered', ordered.path
        elif reported.found:
            source_relation, chosen = 'reported', reported.path
        elif possible.found:
            source_relation, chosen = 'possible', possible.path
        else:
            chosen = ()
        if source_relation is not None:
            if self._witness_satisfies('ordered', query.source, chosen):
                status: Status = 'REPORTED_ORDERED_LINEAGE'
                satisfied: Relation = 'ordered'
            elif self._witness_satisfies('reported', query.source, chosen):
                status, satisfied = 'REPORTED_ORDER_UNRESOLVED', 'reported'
            else:
                status, satisfied = 'POSSIBLE_ROUTE', 'possible'
            if source_relation == 'ordered' and satisfied != 'ordered':
                raise AssertionError('ordered search returned a witness that fails the ordered predicate')
            if source_relation == 'reported' and satisfied == 'possible':
                raise AssertionError('reported search returned a non-reported witness')
            reclassified = satisfied != source_relation
        elif possible.exhaustive:
            # Proposition 1: no possible route implies no reported or ordered
            # route, so an exhaustive negative possible search is decisive even
            # if a narrower search reached its cap.
            status, reclassified = 'NO_ROUTE_IN_DECLARED_GRAPH', False
        elif any(t.limit_reached for t in (ordered, reported, possible)):
            status, reclassified = 'UNKNOWN_LIMIT', False
        else:
            status, reclassified = 'NO_ROUTE_IN_DECLARED_GRAPH', False
        # Only a completed *negative* broader search can contradict a positive
        # narrower witness. Budget-limited searches must never erase evidence.
        if ordered.found and reported.exhaustive and not reported.found:
            raise AssertionError('ordered witness omitted from completed reported search')
        if reported.found and possible.exhaustive and not possible.found:
            raise AssertionError('reported witness omitted from completed possible search')
        if ordered.found and possible.exhaustive and not possible.found:
            raise AssertionError('ordered witness omitted from completed possible search')
        gaps = tuple(sorted(set(ordered.declared_coverage_gaps)
                            | set(reported.declared_coverage_gaps)
                            | set(possible.declared_coverage_gaps)))
        hops, path_status = self._path_policy(query.source, tuple(chosen), query.category)
        if status == 'REPORTED_ORDERED_LINEAGE':
            caveat = ('The input reports reference-backed, scalar-ordered lineage; '
                      'neither provenance authenticity nor sensitive-byte transfer is established.')
        elif status == 'REPORTED_ORDER_UNRESOLVED':
            caveat = ('The input reports a reference-backed route, but no qualifying ordered '
                      'witness was established; scalar sequence metadata can be missing, '
                      'non-increasing, spoofed, or search-limited.')
        elif status == 'POSSIBLE_ROUTE':
            caveat = ('A data-or-unknown-content route exists in the supplied graph; '
                      'carriage, timing, and stronger provenance may remain unestablished.')
        elif status == 'UNKNOWN_LIMIT':
            caveat = ('No positive witness was found before at least one cap was reached; '
                      'this is not a negative finding about the graph or the real world.')
        else:
            caveat = ('No route exists in the enumerated finite graph under this model; '
                      'absence from incomplete or adversarially modified inputs is not safety.')
        return Finding(status=status, policy=destination_policy,
                       path=tuple(chosen), ordered=ordered, reported=reported, possible=possible,
                       reported_path_order_issues=self._issues_on_reported_path(
                           tuple(chosen) if status == 'REPORTED_ORDER_UNRESOLVED' else None),
                       policy_hops=hops, policy_path_status=path_status,
                       declared_coverage_gap_nodes=gaps, provenance_trust='unauthenticated',
                       causal_annotations=self._causal_annotations(tuple(chosen)),
                       declassification_assessments=self._assess_declassification(query.category),
                       caveat=caveat + (' Authenticated transformation METADATA is not proof of '
                                        'semantic sanitization; declassified edges remain traversable.'),
                       examined_states=(ordered.examined_states + reported.examined_states
                                        + possible.examined_states),
                       witness_source=source_relation,
                       witness_reclassified=reclassified)


def _nonblank(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _short_id(value: object) -> bool:
    return _nonblank(value) and len(value) <= 256 and not any(ord(c) < 32 for c in value)


def _digest(value: object) -> bool:
    return isinstance(value, str) and bool(DIGEST_PATTERN.fullmatch(value))


def _validate_declassification(claim: DeclassificationClaim) -> None:
    for text in (claim.attester_id, claim.category, claim.policy_id,
                 claim.transform, claim.nonce):
        if not _short_id(text):
            raise ValueError('invalid declassification claim text field')
    if not _digest(claim.source_digest) or not _digest(claim.output_digest):
        raise ValueError('invalid declassification artifact digest')
    if (type(claim.issued_at) is not int or type(claim.expires_at) is not int
            or claim.issued_at < 0 or claim.expires_at < claim.issued_at):
        raise ValueError('invalid declassification validity window')
    if not _digest(claim.mac_hex):
        raise ValueError('declassification mac_hex requires 64 lowercase hex characters')


def _reconstruct(parent: dict, state: tuple[str, int] | str) -> tuple[str, ...]:
    path = []
    while parent[state] is not None:
        predecessor, edge_id = parent[state]
        path.append(edge_id)
        state = predecessor
    path.reverse()
    return tuple(path)


def _record(item: object, required: set[str], optional: set[str], name: str) -> dict:
    if not isinstance(item, dict):
        raise ValueError(f'{name} must be a JSON object')
    missing = required - item.keys()
    extra = item.keys() - (required | optional)
    if missing:
        raise ValueError(f'{name} is missing: {", ".join(sorted(missing))}')
    if extra:
        raise ValueError(f'{name} has unknown fields: {", ".join(sorted(extra))}')
    return item


def from_json_dict(raw: dict) -> Cartographer:
    """Strict local JSON metadata loader. No payload bytes are inspected."""
    if not isinstance(raw, dict):
        raise ValueError('root must be a JSON object')
    _record(raw, {'nodes', 'edges'}, {'policy', 'query', 'description'}, 'root')
    if not isinstance(raw['nodes'], list) or not isinstance(raw['edges'], list):
        raise ValueError('nodes and edges must be JSON lists')
    if not isinstance(raw.get('policy', []), list):
        raise ValueError('policy must be a JSON list')
    nodes = [Node(**_record(item, {'id', 'domain', 'surface'},
                            {'coverage', 'sha256_digest'}, 'node'))
             for item in raw['nodes']]
    edges = []
    for item in raw['edges']:
        entry = dict(_record(item, {'id', 'src', 'dst', 'mode', 'flow'},
                             {'sequence', 'evidence', 'causal_parent_id', 'trace_id',
                              'span_id', 'parent_span_id', 'declassification'}, 'edge'))
        if 'declassification' in entry and entry['declassification'] is not None:
            claim = _record(entry['declassification'],
                            {'attester_id', 'category', 'policy_id', 'transform',
                             'source_digest', 'output_digest', 'nonce',
                             'issued_at', 'expires_at', 'mac_hex'},
                            set(), 'declassification')
            entry['declassification'] = DeclassificationClaim(**claim)
        edges.append(Edge(**entry))
    rules = {}
    for item in raw.get('policy', []):
        entry = _record(item, {'category', 'domain', 'decision'}, set(), 'policy entry')
        if not _nonblank(entry['category']) or not _nonblank(entry['domain']) \
                or entry['decision'] not in ('DENIED', 'PERMITTED'):
            raise ValueError('invalid category, domain or decision in policy entry')
        key = (entry['category'], entry['domain'])
        if key in rules:
            raise ValueError('duplicate policy rule')
        rules[key] = entry['decision']
    return Cartographer(nodes, edges, rules)
