"""Reference DFS oracles for small finite synthetic graphs.

These are algorithmically separate from the production-style BFS kernel.
They check graph semantics, not metadata honesty or real-world causality.
"""


def oracle_possible(nodes, edges, source, destination_domain):
    domain = {n.id: n.domain for n in nodes}
    adj = {n.id: [] for n in nodes}
    for edge in edges:
        if edge.flow in ('data', 'unknown', 'declassified'):
            adj[edge.src].append(edge.dst)
    stack = [source]
    seen = set()
    while stack:
        vertex = stack.pop()
        if vertex in seen:
            continue
        seen.add(vertex)
        if vertex != source and domain[vertex] == destination_domain:
            return True
        stack.extend(adj[vertex])
    return False


def oracle_reported(nodes, edges, source, destination_domain):
    domain = {n.id: n.domain for n in nodes}
    adj = {n.id: [] for n in nodes}
    for edge in edges:
        if (edge.mode == 'observed' and edge.flow in ('data', 'declassified')
                and isinstance(edge.evidence, str) and bool(edge.evidence.strip())):
            adj[edge.src].append(edge.dst)
    stack = [source]
    seen = set()
    while stack:
        vertex = stack.pop()
        if vertex in seen:
            continue
        seen.add(vertex)
        if vertex != source and domain[vertex] == destination_domain:
            return True
        stack.extend(adj[vertex])
    return False


def oracle_ordered(nodes, edges, source, destination_domain):
    domain = {n.id: n.domain for n in nodes}
    adj = {n.id: [] for n in nodes}
    for edge in edges:
        if (edge.mode == 'observed' and edge.flow in ('data', 'declassified')
                and isinstance(edge.evidence, str) and bool(edge.evidence.strip())
                and edge.sequence is not None):
            adj[edge.src].append(edge)
    stack = [(source, -1)]
    seen = set()
    while stack:
        vertex, prior = stack.pop()
        if (vertex, prior) in seen:
            continue
        seen.add((vertex, prior))
        if vertex != source and domain[vertex] == destination_domain:
            return True
        for edge in adj[vertex]:
            if edge.sequence > prior:
                stack.append((edge.dst, edge.sequence))
    return False


# Original test clients can still call this name, without using old statuses.
oracle_observed = oracle_ordered
