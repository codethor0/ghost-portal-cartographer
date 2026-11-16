"""Independent raw-JSON graph oracle for small finite synthetic graphs.

No imports from gpc or independent_oracle. The implementation enumerates
edge-index traces with depth-first search and compares their admissibility.
This is independently coded but necessarily shares the specified predicates;
no software-only oracle can authenticate third-party telemetry or clocks.
"""


def raw_reachability(document, source, destination_domain):
    nodes = {entry['id']: entry for entry in document['nodes']}
    edges = list(document['edges'])
    adjacent = {ident: [] for ident in nodes}
    for edge_number, edge in enumerate(edges):
        adjacent[edge['src']].append(edge_number)

    def explore(route_type):
        # This finite exhaustive trace enumerator is intentionally restricted
        # to small graphs in the tests. The strict-order case may revisit a
        # vertex, but each transition consumes a strictly greater sequence.
        stack = [(source, -1, tuple())]
        while stack:
            current, previous, used = stack.pop()
            if current != source and nodes[current]['domain'] == destination_domain:
                return True
            for index in adjacent[current]:
                edge = edges[index]
                if edge.get('flow') == 'control':
                    continue
                if route_type != 'possible':
                    if (edge.get('mode') != 'observed' or edge.get('flow') not in ('data', 'declassified')
                            or not isinstance(edge.get('evidence'), str)
                            or not edge.get('evidence', '').strip()):
                        continue
                if route_type == 'ordered':
                    seq = edge.get('sequence')
                    if seq is None or seq <= previous:
                        continue
                    if index in used:
                        continue
                    stack.append((edge['dst'], seq, used + (index,)))
                else:
                    # Any reachable route can be made vertex-simple. Repeating
                    # an edge is therefore unnecessary for existence tests.
                    visited_nodes = {source}
                    for former in used:
                        visited_nodes.add(edges[former]['dst'])
                    if edge['dst'] in visited_nodes:
                        continue
                    stack.append((edge['dst'], previous, used + (index,)))
        return False

    return {'ordered': explore('ordered'),
            'reported': explore('reported'),
            'possible': explore('possible')}
