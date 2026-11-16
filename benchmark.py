"""Reproducible local-only synthetic runtime and traced-memory measurements.

Measurements are environment-specific, include graph construction, and exclude
LaTeX/PDF build and JSON serialization. They are not production benchmarks.
"""
from __future__ import annotations

import csv
import platform
import sys
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

from gpc import Cartographer, Edge, Node, Query


def make_case(kind, size):
    nodes = [Node('s', 'internal', 'application', 'complete'),
             Node('v', 'vendor', 'external', 'complete')]
    edges = []
    if kind == 'line':
        nodes.extend(Node(f'x{i}', 'internal', 'log', 'complete') for i in range(size))
        previous = 's'
        for i in range(size):
            vertex = f'x{i}'
            edges.append(Edge(f'e{i:06d}',previous,vertex,'observed','data',i+1,'synthetic:ref'))
            previous = vertex
    elif kind == 'star':
        nodes.extend(Node(f'x{i}', 'internal', 'telemetry', 'complete') for i in range(size))
        edges.extend(Edge(f'e{i:06d}', 's',f'x{i}', 'inferred','unknown') for i in range(size))
    elif kind == 'dense':
        # Dense directed graph among non-destination vertices, excluding loops.
        nodes.extend(Node(f'x{i}', 'internal', 'cache', 'complete') for i in range(size))
        ids=['s']+[f'x{i}' for i in range(size)]
        for i,a in enumerate(ids):
            for j,b in enumerate(ids):
                if i != j:
                    edges.append(Edge(f'e{i:04d}_{j:04d}',a,b,'inferred','data'))
    else:
        raise ValueError('unrecognized benchmark graph')
    return nodes,edges


def benchmark(output_path='BENCHMARK_DATA.csv'):
    cases=[('line',250),('line',1000),('line',3000),
           ('star',250),('star',1000),('star',3000),
           ('dense',30),('dense',60),('dense',120)]
    metadata={
        'python':sys.version.split()[0],
        'platform':platform.platform(),
        'timestamp_utc':datetime.now(timezone.utc).isoformat(),
        'note':'local synthetic graph benchmark; no real data and no production claims'
    }
    rows=[]
    for kind,size in cases:
        tracemalloc.start()
        start=time.perf_counter()
        nodes,edges=make_case(kind,size)
        model=Cartographer(nodes,edges)
        finding=model.analyze(Query('s','vendor','SECRET'),max_states=100000)
        elapsed=time.perf_counter()-start
        _,peak=tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rows.append(dict(kind=kind,size=size,nodes=len(nodes),edges=len(edges),
                         seconds=round(elapsed,6),peak_kib=round(peak/1024,2),
                         examined=finding.examined_states,status=finding.status))
        print(f'{kind:<5} {size:>5} nodes={len(nodes):>6} edges={len(edges):>7} '
              f'elapsed={elapsed:.4f}s peak={peak/1024:.1f}KiB')
    with open(output_path,'w',newline='',encoding='utf-8') as out:
        out.write(f'# environment: {metadata}\n')
        writer=csv.DictWriter(out,fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return metadata,rows


if __name__ == '__main__':
    benchmark(sys.argv[1] if len(sys.argv) > 1 else 'BENCHMARK_DATA.csv')
