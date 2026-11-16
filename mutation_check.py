"""Small controlled mutation analysis run entirely in an isolated temp folder.

Mutants are intentionally incorrect algorithm variants. The canonical code
and the user's original artifacts are never modified.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
SOURCE = (BASE / 'gpc.py').read_text(encoding='utf-8')
MUTATIONS = {
    'budget_overrides_positive': (
        "        if source_relation is not None:\n",
        "        if possible.limit_reached:\n            status, reclassified, chosen, source_relation = 'UNKNOWN_LIMIT', False, (), None\n        elif source_relation is not None:\n"),
    'ignore_sequence_inversion': (
        "if not edge.ordered_eligible or edge.sequence <= state[1]:",
        "if not edge.ordered_eligible:"),
    'collapsing_ordered_state': (
        "next_state: tuple[str, int] | str = (edge.dst, edge.sequence)",
        "next_state: tuple[str, int] | str = (edge.dst, 0)"),
    'unauthenticated_parent_falsely_upgrades': (
        "if not edge.ordered_eligible or edge.sequence <= state[1]:",
        "if not edge.ordered_eligible or (edge.sequence <= state[1] and edge.causal_parent_id is None):"),
    'drop_unverified_declassification': (
        "return self.flow in ('data', 'unknown', 'declassified')",
        "return self.flow in ('data', 'unknown')"),
    'accept_no_evidence': (
        "and isinstance(self.evidence, str) and bool(self.evidence.strip()))",
        "and True)"),
    'reverification_skips_order_check': (
        "if not edge.ordered_eligible or edge.sequence <= last:",
        "if not edge.ordered_eligible:"),
    'negative_possible_search_not_decisive': (
        "        elif possible.exhaustive:\n",
        "        elif False:\n"),
    'claim_not_bound_to_artifacts': (
        "    values['bound_source'] = source\n    values['bound_output'] = output\n"
        "    values['bound_source_domain'] = source_domain\n    values['bound_output_domain'] = output_domain\n",
        ""),
    'diagnostics_on_reported_search_path': (
        "tuple(chosen) if status == 'REPORTED_ORDER_UNRESOLVED' else None),",
        "reported.path),"),
    'accept_all_zero_trace_id': (
        "                                           or e.trace_id == INVALID_TRACE_ID):",
        "                                           ):"),
}


def main(output_path='MUTATION_RESULTS.json'):
    results=[]
    with tempfile.TemporaryDirectory(prefix='gpc_mutation_') as tmp:
        workspace=Path(tmp)
        for fname in ('test_gpc.py','independent_oracle.py','independent_oracle_raw.py','synthetic_example.json'):
            shutil.copy2(BASE / fname,workspace / fname)
        for name,(old,new) in MUTATIONS.items():
            if SOURCE.count(old)!=1:
                raise RuntimeError(f'Could not target mutation exactly: {name}')
            (workspace/'gpc.py').write_text(SOURCE.replace(old,new),encoding='utf-8')
            output=subprocess.run([sys.executable,'-m','unittest','-q','test_gpc.py'],
                                  cwd=workspace,capture_output=True,text=True,timeout=60)
            killed=(output.returncode!=0)
            failed=re.search(r'FAILED \(([^)]*)\)',output.stderr)
            details=failed.group(1) if failed else ('test run passed' if not killed else 'other failure')
            results.append(dict(mutant=name,killed=killed,details=details))
            print(f'{name}: {"KILLED" if killed else "SURVIVED"} ({details})')
    Path(output_path).write_text(json.dumps(results,indent=2)+'\n')
    return 0 if all(r['killed'] for r in results) else 1


if __name__=='__main__':
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else 'MUTATION_RESULTS.json'))
