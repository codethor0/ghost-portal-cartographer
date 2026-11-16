"""Adversarial synthetic tests for Ghost Portal Cartographer.

No third-party dependencies, network connections, real credentials, or live capture.
"""
from __future__ import annotations

import json
import random
import unittest
import hashlib
import hmac
import hashlib
import hmac
from dataclasses import asdict, replace
from pathlib import Path

from gpc import (Cartographer, Edge, Node, Query, from_json_dict,
                 DeclassificationClaim, AttestationTrust)
from independent_oracle import oracle_ordered, oracle_possible, oracle_reported
from independent_oracle_raw import raw_reachability


def n(name, domain='internal', surface='application', coverage='complete'):
    return Node(name, domain, surface, coverage)


def e(name, src, dst, mode='observed', flow='data', seq=1, evidence='synthetic:ref'):
    return Edge(name, src, dst, mode, flow, seq, evidence)


def analyze(nodes=None, edges=None, budget=10000, policy=None, category='SECRET', target='vendor'):
    return Cartographer(nodes or [n('s'), n('v', 'vendor')], edges or [], policy).analyze(
        Query('s', target, category), max_states=budget)


def fixture():
    return json.loads((Path(__file__).parent / 'synthetic_example.json').read_text())


def graph_document(nodes, edges):
    return {'nodes': [asdict(item) for item in nodes],
            'edges': [asdict(item) for item in edges]}


def witness_valid(model, result, relation, source='s', target='vendor'):
    path = result.path
    if path is None:
        return False
    vertex, last = source, -1
    for identifier in path:
        edge = model.edges[identifier]
        if edge.src != vertex:
            return False
        if relation == 'ordered' and (not edge.ordered_eligible or edge.sequence <= last):
            return False
        if relation == 'reported' and not edge.reported:
            return False
        if relation == 'possible' and not edge.possible:
            return False
        vertex = edge.dst
        if relation == 'ordered':
            last = edge.sequence
    return vertex != source and model.nodes[vertex].domain == target


class BasicPathTests(unittest.TestCase):
    def test_01_direct_ordered(self):
        self.assertEqual(analyze(edges=[e('x', 's', 'v')]).status, 'REPORTED_ORDERED_LINEAGE')

    def test_02_multi_hop_ordered(self):
        f = analyze([n('s'), n('a'), n('v', 'vendor')],
                    [e('a', 's', 'a', seq=1), e('b', 'a', 'v', seq=2)])
        self.assertEqual(f.path, ('a', 'b'))

    def test_03_direct_possible(self):
        self.assertEqual(analyze(edges=[e('x','s','v', mode='inferred')]).status, 'POSSIBLE_ROUTE')

    def test_04_unknown_content_possible(self):
        self.assertEqual(analyze(edges=[e('x','s','v', flow='unknown')]).status, 'POSSIBLE_ROUTE')

    def test_05_control_not_data(self):
        self.assertEqual(analyze(edges=[e('x','s','v', flow='control')]).status, 'NO_ROUTE_IN_DECLARED_GRAPH')

    def test_06_missing_evidence_only_possible(self):
        self.assertEqual(analyze(edges=[e('x','s','v', evidence=None)]).status, 'POSSIBLE_ROUTE')

    def test_07_blank_evidence_only_possible(self):
        self.assertEqual(analyze(edges=[e('x','s','v', evidence=' \n ')]).status, 'POSSIBLE_ROUTE')

    def test_08_missing_sequence_reported(self):
        f = analyze(edges=[e('x', 's', 'v', seq=None)])
        self.assertEqual(f.status, 'REPORTED_ORDER_UNRESOLVED')
        self.assertEqual(f.reported_path_order_issues[0].reason, 'MISSING_SEQUENCE')

    def test_09_sequence_inversion_reported(self):
        f = analyze([n('s'),n('a'),n('v','vendor')],
                    [e('a','s','a',seq=5),e('b','a','v',seq=4)])
        self.assertEqual(f.status, 'REPORTED_ORDER_UNRESOLVED')
        self.assertEqual(f.path, ('a','b'))
        self.assertEqual(f.reported_path_order_issues[0].reason, 'NON_INCREASING_SEQUENCE')

    def test_10_equal_sequence_reported(self):
        f = analyze([n('s'),n('a'),n('v','vendor')],
                    [e('a','s','a',seq=2),e('b','a','v',seq=2)])
        self.assertEqual(f.status, 'REPORTED_ORDER_UNRESOLVED')

    def test_11_zero_sequence_is_valid(self):
        self.assertEqual(analyze(edges=[e('x','s','v',seq=0)]).status, 'REPORTED_ORDERED_LINEAGE')

    def test_12_reported_path_over_possible(self):
        f = analyze(edges=[e('a','s','v',mode='inferred'),e('z','s','v',seq=None)])
        self.assertEqual((f.status,f.path), ('REPORTED_ORDER_UNRESOLVED',('z',)))

    def test_13_ordered_path_over_reported(self):
        f = analyze(edges=[e('a','s','v',seq=None), e('z','s','v',seq=1)])
        self.assertEqual((f.status,f.path), ('REPORTED_ORDERED_LINEAGE',('z',)))

    def test_14_distinct_artifact_identity_required(self):
        f = analyze([n('s'),n('m1'),n('m2'),n('v','vendor')],
                    [e('a','s','m1'),e('b','m2','v',seq=2)])
        self.assertEqual(f.status,'NO_ROUTE_IN_DECLARED_GRAPH')

    def test_15_multiple_same_domain_sinks(self):
        f = analyze([n('s'),n('v','vendor'),n('w','vendor')],
                    [e('b','s','w'),e('a','s','v')])
        self.assertEqual(f.path, ('a',))

    def test_16_cycle_terminates(self):
        f = analyze([n('s'),n('x'),n('v','vendor')],
                    [e('a','s','x',seq=1),e('b','x','s',seq=2),e('c','x','v',seq=3)])
        self.assertEqual(f.status,'REPORTED_ORDERED_LINEAGE')

    def test_17_unreachable_cycle_terminates(self):
        f = analyze([n('s'),n('x'),n('v','vendor')],
                    [e('a','s','x',seq=1),e('b','x','s',seq=2)])
        self.assertEqual(f.status,'NO_ROUTE_IN_DECLARED_GRAPH')

    def test_18_self_loop_only_not_target(self):
        self.assertEqual(analyze(edges=[e('a','s','s')]).status,'NO_ROUTE_IN_DECLARED_GRAPH')

    def test_19_target_domain_only(self):
        f = analyze([n('s'), n('x','other'), n('v','vendor')],[e('a','s','x')])
        self.assertEqual(f.status,'NO_ROUTE_IN_DECLARED_GRAPH')

    def test_20_log_telemetry_memory_cache_integrations(self):
        ids=['s','l','t','m','c','i','v']
        surfaces=['application','log','telemetry','memory','cache','integration','external']
        ns=[n(k,'vendor' if k=='v' else 'internal',surface) for k,surface in zip(ids,surfaces)]
        es=[e(str(j),ids[j],ids[j+1],seq=j+1) for j in range(len(ids)-1)]
        self.assertEqual(analyze(ns,es).status,'REPORTED_ORDERED_LINEAGE')

    def test_21_backup_and_trace_supported(self):
        ns=[n('s'),n('a',surface='backup'),n('b',surface='trace'),n('v','vendor')]
        es=[e('a','s','a',seq=1),e('b','a','b',seq=2),e('c','b','v',seq=3)]
        self.assertEqual(analyze(ns,es).path,('a','b','c'))

    def test_22_policy_does_not_change_search(self):
        nodes=[n('s'),n('v','vendor')]; edges=[e('a','s','v')]
        self.assertEqual(analyze(nodes,edges,policy={('SECRET','vendor'):'DENIED'}).status,
                         analyze(nodes,edges,policy={('SECRET','vendor'):'PERMITTED'}).status)

    def test_23_category_affects_policy_not_path(self):
        nodes=[n('s'),n('v','vendor')]; edges=[e('a','s','v')]
        a=analyze(nodes,edges,category='A',policy={('A','vendor'):'DENIED'})
        b=analyze(nodes,edges,category='B',policy={('A','vendor'):'DENIED'})
        self.assertEqual(a.path,b.path)
        self.assertEqual((a.policy,b.policy),('DENIED','UNSPECIFIED'))

    def test_24_no_route_not_proof_safe(self):
        self.assertIn('not safety',analyze().caveat)

    def test_25_input_provenance_not_authenticated(self):
        self.assertEqual(analyze(edges=[e('a','s','v')]).provenance_trust,'unauthenticated')

    def test_26_synthetic_fixture_exact_path(self):
        raw=fixture()
        f=from_json_dict(raw).analyze(Query(**raw['query']))
        self.assertEqual((f.status, f.policy, f.path),
                         ('REPORTED_ORDERED_LINEAGE','DENIED',('e1','e2','e3')))

    def test_27_fixture_without_observed_vendor(self):
        raw=fixture(); raw['edges']=[e for e in raw['edges'] if e['id']!='e3']
        f=from_json_dict(raw).analyze(Query(**raw['query']))
        self.assertEqual(f.status,'POSSIBLE_ROUTE')

    def test_28_fixture_without_both_vendor(self):
        raw=fixture(); raw['edges']=[e for e in raw['edges'] if e['id'] not in ('e3','e6')]
        f=from_json_dict(raw).analyze(Query(**raw['query']))
        self.assertEqual(f.status,'NO_ROUTE_IN_DECLARED_GRAPH')

    def test_29_fixture_inverted_vendor_order(self):
        raw=fixture()
        for edge in raw['edges']:
            if edge['id']=='e3': edge['sequence']=1
        f=from_json_dict(raw).analyze(Query(**raw['query']))
        self.assertEqual(f.status,'REPORTED_ORDER_UNRESOLVED')

    def test_30_two_paths_choose_shortest_hops(self):
        ns=[n('s'),n('a'),n('b'),n('v','vendor')]
        es=[e('a','s','a',seq=1),e('b','a','b',seq=2),e('c','b','v',seq=3),e('z','s','v',seq=10)]
        self.assertEqual(analyze(ns,es).path,('z',))


class BudgetTests(unittest.TestCase):
    def test_31_original_suppression_regression(self):
        ns=[n('s'),n('a'),n('b'),n('v','vendor')]
        es=[e('a','s','b',mode='inferred'), e('z1','s','a',seq=1), e('z2','a','v',seq=2)]
        f=analyze(ns,es,budget=3)
        self.assertEqual(f.status,'REPORTED_ORDERED_LINEAGE')
        self.assertEqual(f.path,('z1','z2'))
        self.assertTrue(f.possible.limit_reached)
        self.assertFalse(f.ordered.limit_reached)
        self.assertEqual(f.possible.examined_states,3)

    def test_32_hundred_thousand_noise_nodes(self):
        # A large DISCONNECTED component is irrelevant to reachable-state BFS.
        # Include reachable noise to meaningfully stress the budget.
        ns=[n('s'),n('a'),n('v','vendor')]+[n(f'x{i}') for i in range(100000)]
        es=[e('z1','s','a',seq=1),e('z2','a','v',seq=2)]
        es.extend(e(f'a{i:06d}','s',f'x{i}',mode='inferred') for i in range(100000))
        f=analyze(ns,es,budget=3)
        self.assertEqual((f.status,f.path),('REPORTED_ORDERED_LINEAGE',('z1','z2')))
        self.assertTrue(f.possible.limit_reached)

    def test_33_unordered_survives_ordered_budget(self):
        ns=[n('s'),n('a'),n('v','vendor')]
        # Parallel sequence-distinct edges increase ORDERED state count;
        # REPORTED de-duplicates by vertex and still reaches destination.
        es=[e(f'a{i:02d}','s','a',seq=i+1) for i in range(12)]
        es.append(e('z','a','v',seq=0))
        f=analyze(ns,es,budget=3)
        self.assertEqual(f.status,'REPORTED_ORDER_UNRESOLVED')
        self.assertTrue(f.ordered.limit_reached)
        self.assertTrue(f.reported.found)
        self.assertEqual(f.path,('a00','z'))

    def test_34_possible_survives_reported_limit(self):
        ns=[n('s'),n('v','vendor')]+[n(f'x{i}') for i in range(12)]
        es=[e('a00','s','v',mode='inferred')]
        es.extend(e(f'z{i:02d}','s',f'x{i}',seq=i+1) for i in range(12))
        f=analyze(ns,es,budget=2)
        self.assertEqual(f.status,'POSSIBLE_ROUTE')
        self.assertTrue(f.reported.limit_reached)
        self.assertEqual(f.possible.path,('a00',))

    def test_35_none_found_budget_unknown(self):
        ns=[n('s'),n('a'),n('v','vendor')]; es=[e('a','s','a',seq=1),e('b','a','v',seq=2)]
        self.assertEqual(analyze(ns,es,budget=1).status,'UNKNOWN_LIMIT')

    def test_36_empty_graph_budget_one_decisive(self):
        f=analyze(budget=1)
        self.assertEqual(f.status,'NO_ROUTE_IN_DECLARED_GRAPH')
        self.assertTrue(f.possible.exhaustive)

    def test_37_budget_equals_required_pops(self):
        f=analyze(edges=[e('x','s','v')],budget=2)
        self.assertTrue(f.ordered.found)
        self.assertFalse(f.ordered.limit_reached)

    def test_38_budget_one_no_premature_witness(self):
        f=analyze(edges=[e('x','s','v')],budget=1)
        self.assertEqual(f.status,'UNKNOWN_LIMIT')

    def test_39_positive_result_counts_exact(self):
        f=analyze(edges=[e('x','s','v')],budget=2)
        self.assertEqual((f.ordered.examined_states,f.reported.examined_states,f.possible.examined_states),(2,2,2))
        self.assertEqual(f.examined_states,6)

    def test_40_limit_counts_exact_not_claimed_max(self):
        f=analyze([n('s'),n('a'),n('v','vendor')], [e('a','s','a')],budget=1)
        self.assertEqual(f.ordered.examined_states,1)
        self.assertEqual(f.ordered.discovered_states,2)
        self.assertTrue(f.ordered.limit_reached)

    def test_41_limits_independent(self):
        ns=[n('s'),n('a'),n('b'),n('v','vendor')]
        es=[e('a','s','b',mode='inferred'),e('z','s','a'),e('zz','a','v',seq=2)]
        f=analyze(ns,es,budget=3)
        self.assertEqual(f.ordered.examined_states,3)
        self.assertEqual(f.possible.examined_states,3)

    def test_42_control_only_no_budget_noise(self):
        ns=[n('s'),n('v','vendor')]+[n(f'x{i}') for i in range(20)]
        es=[e(f'c{i}','s',f'x{i}',flow='control') for i in range(20)]
        f=analyze(ns,es,budget=1)
        self.assertEqual(f.status,'NO_ROUTE_IN_DECLARED_GRAPH')

    def test_43_exhaustion_not_same_as_coverage_complete(self):
        f=analyze([n('s',coverage='unknown'),n('v','vendor',coverage='partial')], [],budget=1)
        self.assertTrue(f.possible.exhaustive)
        self.assertEqual(f.declared_coverage_gap_nodes,('s',))

    def test_44_budget_zero_rejected(self):
        with self.assertRaises(ValueError): analyze(budget=0)

    def test_45_boolean_budget_rejected(self):
        with self.assertRaises(ValueError): analyze(budget=True)

    def test_46_fractional_budget_rejected(self):
        with self.assertRaises(ValueError): analyze(budget=1.5)


class PolicyAndCoverageTests(unittest.TestCase):
    def test_47_destination_denied_separate(self):
        f=analyze(edges=[e('x','s','v')],policy={('SECRET','vendor'):'DENIED'})
        self.assertEqual((f.policy,f.status),('DENIED','REPORTED_ORDERED_LINEAGE'))

    def test_48_destination_permitted_separate(self):
        f=analyze(edges=[e('x','s','v')],policy={('SECRET','vendor'):'PERMITTED'})
        self.assertEqual(f.policy_path_status,'ALL_PERMITTED')

    def test_49_destination_unspecified(self):
        self.assertEqual(analyze(edges=[e('x','s','v')]).policy,'UNSPECIFIED')

    def test_50_intermediate_denied_detected(self):
        ns=[n('s'),n('x','vendor_a'),n('v','vendor')]
        es=[e('a','s','x',seq=1),e('b','x','v',seq=2)]
        f=analyze(ns,es,policy={('SECRET','vendor_a'):'DENIED',('SECRET','vendor'):'PERMITTED'})
        self.assertEqual(f.policy_path_status,'CONTAINS_DENIED')
        self.assertEqual([x.decision for x in f.policy_hops], ['DENIED','PERMITTED'])

    def test_51_unspecified_intermediate_not_permitted(self):
        ns=[n('s'),n('x','processor'),n('v','vendor')]
        es=[e('a','s','x',seq=1),e('b','x','v',seq=2)]
        f=analyze(ns,es,policy={('SECRET','vendor'):'PERMITTED'})
        self.assertEqual(f.policy_path_status,'UNSPECIFIED')

    def test_52_destination_denied_path(self):
        f=analyze(edges=[e('a','s','v')],policy={('SECRET','vendor'):'DENIED'})
        self.assertEqual(f.policy_path_status,'CONTAINS_DENIED')

    def test_53_no_path_policy_not_evaluated(self):
        f=analyze(policy={('SECRET','vendor'):'DENIED'})
        self.assertEqual(f.policy_path_status,'NO_PATH')

    def test_54_path_hop_record_order(self):
        ns=[n('s'),n('x','layer'),n('v','vendor')]
        f=analyze(ns,[e('a','s','x',seq=1),e('b','x','v',seq=2)])
        self.assertEqual([h.node_id for h in f.policy_hops],['x','v'])

    def test_55_declared_coverage_gaps_observed(self):
        ns=[n('s',coverage='partial'),n('v','vendor',coverage='unknown')]
        f=analyze(ns,[e('a','s','v')])
        self.assertEqual(f.ordered.declared_coverage_gaps,('s','v'))

    def test_56_declared_coverage_gaps_possible_only(self):
        ns=[n('s'),n('x',coverage='partial'),n('v','vendor')]
        f=analyze(ns,[e('a','s','x',mode='inferred')])
        self.assertEqual(f.declared_coverage_gap_nodes,('x',))

    def test_57_unpopped_coverage_not_claimed(self):
        ns=[n('s'),n('v','vendor',coverage='unknown')]
        f=analyze(ns,[e('a','s','v')],budget=1)
        self.assertEqual(f.declared_coverage_gap_nodes,())

    def test_58_no_external_visibility_percentage(self):
        self.assertNotIn('visibility_percentage',analyze().to_dict())

    def test_59_frozen_result(self):
        f=analyze()
        with self.assertRaises(Exception): f.provenance_trust='authenticated'

    def test_60_serialized_result_contains_all_three(self):
        doc=analyze(edges=[e('a','s','v')]).to_dict()
        self.assertEqual(set(('ordered','reported','possible')) - doc.keys(),set())
        self.assertEqual(doc['provenance_trust'],'unauthenticated')


class SchemaTests(unittest.TestCase):
    def test_61_duplicate_node_rejected(self):
        with self.assertRaises(ValueError): Cartographer([n('s'),n('s')],[])

    def test_62_duplicate_edge_rejected(self):
        with self.assertRaises(ValueError): Cartographer([n('s'),n('v','vendor')],[e('a','s','v'),e('a','s','v')])

    def test_63_dangling_edge_rejected(self):
        with self.assertRaises(ValueError): Cartographer([n('s')],[e('a','s','missing')])

    def test_64_invalid_surface_rejected(self):
        with self.assertRaises(ValueError): Cartographer([n('s',surface='remote_shell')],[])

    def test_65_invalid_coverage_rejected(self):
        with self.assertRaises(ValueError): Cartographer([n('s',coverage='verified')],[])

    def test_66_empty_node_id_rejected(self):
        with self.assertRaises(ValueError): Cartographer([n(' ')],[])

    def test_67_unhashable_node_id_rejected_cleanly(self):
        with self.assertRaises(ValueError): Cartographer([n([])],[])

    def test_68_unhashable_edge_id_rejected_cleanly(self):
        with self.assertRaises(ValueError): Cartographer([n('s')],[e([], 's','s')])

    def test_69_boolean_sequence_rejected(self):
        with self.assertRaises(ValueError): Cartographer([n('s'),n('v','vendor')],[e('a','s','v',seq=True)])

    def test_70_negative_sequence_rejected(self):
        with self.assertRaises(ValueError): Cartographer([n('s'),n('v','vendor')],[e('a','s','v',seq=-1)])

    def test_71_fractional_sequence_rejected(self):
        with self.assertRaises(ValueError): Cartographer([n('s'),n('v','vendor')],[e('a','s','v',seq=1.2)])

    def test_72_evidence_object_rejected(self):
        with self.assertRaises(ValueError): Cartographer([n('s'),n('v','vendor')],[e('a','s','v',evidence={})])

    def test_73_bad_mode_rejected(self):
        with self.assertRaises(ValueError): Cartographer([n('s'),n('v','vendor')],[e('a','s','v',mode='verified')])

    def test_74_bad_flow_rejected(self):
        with self.assertRaises(ValueError): Cartographer([n('s'),n('v','vendor')],[e('a','s','v',flow='payload')])

    def test_75_policy_invalid_value(self):
        with self.assertRaises(ValueError): Cartographer([n('s')],[],{('SECRET','vendor'):'ALLOW'})

    def test_76_policy_bad_key(self):
        with self.assertRaises(ValueError): Cartographer([n('s')],[],{'bad':'DENIED'})

    def test_77_missing_json_nodes(self):
        with self.assertRaises(ValueError): from_json_dict({'edges':[]})

    def test_78_missing_json_policy_decision(self):
        raw=fixture(); raw['policy']=[{'category':'SECRET','domain':'vendor'}]
        with self.assertRaises(ValueError): from_json_dict(raw)

    def test_79_missing_json_edge_id(self):
        raw=fixture(); raw['edges'][0].pop('id')
        with self.assertRaises(ValueError): from_json_dict(raw)

    def test_80_unrecognized_json_field(self):
        raw=fixture(); raw['edges'][0]['payload']='secret'
        with self.assertRaises(ValueError): from_json_dict(raw)

    def test_81_conflicting_policy_entries(self):
        raw=fixture(); raw['policy'].append({'category':'CREDENTIAL','domain':'external_vendor','decision':'PERMITTED'})
        with self.assertRaises(ValueError): from_json_dict(raw)

    def test_82_duplicate_same_policy_entries(self):
        raw=fixture(); raw['policy'].append(dict(raw['policy'][0]))
        with self.assertRaises(ValueError): from_json_dict(raw)

    def test_83_malformed_top_level(self):
        with self.assertRaises(ValueError): from_json_dict([])

    def test_84_malformed_node_list(self):
        with self.assertRaises(ValueError): from_json_dict({'nodes':{},'edges':[]})

    def test_85_same_domain_query_rejected(self):
        with self.assertRaises(ValueError): analyze(target='internal')

    def test_86_missing_source_query_rejected(self):
        with self.assertRaises(ValueError): Cartographer([n('s')],[]).analyze(Query('missing','vendor','SECRET'))

    def test_87_non_string_category_rejected(self):
        with self.assertRaises(ValueError): analyze(category=None)

    def test_88_whitespace_destination_rejected(self):
        with self.assertRaises(ValueError): analyze(target='  ')

    def test_89_empty_policy_domain_rejected(self):
        with self.assertRaises(ValueError): Cartographer([n('s')],[],{('SECRET',' '):'DENIED'})

    def test_90_input_is_metadata_only(self):
        raw=fixture(); self.assertTrue(all('payload' not in edge for edge in raw['edges']))


class OracleTests(unittest.TestCase):
    def random_graph(self, rng):
        count=rng.randint(2,7)
        nodes=[n('s' if j == 0 else f'n{j}', 'vendor' if j == count-1 else 'internal',
                 coverage=rng.choice(['complete','partial','unknown'])) for j in range(count)]
        labels=[node.id for node in nodes]
        edges=[]
        for j in range(rng.randint(0,17)):
            edges.append(e(f'e{j:02d}',rng.choice(labels),rng.choice(labels),
                           rng.choice(('observed','inferred')),
                           rng.choice(('data','unknown','control')),
                           rng.choice((None,0,1,2,3,4,5,6)),
                           rng.choice((None,'', 'ref'))))
        return nodes,edges

    def test_91_independent_dfs_oracle_1200_random_graphs(self):
        rng=random.Random(202611151)
        for index in range(1200):
            nodes,edges=self.random_graph(rng)
            model=Cartographer(nodes,edges)
            f=model.analyze(Query('s','vendor','SECRET'),max_states=10000)
            expected=(oracle_ordered(nodes,edges,'s','vendor'),
                      oracle_reported(nodes,edges,'s','vendor'),
                      oracle_possible(nodes,edges,'s','vendor'))
            self.assertEqual(tuple(x.found for x in (f.ordered,f.reported,f.possible)),expected,index)
            self.assertTrue(all(x.resolved for x in (f.ordered,f.reported,f.possible)))
            for relation,result in zip(('ordered','reported','possible'),(f.ordered,f.reported,f.possible)):
                if result.found:
                    self.assertTrue(witness_valid(model,result,relation), (index,relation))

    def test_92_independent_raw_oracle_1200_random_graphs(self):
        rng=random.Random(202611152)
        for index in range(1200):
            nodes,edges=self.random_graph(rng)
            model=Cartographer(nodes,edges)
            f=model.analyze(Query('s','vendor','SECRET'),max_states=10000)
            raw=raw_reachability(graph_document(nodes,edges),'s','vendor')
            self.assertEqual({key:getattr(f,key).found for key in ('ordered','reported','possible')},raw,index)

    def test_93_exhaustive_three_vertex_possible_graphs(self):
        nodes=[n('s'),n('a'),n('v','vendor')]
        pairs=[(a,b) for a in ('s','a','v') for b in ('s','a','v')]
        for mask in range(1 << len(pairs)):
            edges=[e(str(i),a,b,mode='inferred') for i,(a,b) in enumerate(pairs) if mask & (1<<i)]
            f=analyze(nodes,edges)
            expected=oracle_possible(nodes,edges,'s','vendor')
            self.assertEqual(f.possible.found,expected,mask)
            self.assertEqual(f.reported.found,False)

    def test_94_exhaustive_three_vertex_observation_mappings(self):
        nodes=[n('s'),n('a'),n('v','vendor')]
        pairs=[('s','a'),('a','v'),('s','v'),('a','s')]
        for packed in range(5 ** len(pairs)):
            t=packed; edges=[]
            for i,(a,b) in enumerate(pairs):
                case=t%5; t//=5
                if case:
                    edges.append(e(str(i),a,b,seq=[None,0,1,2,3][case]))
            f=analyze(nodes,edges)
            expected=oracle_ordered(nodes,edges,'s','vendor')
            self.assertEqual(f.ordered.found,expected,packed)

    def test_95_possible_edge_monotonicity_500_cases(self):
        rng=random.Random(3141592)
        ns=[n('s'),n('a'),n('b'),n('v','vendor')]
        names=[x.id for x in ns]
        for j in range(500):
            edges=[e(f'e{i}',rng.choice(names),rng.choice(names),mode='inferred') for i in range(6)]
            before=analyze(ns,edges).possible.found
            after=analyze(ns,edges+[e('extra',rng.choice(names),rng.choice(names),mode='inferred')]).possible.found
            self.assertFalse(before and not after,j)

    def test_96_reported_edge_monotonicity_250_cases(self):
        rng=random.Random(3141593)
        ns=[n('s'),n('a'),n('v','vendor')]; names=[x.id for x in ns]
        for j in range(250):
            edges=[e(f'e{i}',rng.choice(names),rng.choice(names),seq=None) for i in range(6)]
            before=analyze(ns,edges).reported.found
            after=analyze(ns,edges+[e('extra',rng.choice(names),rng.choice(names),seq=None)]).reported.found
            self.assertFalse(before and not after,j)

    def test_97_ordered_edge_monotonicity_250_cases(self):
        rng=random.Random(3141594)
        ns=[n('s'),n('a'),n('v','vendor')]; names=[x.id for x in ns]
        for j in range(250):
            edges=[e(f'e{i}',rng.choice(names),rng.choice(names),seq=rng.randint(0,6)) for i in range(6)]
            before=analyze(ns,edges).ordered.found
            after=analyze(ns,edges+[e('extra',rng.choice(names),rng.choice(names),seq=7)]).ordered.found
            self.assertFalse(before and not after,j)

    def test_98_ordered_implies_reported_implies_possible(self):
        rng=random.Random(100)
        for case in range(400):
            ns,es=self.random_graph(rng)
            f=analyze(ns,es)
            self.assertFalse(f.ordered.found and not f.reported.found,case)
            self.assertFalse(f.reported.found and not f.possible.found,case)

    def test_99_result_priority_random_budgets(self):
        rng=random.Random(101)
        for case in range(500):
            ns,es=self.random_graph(rng)
            budget=rng.randint(1,4)
            model=Cartographer(ns,es)
            f=model.analyze(Query('s','vendor','SECRET'),max_states=budget)
            # Witness-first, then re-verification of the returned witness, then
            # containment for an exhaustive negative possible search.
            returned=f.ordered.path or f.reported.path or f.possible.path
            if f.ordered.found:
                self.assertEqual(f.status,'REPORTED_ORDERED_LINEAGE',case)
            elif returned is not None:
                if witness_valid(model,f,'ordered',target='vendor'):
                    expected='REPORTED_ORDERED_LINEAGE'
                elif witness_valid(model,f,'reported',target='vendor'):
                    expected='REPORTED_ORDER_UNRESOLVED'
                else:
                    expected='POSSIBLE_ROUTE'
                self.assertEqual(f.status,expected,case)
                self.assertEqual(f.path,returned,case)
            elif f.possible.exhaustive:
                self.assertEqual(f.status,'NO_ROUTE_IN_DECLARED_GRAPH',case)
            else:
                self.assertTrue(any(r.limit_reached for r in (f.ordered,f.reported,f.possible)),case)
                self.assertEqual(f.status,'UNKNOWN_LIMIT',case)

    def test_100_reordering_input_deterministic(self):
        ns=[n('s'),n('a'),n('b'),n('v','vendor')]
        es=[e('z','s','a',seq=1),e('c','s','b',seq=1),
            e('e','a','v',seq=2),e('d','b','v',seq=2)]
        original=analyze(ns,es).path
        self.assertEqual(original,analyze(list(reversed(ns)),list(reversed(es))).path)

    def test_101_all_statuses_have_no_authentication_claim(self):
        samples=[analyze(),analyze(edges=[e('a','s','v',mode='inferred')]),
                 analyze(edges=[e('a','s','v',seq=None)]),
                 analyze(edges=[e('a','s','v',seq=1)]),
                 analyze(edges=[e('a','s','v')],budget=1)]
        self.assertTrue(all(x.provenance_trust=='unauthenticated' for x in samples))




# Extension tests deliberately keep graph reachability separate from an
# authenticated (but not semantically validated) transformation claim.
class DistributedContextTests(unittest.TestCase):
    def test_102_causal_parent_match_does_not_upgrade_sequence(self):
        nodes=[n('s'),n('a'),n('v','vendor')]
        edges=[e('first','s','a',seq=5),replace(e('second','a','v',seq=4),
                                               causal_parent_id='first')]
        result=analyze(nodes,edges)
        self.assertEqual(result.status,'REPORTED_ORDER_UNRESOLVED')
        self.assertEqual(result.causal_annotations[1].claim,'MATCHED_UNAUTHENTICATED_PARENT')

    def test_103_false_parent_does_not_upgrade(self):
        nodes=[n('s'),n('a'),n('v','vendor')]
        edges=[e('first','s','a',seq=5),replace(e('second','a','v',seq=4),
                                               causal_parent_id='forged')]
        result=analyze(nodes,edges)
        self.assertEqual(result.status,'REPORTED_ORDER_UNRESOLVED')
        self.assertEqual(result.causal_annotations[1].claim,'CONFLICTING_PARENT')

    def test_104_matching_trace_parent_is_only_reported(self):
        ns=[n('s'),n('a'),n('v','vendor')]
        a=replace(e('one','s','a',seq=5),trace_id='a'*32,span_id='1'*16)
        b=replace(e('two','a','v',seq=4),trace_id='a'*32,span_id='2'*16,
                  parent_span_id='1'*16)
        result=analyze(ns,[a,b])
        self.assertEqual(result.status,'REPORTED_ORDER_UNRESOLVED')
        self.assertEqual(result.causal_annotations[1].claim,'TRACE_PARENT_MATCH')

    def test_105_trace_scope_mismatch_detected(self):
        ns=[n('s'),n('a'),n('v','vendor')]
        a=replace(e('one','s','a',seq=5),trace_id='a'*32,span_id='1'*16)
        b=replace(e('two','a','v',seq=4),trace_id='b'*32,span_id='2'*16,
                  parent_span_id='1'*16)
        result=analyze(ns,[a,b])
        self.assertEqual(result.causal_annotations[1].claim,'TRACE_PARENT_MISMATCH')

    def test_106_trace_parent_without_previous_span(self):
        ns=[n('s'),n('a'),n('v','vendor')]
        a=e('one','s','a',seq=5)
        b=replace(e('two','a','v',seq=4),trace_id='a'*32,span_id='2'*16,
                  parent_span_id='1'*16)
        self.assertEqual(analyze(ns,[a,b]).causal_annotations[1].claim,'UNSCOPED_TRACE')

    def test_107_invalid_trace_id_rejected(self):
        with self.assertRaises(ValueError):
            Cartographer([n('s'),n('v','vendor')],[replace(e('one','s','v'),trace_id='bad')])

    def test_108_invalid_span_rejected(self):
        with self.assertRaises(ValueError):
            Cartographer([n('s'),n('v','vendor')],[replace(e('one','s','v'),span_id='zzzz')])

    def test_109_orphan_parent_span_rejected(self):
        with self.assertRaises(ValueError):
            Cartographer([n('s'),n('v','vendor')],
                         [replace(e('one','s','v'),parent_span_id='2'*16)])

    def test_110_invalid_claimed_parent_rejected(self):
        with self.assertRaises(ValueError):
            Cartographer([n('s'),n('v','vendor')],
                         [replace(e('one','s','v'),causal_parent_id='  ')])

    def test_111_parentage_never_authenticates_provenance(self):
        result=analyze([n('s'),n('a'),n('v','vendor')],
                       [e('one','s','a',seq=5),replace(e('two','a','v',seq=4),causal_parent_id='one')])
        self.assertEqual(result.provenance_trust,'unauthenticated')
        self.assertTrue(all(a.provenance_trust=='unauthenticated' for a in result.causal_annotations))

    def test_112_missing_sequence_parentage_preserves_reported(self):
        result=analyze([n('s'),n('a'),n('v','vendor')],
                       [e('one','s','a',seq=None),replace(e('two','a','v',seq=None),causal_parent_id='one')])
        self.assertEqual(result.status,'REPORTED_ORDER_UNRESOLVED')

    def test_113_trace_metadata_alone_not_edge(self):
        result=analyze([n('s'),n('v','vendor')],[])
        self.assertEqual(result.status,'NO_ROUTE_IN_DECLARED_GRAPH')


class DeclassificationTests(unittest.TestCase):
    KEY=b'synthetic-test-key-material-only-32!'
    SRC='a'*64
    OUT='b'*64

    def configuration(self):
        ns=[Node('s','internal','application','complete',self.SRC),
            Node('v','vendor','external','complete',self.OUT)]
        trust=AttestationTrust('demo','policy-1',self.KEY,('SECRET',),('mask',))
        return ns,{'demo':trust}

    def claim(self, bind=('s','v','internal','vendor'), **updates):
        values=dict(attester_id='demo',category='SECRET',policy_id='policy-1',
                    transform='mask',source_digest=self.SRC,output_digest=self.OUT,
                    nonce='fixture-1',issued_at=10,expires_at=20,mac_hex='0'*64)
        values.update(updates)
        temporary=DeclassificationClaim(**values)
        payload=asdict(temporary); payload.pop('mac_hex')
        # Independent re-statement of the edge binding (source/output artifacts and domains).
        payload.update(bound_source=bind[0],bound_output=bind[1],
                       bound_source_domain=bind[2],bound_output_domain=bind[3])
        canonical=b'GPC-DECLASSIFICATION-HMAC-DEMO\x00'+json.dumps(
            payload,sort_keys=True,separators=(',', ':'),ensure_ascii=True).encode('utf-8')
        values['mac_hex']=hmac.new(self.KEY,canonical,hashlib.sha256).hexdigest()
        return DeclassificationClaim(**values)

    def check(self,claim=None,category='SECRET',trust=True,epoch=15,edges=None,model_nodes=None):
        nodes,rules=self.configuration()
        node_list=model_nodes if model_nodes is not None else nodes
        graph_edges=edges if edges is not None else [replace(e('d','s','v',flow='declassified'),declassification=claim)]
        model=Cartographer(node_list,graph_edges,attestation_trust=rules if trust else {},
                           verification_epoch=epoch)
        return model.analyze(Query('s','vendor',category))

    def test_114_unsigned_declassification_still_possible(self):
        result=self.check()
        self.assertEqual(result.status,'REPORTED_ORDERED_LINEAGE')
        self.assertEqual(result.declassification_assessments[0].reason,'MISSING_CLAIM')

    def test_115_good_mac_authenticates_metadata_but_does_not_suppress(self):
        result=self.check(self.claim())
        self.assertEqual(result.status,'REPORTED_ORDERED_LINEAGE')
        self.assertEqual(result.path,('d',))
        check=result.declassification_assessments[0]
        self.assertEqual(check.status,'AUTHENTICATED_METADATA_CLAIM')
        self.assertFalse(check.edge_suppressed)

    def test_116_tampered_mac_does_not_authenticate(self):
        result=self.check(replace(self.claim(),mac_hex='0'*64))
        self.assertEqual(result.declassification_assessments[0].reason,'MAC_MISMATCH')
        self.assertEqual(result.path,('d',))

    def test_117_wrong_policy(self):
        result=self.check(self.claim(policy_id='other'))
        self.assertEqual(result.declassification_assessments[0].reason,'POLICY_MISMATCH')

    def test_118_wrong_category(self):
        result=self.check(self.claim(category='OTHER'))
        self.assertEqual(result.declassification_assessments[0].reason,'CATEGORY_MISMATCH')

    def test_119_wrong_transform(self):
        result=self.check(self.claim(transform='decrypt'))
        self.assertEqual(result.declassification_assessments[0].reason,'POLICY_MISMATCH')

    def test_120_wrong_digest_on_node(self):
        ns,_=self.configuration()
        ns=[replace(ns[0],sha256_digest='e'*64),ns[1]]
        result=self.check(self.claim(),model_nodes=ns)
        self.assertEqual(result.declassification_assessments[0].reason,'ARTIFACT_DIGEST_MISMATCH')

    def test_121_expired_claim(self):
        result=self.check(self.claim(),epoch=21)
        self.assertEqual(result.declassification_assessments[0].reason,'OUTSIDE_VALIDITY_WINDOW')

    def test_122_missing_verification_epoch(self):
        result=self.check(self.claim(),epoch=None)
        self.assertEqual(result.declassification_assessments[0].reason,'NO_VERIFICATION_TIME')

    def test_123_untrusted_signer(self):
        result=self.check(self.claim(),trust=False)
        self.assertEqual(result.declassification_assessments[0].reason,'UNTRUSTED_ATTESTER')

    def test_124_duplicate_nonce(self):
        claim=self.claim()
        edges=[replace(e('a','s','v',flow='declassified'),declassification=claim),
               replace(e('b','s','v',flow='declassified'),declassification=claim)]
        result=self.check(claim,edges=edges)
        self.assertEqual([a.reason for a in result.declassification_assessments],
                         ['MAC_VERIFIED_METADATA_ONLY','DUPLICATE_NONCE_IN_GRAPH'])

    def test_125_different_category_never_suppressed(self):
        result=self.check(self.claim(),category='OTHER')
        self.assertEqual(result.status,'REPORTED_ORDERED_LINEAGE')
        self.assertEqual(result.declassification_assessments[0].reason,'CATEGORY_MISMATCH')

    def test_126_inferred_declassified_edge_still_possible(self):
        edges=[replace(e('d','s','v',flow='declassified',mode='inferred'),
                       declassification=self.claim())]
        result=self.check(self.claim(),edges=edges)
        self.assertEqual(result.status,'POSSIBLE_ROUTE')

    def test_127_json_claim_roundtrip(self):
        nodes,_=self.configuration()
        edge=replace(e('d','s','v',flow='declassified'),declassification=self.claim())
        parsed=from_json_dict(graph_document(nodes,[edge]))
        result=parsed.analyze(Query('s','vendor','SECRET'))
        self.assertEqual(result.declassification_assessments[0].reason,'UNTRUSTED_ATTESTER')

    def test_128_missing_claim_field_is_clean_value_error(self):
        nodes,_=self.configuration()
        raw=graph_document(nodes,[replace(e('d','s','v',flow='declassified'),
                                              declassification=self.claim())])
        raw['edges'][0]['declassification'].pop('nonce')
        with self.assertRaises(ValueError): from_json_dict(raw)

    def test_129_invalid_mac_type_is_clean_value_error(self):
        with self.assertRaises(ValueError):
            self.check(replace(self.claim(),mac_hex=['invalid']))

    def test_130_tampered_claim_does_not_authenticate(self):
        result=self.check(replace(self.claim(),transform='drop'))
        self.assertEqual(result.declassification_assessments[0].status,'UNVERIFIED_CLAIM')

    def test_131_valid_mac_does_not_erase_alternate_route(self):
        nodes,_=self.configuration()
        nodes.insert(1,n('a'))
        edges=[replace(e('a','s','v',flow='declassified'),declassification=self.claim()),
               e('b','s','a',mode='inferred'),e('c','a','v',mode='inferred')]
        result=self.check(self.claim(),edges=edges,model_nodes=nodes)
        self.assertTrue(result.possible.found)
        self.assertFalse(result.declassification_assessments[0].edge_suppressed)

    def test_132_false_digest_rejected_cleanly(self):
        ns,_=self.configuration()
        with self.assertRaises(ValueError):
            Cartographer([replace(ns[0],sha256_digest='bad'),ns[1]],[])

    def test_133_wrong_key_detected(self):
        nodes,_=self.configuration()
        bad=AttestationTrust('demo','policy-1',b'wrong-test-key-material-only-32!',('SECRET',),('mask',))
        edge=replace(e('d','s','v',flow='declassified'),declassification=self.claim())
        result=Cartographer(nodes,[edge],attestation_trust={'demo':bad},
                            verification_epoch=15).analyze(Query('s','vendor','SECRET'))
        self.assertEqual(result.declassification_assessments[0].reason,'MAC_MISMATCH')

    def test_134_boolean_verification_epoch_rejected(self):
        with self.assertRaises(ValueError):
            Cartographer([n('s')],[],verification_epoch=True)

    def test_135_result_has_zero_production_cryptographic_claims(self):
        result=self.check(self.claim())
        self.assertIn('not proof of semantic sanitization',result.caveat)
        self.assertEqual(result.provenance_trust,'unauthenticated')
        self.assertTrue(all(not a.edge_suppressed for a in result.declassification_assessments))

    def test_136_untrusted_key_is_not_in_serialized_output(self):
        result=self.check(self.claim())
        self.assertNotIn(self.KEY.hex(),json.dumps(result.to_dict()))

    def test_137_declared_node_digest_is_not_verified_from_bytes(self):
        result=self.check(self.claim())
        self.assertIn('METADATA',result.caveat)

    def test_138_duplicate_claim_same_nonce_order_deterministic(self):
        claim=self.claim()
        es=[replace(e('z','s','v',flow='declassified'),declassification=claim),
            replace(e('a','s','v',flow='declassified'),declassification=claim)]
        one=self.check(claim,edges=es)
        two=self.check(claim,edges=list(reversed(es)))
        self.assertEqual(one.declassification_assessments,two.declassification_assessments)


class ExtendedOracleTests(unittest.TestCase):
    def test_139_declassified_edges_remain_in_all_eligible_relations(self):
        rng=random.Random(5741)
        for case in range(400):
            ns=[n('s'),n('a'),n('b'),n('v','vendor')]
            es=[]
            for k in range(rng.randrange(1,9)):
                u=rng.choice(['s','a','b'])
                v=rng.choice(['s','a','b','v'])
                flow=rng.choice(['data','unknown','control','declassified'])
                mode=rng.choice(['observed','inferred'])
                seq=rng.choice([None,0,1,2,3,4])
                ref=rng.choice(['synthetic:ref',None,' '])
                es.append(e(f'edge{k}',u,v,mode,flow,seq,ref))
            model=Cartographer(ns,es)
            got=model.analyze(Query('s','vendor','SECRET'))
            self.assertEqual(got.possible.found,oracle_possible(ns,es,'s','vendor'),case)
            self.assertEqual(got.reported.found,oracle_reported(ns,es,'s','vendor'),case)
            self.assertEqual(got.ordered.found,oracle_ordered(ns,es,'s','vendor'),case)
            raw=raw_reachability(graph_document(ns,es),'s','vendor')
            self.assertEqual((got.possible.found,got.reported.found,got.ordered.found),
                             (raw['possible'],raw['reported'],raw['ordered']),case)

    def test_140_all_declassification_attestations_are_observational(self):
        nodes=[n('s'),n('v','vendor')]
        edge=e('x','s','v',flow='declassified',seq=1)
        model=Cartographer(nodes,[edge])
        self.assertTrue(model.analyze(Query('s','vendor','SECRET')).possible.found)
        self.assertEqual(model.analyze(Query('s','vendor','SECRET')).status,'REPORTED_ORDERED_LINEAGE')


class ExternalReviewPrecisionTests(unittest.TestCase):
    """Regressions mapping the paper's secondary diagnostics to the kernel."""

    def test_141_reproduced_parent_edge_never_upgrades_inverted_order(self):
        ns = [n('s'), n('a'), n('v', 'vendor')]
        first = e('first', 's', 'a', seq=5)
        second = replace(e('second', 'a', 'v', seq=4), causal_parent_id='first')
        result = analyze(ns, [first, second])
        self.assertEqual(result.status, 'REPORTED_ORDER_UNRESOLVED')
        self.assertFalse(result.ordered.found)
        self.assertTrue(result.reported.found)
        self.assertEqual(result.reported_path_order_issues[0].reason, 'NON_INCREASING_SEQUENCE')
        self.assertEqual(result.causal_annotations[1].claim, 'MATCHED_UNAUTHENTICATED_PARENT')

    def test_142_reported_span_parent_never_upgrades_inverted_order(self):
        ns = [n('s'), n('a'), n('v', 'vendor')]
        first = replace(e('first', 's', 'a', seq=5), trace_id='a'*32, span_id='1'*16)
        second = replace(e('second', 'a', 'v', seq=4), trace_id='a'*32,
                         span_id='2'*16, parent_span_id='1'*16)
        result = analyze(ns, [first, second])
        self.assertFalse(result.ordered.found)
        self.assertTrue(result.reported.found)
        self.assertEqual(result.causal_annotations[1].claim, 'TRACE_PARENT_MATCH')

    def test_143_claimed_edge_parent_has_precedence_over_span_context(self):
        ns = [n('s'), n('a'), n('v', 'vendor')]
        first = replace(e('first', 's', 'a', seq=5), trace_id='a'*32, span_id='1'*16)
        second = replace(e('second', 'a', 'v', seq=4), trace_id='a'*32,
                         span_id='2'*16, parent_span_id='1'*16, causal_parent_id='wrong')
        result = analyze(ns, [first, second])
        self.assertEqual(result.status, 'REPORTED_ORDER_UNRESOLVED')
        self.assertEqual(result.causal_annotations[1].claim, 'CONFLICTING_PARENT')

    def test_144_hmac_trust_missing_is_unverified_and_route_preserved(self):
        d = DeclassificationTests()
        d.setUp() if hasattr(d, 'setUp') else None
        result = d.check(d.claim(), trust=False)
        self.assertEqual(result.declassification_assessments[0].status, 'UNVERIFIED_CLAIM')
        self.assertEqual(result.declassification_assessments[0].reason, 'UNTRUSTED_ATTESTER')
        self.assertEqual(result.status, 'REPORTED_ORDERED_LINEAGE')

    def test_145_hmac_nonce_scope_is_per_analysis_call(self):
        d = DeclassificationTests()
        nodes, trust = d.configuration()
        edge = replace(e('attested', 's', 'v', flow='declassified'), declassification=d.claim())
        model = Cartographer(nodes, [edge], attestation_trust=trust, verification_epoch=15)
        q = Query('s', 'vendor', 'SECRET')
        first = model.analyze(q)
        second = model.analyze(q)
        # Illustrates the documented limitation: this demo has no persistent replay store.
        self.assertEqual(first.declassification_assessments[0].status, 'AUTHENTICATED_METADATA_CLAIM')
        self.assertEqual(second.declassification_assessments[0].status, 'AUTHENTICATED_METADATA_CLAIM')
        self.assertEqual(first.path, second.path)

    def test_146_declassified_and_data_equal_for_all_three_relations(self):
        d = DeclassificationTests()
        nodes, trust = d.configuration()
        data = e('direct', 's', 'v', flow='data')
        declass = replace(e('direct', 's', 'v', flow='declassified'), declassification=d.claim())
        q = Query('s', 'vendor', 'SECRET')
        model_a = Cartographer(nodes, [data], attestation_trust=trust, verification_epoch=15)
        model_b = Cartographer(nodes, [declass], attestation_trust=trust, verification_epoch=15)
        result_a, result_b = model_a.analyze(q), model_b.analyze(q)
        self.assertEqual(result_a.status, result_b.status)
        self.assertEqual(result_a.path, result_b.path)
        self.assertEqual((result_a.ordered.found, result_a.reported.found, result_a.possible.found),
                         (result_b.ordered.found, result_b.reported.found, result_b.possible.found))
        self.assertFalse(result_b.declassification_assessments[0].edge_suppressed)

    def test_147_nonce_duplicate_diagnostic_on_second_edge_only(self):
        d = DeclassificationTests()
        nodes, trust = d.configuration()
        claim = d.claim()
        edges = [replace(e('b', 's', 'v', flow='declassified'), declassification=claim),
                 replace(e('a', 's', 'v', flow='declassified'), declassification=claim)]
        model = Cartographer(nodes, edges, attestation_trust=trust, verification_epoch=15)
        assessments = model.analyze(Query('s', 'vendor', 'SECRET')).declassification_assessments
        self.assertEqual([a.edge_id for a in assessments], ['a', 'b'])
        self.assertEqual([a.status for a in assessments],
                         ['AUTHENTICATED_METADATA_CLAIM', 'UNVERIFIED_CLAIM'])
        self.assertEqual(assessments[1].reason, 'DUPLICATE_NONCE_IN_GRAPH')


class SelectionBindingAndBoundaryTests(unittest.TestCase):
    """Witness re-verification, decisive negatives, claim binding, and validation boundaries."""

    def test_148_order_issues_describe_selected_path_only(self):
        # A 1-hop unsequenced reported edge must not
        # produce an order issue when the selected witness is the ordered route.
        f=analyze([n('s'),n('a'),n('v','vendor')],
                  [e('e0','s','v',seq=None),e('e1','s','a',seq=1),e('e2','a','v',seq=2)])
        self.assertEqual((f.status,f.path),('REPORTED_ORDERED_LINEAGE',('e1','e2')))
        self.assertEqual(f.reported_path_order_issues,())

    def test_149_returned_reported_witness_reverified_as_ordered(self):
        # Ordered search capped; the reported witness is itself strictly ordered.
        es=[e(f'e{k}','s','a',seq=k) for k in range(1,6)]+[e('z','a','v',seq=10)]
        f=analyze([n('s'),n('a'),n('v','vendor')],es,budget=3)
        self.assertTrue(f.ordered.limit_reached)
        self.assertFalse(f.ordered.found)
        self.assertEqual(f.status,'REPORTED_ORDERED_LINEAGE')
        self.assertEqual(f.path,('e1','z'))
        self.assertEqual(f.witness_source,'reported')
        self.assertTrue(f.witness_reclassified)
        self.assertEqual(f.reported_path_order_issues,())

    def test_150_unordered_reported_witness_not_upgraded(self):
        es=[e(f'a{i:02d}','s','a',seq=i+1) for i in range(12)]+[e('z','a','v',seq=0)]
        f=analyze([n('s'),n('a'),n('v','vendor')],es,budget=3)
        self.assertEqual(f.status,'REPORTED_ORDER_UNRESOLVED')
        self.assertFalse(f.witness_reclassified)
        self.assertEqual(f.reported_path_order_issues[0].reason,'NON_INCREASING_SEQUENCE')

    def test_151_witness_reverification_predicates(self):
        model=Cartographer([n('s'),n('a'),n('v','vendor')],
                           [e('r1','s','a',seq=None),e('r2','a','v',seq=3),
                            e('o1','s','a',seq=1),e('i1','a','v',mode='inferred'),
                            e('d1','s','a',seq=4)])
        check=model._witness_satisfies
        self.assertTrue(check('ordered','s',('o1','r2')))
        self.assertFalse(check('ordered','s',('d1','r2')))      # 4 then 3
        self.assertTrue(check('reported','s',('d1','r2')))
        self.assertFalse(check('ordered','s',('r1','r2')))      # missing sequence
        self.assertTrue(check('reported','s',('r1','r2')))
        self.assertFalse(check('reported','s',('o1','i1')))     # inferred edge
        self.assertFalse(check('reported','s',('r2',)))         # does not start at source
        self.assertFalse(check('ordered','s',()))
        with self.assertRaises(ValueError):
            check('possible','s',('o1','i1'))

    def test_152_exhaustive_negative_possible_search_is_decisive(self):
        # Possible search exhaustive and negative; ordered search capped.
        es=[e(f'e{k}','s','a',seq=k) for k in range(1,6)]
        f=analyze([n('s'),n('a'),n('v','vendor')],es,budget=3)
        self.assertTrue(f.ordered.limit_reached)
        self.assertTrue(f.possible.exhaustive)
        self.assertEqual(f.status,'NO_ROUTE_IN_DECLARED_GRAPH')

    def test_153_capped_possible_search_still_unknown(self):
        es=[e('a','s','a',seq=1),e('b','a','v',seq=2)]
        f=analyze([n('s'),n('a'),n('v','vendor')],es,budget=1)
        self.assertFalse(f.possible.exhaustive)
        self.assertEqual(f.status,'UNKNOWN_LIMIT')

    def test_154_all_zero_trace_id_rejected(self):
        with self.assertRaises(ValueError):
            Cartographer([n('s'),n('v','vendor')],[replace(e('x','s','v'),trace_id='0'*32,span_id='1'*16)])

    def test_155_all_zero_span_and_parent_rejected(self):
        for field in ('span_id','parent_span_id'):
            edge=replace(e('x','s','v'),trace_id='a'*32,span_id='1'*16)
            edge=replace(edge,**{field:'0'*16})
            with self.assertRaises(ValueError,msg=field):
                Cartographer([n('s'),n('v','vendor')],[edge])

    def test_156_claim_transplanted_to_other_artifacts_fails(self):
        d=DeclassificationTests(); claim=d.claim()
        ns=[Node('X','internal','application','complete',d.SRC),
            Node('Y','vendor','external','complete',d.OUT),Node('s','internal','application','complete')]
        model=Cartographer(ns,[replace(e('t','X','Y',flow='declassified'),declassification=claim)],
                           attestation_trust=d.configuration()[1],verification_epoch=15)
        result=model.analyze(Query('X','vendor','SECRET'))
        self.assertEqual(result.declassification_assessments[0].reason,'MAC_MISMATCH')
        self.assertEqual(result.status,'REPORTED_ORDERED_LINEAGE')

    def test_157_claim_bound_to_destination_domain(self):
        d=DeclassificationTests(); claim=d.claim(bind=('s','v','internal','internal_redactor'))
        result=d.check(claim)
        self.assertEqual(result.declassification_assessments[0].reason,'MAC_MISMATCH')

    def test_158_unhashable_endpoint_is_value_error(self):
        raw={'nodes':[{'id':'s','domain':'i','surface':'application'}],
             'edges':[{'id':'x','src':['s'],'dst':'s','mode':'observed','flow':'data'}]}
        with self.assertRaises(ValueError):
            from_json_dict(raw)

    def test_159_mac_checked_before_field_reasons(self):
        d=DeclassificationTests()
        result=d.check(replace(d.claim(),category='OTHER'))
        self.assertEqual(result.declassification_assessments[0].reason,'MAC_MISMATCH')

    def test_160_malformed_claim_rejects_whole_input(self):
        # Documented fail-closed behaviour (paper Section 5.2, Proposition 5).
        d=DeclassificationTests()
        bad=replace(d.claim(),mac_hex='not-hex')
        with self.assertRaises(ValueError):
            Cartographer([n('s'),n('v','vendor'),n('q'),n('r','other')],
                         [e('route','s','v'),replace(e('u','q','r',flow='declassified'),declassification=bad)])

    # Validation and diagnostic boundaries.
    def test_161_equal_sequence_flagged_non_increasing(self):
        f=analyze([n('s'),n('a'),n('v','vendor')],[e('a','s','a',seq=2),e('b','a','v',seq=2)])
        self.assertEqual([(i.edge_id,i.reason,i.position) for i in f.reported_path_order_issues],
                         [('b','NON_INCREASING_SEQUENCE',2)])

    def test_162_annotation_positions_start_at_one(self):
        f=analyze(edges=[e('x','s','v',seq=None)])
        self.assertEqual(f.reported_path_order_issues[0].position,1)
        self.assertEqual(f.causal_annotations[0].position,1)

    def test_163_validity_window_bounds_inclusive(self):
        d=DeclassificationTests()
        for epoch,reason in ((10,'MAC_VERIFIED_METADATA_ONLY'),(20,'MAC_VERIFIED_METADATA_ONLY'),
                             (9,'OUTSIDE_VALIDITY_WINDOW'),(21,'OUTSIDE_VALIDITY_WINDOW')):
            self.assertEqual(d.check(d.claim(),epoch=epoch).declassification_assessments[0].reason,reason,epoch)

    def test_164_claim_window_and_digest_validation(self):
        d=DeclassificationTests()
        d.check(d.claim(issued_at=5,expires_at=5),epoch=5)  # equal bounds accepted
        self.assertEqual(d.check(d.claim(issued_at=0,expires_at=5),epoch=0)
                         .declassification_assessments[0].reason,'MAC_VERIFIED_METADATA_ONLY')
        for updates in (dict(issued_at=6,expires_at=5),dict(issued_at=-1,expires_at=5),
                        dict(source_digest='x'),dict(output_digest='x'),
                        dict(issued_at=True),dict(expires_at=1.5)):
            with self.assertRaises(ValueError,msg=str(updates)):
                d.check(replace(d.claim(),**updates))

    def test_165_parent_span_requires_trace_and_span(self):
        for kw in (dict(span_id='1'*16),dict(trace_id='a'*32)):
            with self.assertRaises(ValueError,msg=str(kw)):
                Cartographer([n('s'),n('v','vendor')],[replace(e('x','s','v'),parent_span_id='2'*16,**kw)])
        Cartographer([n('s'),n('v','vendor')],
                     [replace(e('x','s','v'),trace_id='a'*32,span_id='1'*16,parent_span_id='2'*16)])

    def test_166_trust_configuration_boundaries(self):
        ok=AttestationTrust('demo','p',b'k'*16,('SECRET',),('mask',))
        Cartographer([n('s')],[],attestation_trust={'demo':ok},verification_epoch=0)
        for trust,key in ((replace(ok,secret_key=b'k'*15),'demo'),(ok,'other'),
                          (replace(ok,policy_id=' '),'demo'),(replace(ok,categories=()),'demo'),
                          (replace(ok,transforms=('',)),'demo'),(replace(ok,categories=['SECRET']),'demo')):
            with self.assertRaises(ValueError):
                Cartographer([n('s')],[],attestation_trust={key:trust})
        with self.assertRaises(ValueError):
            Cartographer([n('s')],[],verification_epoch=-1)

    def test_167_short_identifier_limits(self):
        Cartographer([n('s'),n('v','vendor')],[replace(e('x','s','v'),causal_parent_id='p'*256)])
        Cartographer([n('s'),n('v','vendor')],[replace(e('x','s','v'),causal_parent_id='with space')])
        for bad in ('p'*257,'bad\nid','bad\x1fid'):
            with self.assertRaises(ValueError):
                Cartographer([n('s'),n('v','vendor')],[replace(e('x','s','v'),causal_parent_id=bad)])

    def test_168_policy_entry_requires_category_and_domain(self):
        base={'nodes':[{'id':'s','domain':'i','surface':'application'}],'edges':[]}
        for entry in ({'category':' ','domain':'v','decision':'DENIED'},
                      {'category':'S','domain':' ','decision':'DENIED'}):
            with self.assertRaises(ValueError):
                from_json_dict(dict(base,policy=[entry]))

    def test_169_nodes_and_edges_must_be_sequences(self):
        for nodes,edges in (({},[]),([],{})):
            with self.assertRaises(ValueError):
                Cartographer(nodes,edges)

    def test_170_claim_only_on_declassified_edge(self):
        d=DeclassificationTests()
        with self.assertRaises(ValueError):
            Cartographer([n('s'),n('v','vendor')],[replace(e('x','s','v',flow='data'),declassification=d.claim())])
        with self.assertRaises(ValueError):
            Cartographer([n('s'),n('v','vendor')],[replace(e('x','s','v',flow='declassified'),declassification='claim')])

    def test_171_witness_source_reported_without_reclassification(self):
        f=analyze(edges=[e('x','s','v',seq=1)])
        self.assertEqual((f.witness_source,f.witness_reclassified),('ordered',False))
        f=analyze()
        self.assertEqual((f.witness_source,f.witness_reclassified),(None,False))


if __name__ == '__main__':
    unittest.main(verbosity=2)
