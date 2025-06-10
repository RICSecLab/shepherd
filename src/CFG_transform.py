# -*- coding: utf-8 -*-
import logging
from CFG_recover import Funcnode, BB, CFG
from graph_algo import CallGraph
from typing import List, Set
from collections import defaultdict


class CFGTransformer:
    def __init__(self, cfg: CFG):
        self.cfg = cfg
        self.operation_count = 0

    def _rebuild_callgraph(self):
        live_funcs = set(self.cfg.funcnode_dict.values())
        self.cg = CallGraph(list(self.cfg.get_string_refer_funcs() & live_funcs))

    def get_callgraph(self):
        if hasattr(self, "cg"):
            return self.cg
        self._rebuild_callgraph()
        return self.cg

    # We don't care about order but return interesting funcs rapidly
    def get_funcs(self) -> Set[Funcnode]:
        cg = self.get_callgraph()
        return set(cg.idx_to_func)

    def get_funcs_in_bottomup_order(self) -> List[Funcnode]:
        cg = self.get_callgraph()
        result: List[Funcnode] = []
        scc_id_list = cg.reverse_topological_sort()
        for scc_id in scc_id_list:
            funcs_to_visit: List[int] = cg.scc_funcidx_map[scc_id]
            for func_idx in funcs_to_visit:
                funcnode = cg.idx_to_func[func_idx]
                result.append(funcnode)
        return result

    def get_string_calling_bbs(self) -> Set[BB]:
        funcs = self.get_funcs()
        result: Set[BB] = set()
        for caller in funcs:
            for bb in caller.get_bbs():
                for callee in bb.call_func:
                    if callee in funcs:
                        result.add(bb)
        return result

    # Inline proc for a specif caller and callee
    def inline_callee(self, call_site: BB, callee: Funcnode, new_bbs: List[BB]):
        assert callee in call_site.call_func
        caller = call_site.parent_funcnode
        callee_sinks: List[BB] = callee.get_sinks()
        call_site_succs = call_site.dst_bbs
        # Connect sink of the callee to the successors of the call site
        for sink in callee_sinks:
            sink.dst_bbs = call_site_succs.copy()
            sink.edge_implicate_bbs = call_site.edge_implicate_bbs.copy()
        # Connect the call site to the entry of the callee
        call_site.edge_implicate_bbs.clear()
        call_site.dst_bbs = {callee.get_entry()}
        # Overwrite the parent func of the callee BBs to the caller
        for callee_bb in callee.BBs.values():
            callee_bb.parent_funcnode = caller
            new_bbs.append(callee_bb)

        # Empty the callee
        callee.BBs = {}
        self.operation_count += 1

    # Inline function calls in the given function node bbs
    def _inline_function_callees(
        self,
        caller: Funcnode,
        interesting_funcs: Set[Funcnode],
        removed_funcs: List[Funcnode],
        same_scc_funcs: Set[Funcnode],
    ) -> bool:
        changed = False
        new_bbs: List[BB] = []
        for bb in caller.get_bbs():
            removed_callee = set()
            for callee in bb.call_func:
                if (
                    callee in interesting_funcs
                    and len(callee.xrefs) == 1
                    and callee not in same_scc_funcs
                ):
                    logging.debug(f"  Inlining {callee} into {caller}")
                    self.inline_callee(bb, callee, new_bbs)
                    removed_funcs.append(callee)
                    removed_callee.add(callee)
                    changed = True
                    self.verify_func_cfg(caller)
            for callee in removed_callee:
                bb.call_func.remove(callee)

        # Add the new BBs to the parent funcnode
        for bb in new_bbs:
            caller.register_bb(bb)

        return changed

    def run_inliner_pass(self, cfg: CFG) -> bool:
        funcs = self.get_funcs_in_bottomup_order()
        cg = self.get_callgraph()
        func_to_scc_id = cg.build_func_to_scc_id()
        removed_funcs: List[Funcnode] = []
        for caller in funcs:
            same_scc_func_indices = cg.scc_funcidx_map[func_to_scc_id[caller.addr]]
            same_scc_funcs = {cg.idx_to_func[idx] for idx in same_scc_func_indices}
            assert len(caller.get_bbs()) > 0, (
                "Function is not visited in bottom-up order."
            )
            self._inline_function_callees(
                caller, set(funcs), removed_funcs, same_scc_funcs
            )

        if len(removed_funcs) == 0:
            return False
        # Remove the inlined functions from the CFG

        for func in removed_funcs:
            cfg.funcnode_dict.pop(func.addr)
        self._rebuild_callgraph()

        return True

    # Remove edge (bb -> entry_bb) by redirecting them to the successors of the entry node
    def remove_entry_incoming_edge(self, bb: BB, entry_bb: BB):
        func = entry_bb.parent_funcnode
        logging.debug(
            f"  Redirecting entry incoming edge {bb} -> {entry_bb} ({len(func.get_bbs())} @ {self.operation_count})"
        )
        assert entry_bb in bb.dst_bbs, f"{bb} -> {entry_bb} edge does not exist"
        bb.dst_bbs.remove(entry_bb)
        for entry_succ in entry_bb.dst_bbs.copy():
            # TODO: If the entry does not refer to strings, then the self-loop edge should be removed
            # But this would take almost no effect
            if entry_succ == entry_bb:
                continue
            overlap = entry_succ in bb.dst_bbs
            bb.dst_bbs.add(entry_succ)
            if overlap:
                bb.edge_implicate_bbs[entry_succ] &= bb.edge_implicate_bbs[entry_bb]
            else:
                bb.edge_implicate_bbs[entry_succ] = bb.edge_implicate_bbs[
                    entry_bb
                ].copy()
            bb.edge_implicate_bbs[entry_bb].clear()
        self.verify_bb(bb)
        self.operation_count += 1

    # Remove all incoming edges to the entry node by redirecting them to the successors of the entry node
    def remove_entry_incomings(self, func: Funcnode):
        entry_bb = func.get_entry()
        for bb in func.get_bbs():
            if entry_bb in bb.dst_bbs:
                self.remove_entry_incoming_edge(bb, entry_bb)

    # Remove all incoming/outgoing edges to/from a node and redirect them to each other
    def remove_node(self, func: Funcnode, bb: BB):
        logging.debug(
            f"  Removing node {bb.start_addr:x} from {func.addr:x} ({len(func.get_bbs())} @ {self.operation_count})"
        )
        # Add a edge (pred) -> (succ) for each pair of predecessors and successors
        # Still keeps the reverse edges well-formed for perf
        for p in bb.pred_bbs.copy():
            for s in bb.dst_bbs.copy():
                # Be careful of the aliasing of those BBs
                if p == bb or s == bb:
                    # (bb -> bb -> bb) case
                    continue
                    # (bb -> bb -> s) case
                    # Since (bb -> s) already exists, we don't need much
                    # Plus implication of (bb -> s) is still valid
                # CFG is (p -> bb -> s) and now removing b; Is there an edge (p -> s) already?
                # If so, the implicated bbs in the new edge (p -> q) should be the joined (intersection)
                overlap_edge = s in p.dst_bbs
                p.dst_bbs.add(s)
                s.pred_bbs.add(p)

                # The new edge (p -> s) implicates BBs that are already implicated by
                # either of (p -> bb) and (bb -> s) because we assume we passed both edges
                implicated_bbs = set()
                implicated_bbs.update(p.edge_implicate_bbs[bb])
                implicated_bbs.update(bb.edge_implicate_bbs[s])

                # Plus, bb itself is also implicated by (p -> s)
                implicated_bbs.add(bb)

                # If (p -> s) already exists, the implication becomes intersected
                # because we are merging multiple edges
                if overlap_edge:
                    p.edge_implicate_bbs[s] &= implicated_bbs
                else:
                    assert len(p.edge_implicate_bbs[s]) == 0, (
                        "(p -> s) should not exist before bb removal"
                    )
                    p.edge_implicate_bbs[s] = implicated_bbs
        func.update_preds()
        for p in bb.pred_bbs.copy():
            p.dst_bbs.remove(bb)
            p.edge_implicate_bbs[bb].clear()
        for s in bb.dst_bbs.copy():
            s.pred_bbs.remove(bb)
        bb.pred_bbs.clear()
        bb.dst_bbs.clear()

        func.remove_bb(bb)
        self.verify_func_cfg(func)
        self.operation_count += 1

    # Remove every node that doesn't count
    def remove_non_interesting_nodes(
        self,
        func: Funcnode,
        interesting_nodes: Set[BB],
    ):
        nodes_to_remove = []
        for bb in func.get_bbs():
            # Skip marked nodes, entry node, and sink nodes
            if bb in interesting_nodes or bb == func.get_entry() or not bb.dst_bbs:
                continue
            nodes_to_remove.append(bb)
        for bb in nodes_to_remove:
            self.remove_node(func, bb)

    # Remove uninteresting nodes from the Funcnode
    def minimize_funcnode_cfg(self, func: Funcnode, interesting_nodes: Set[BB]):
        func.update_preds()
        self.remove_non_interesting_nodes(func, interesting_nodes)
        self.remove_entry_incomings(func)

    def run_node_remove_pass(self, cfg: CFG) -> bool:
        saved_bbs = cfg.get_string_refer_bbs() | self.get_string_calling_bbs()
        funcs = self.get_funcs()
        changed = False
        for func in funcs:
            orig_bb_count = len(func.get_bbs())
            self.minimize_funcnode_cfg(func, saved_bbs)
            after_bb_count = len(func.get_bbs())
            assert orig_bb_count >= after_bb_count
            changed |= orig_bb_count != after_bb_count
        return changed

    def _merge_bbs(
        self,
        func: Funcnode,
        bb_list: List[BB],
        final: BB,
        interesting_funcs: Set[Funcnode],
    ):
        """
        When CFG splits into bb1 and bb2 and they are indistinguishable,
        we merge them into final (either bb1 or bb2)
        p1 ----> bb1 ----> s1
            |          ^
             \-> bb2 --/
        So that the final CFG becomes simpler like this
        p1 ----> final ----> s1

        Note that unlike remove_node, the removed BBs does not generate new edge (p1 -> s1)
        The bb_list contains bbs to be removed, and the final is the BB to be kept.
        """
        assert final not in bb_list
        for bb in bb_list:
            # Firstly merging evey edge (p -> bb) into (p -> final) for all removed bbs
            for pred in bb.pred_bbs.copy():
                if pred == bb:
                    continue
                # It's quite rare, but (p -> final) might not already exist
                overlap_edge = final in pred.dst_bbs

                pred.dst_bbs.remove(bb)
                pred.dst_bbs.add(final)
                final.pred_bbs.add(pred)
                bb.pred_bbs.remove(pred)

                implicated_bbs = pred.edge_implicate_bbs[bb].copy()
                if overlap_edge:
                    pred.edge_implicate_bbs[final] &= implicated_bbs
                else:
                    pred.edge_implicate_bbs[final] = implicated_bbs

                pred.edge_implicate_bbs[bb].clear()

            # Next merging every edge (bb -> s) into (final -> s) for all removed bbs
            for succ in bb.dst_bbs.copy():
                if succ == bb:
                    continue
                overlap_edge = succ in final.dst_bbs

                succ.pred_bbs.remove(bb)
                succ.pred_bbs.add(final)
                final.dst_bbs.add(succ)
                bb.dst_bbs.remove(succ)

                # Update edge metadata from final to succ
                implicated_bbs = bb.edge_implicate_bbs[succ].copy()
                if overlap_edge:
                    final.edge_implicate_bbs[succ] &= implicated_bbs
                else:
                    final.edge_implicate_bbs[succ] = implicated_bbs

                bb.edge_implicate_bbs[succ].clear()

        # Remove the BBs in the list from the function
        for bb in bb_list:
            for callee in bb.call_func:
                if callee in interesting_funcs:
                    callee.xrefs.remove(bb)
            func.remove_bb(bb)

        self.verify_func_cfg(func)
        self.operation_count += 1

    # Merged indistinguishable nodes like the automata minimization
    def merge_duplicate_nodes(
        self, func: Funcnode, interesting_funcs: Set[Funcnode]
    ) -> bool:
        func.update_preds()
        behavior_to_bb = defaultdict(list)
        for bb in func.get_bbs():
            literals = frozenset({xref.literal for xref in bb.xrefs})
            callees = frozenset(bb.call_func).intersection(interesting_funcs)
            bb_behavior = (literals, callees)
            behavior_to_bb[bb_behavior].append(bb)

        segment = list(behavior_to_bb.values())
        bb_to_segment = {}
        for id, bb_list in enumerate(segment):
            for bb in bb_list:
                bb_to_segment[bb] = id

        converged = False
        while not converged:
            converged = True
            new_segment: List[List[BB]] = []
            new_bb_to_segment = {}
            for bb_list in segment:
                if len(bb_list) == 1:
                    new_bb_to_segment[bb_list[0]] = len(new_segment)
                    new_segment.append(bb_list)
                    continue
                # If there are multiple BBs, we might split them into different segments
                nextseg_to_bb = defaultdict(list)
                for bb in bb_list:
                    next_segment = set()
                    for succ in bb.dst_bbs:
                        next_segment.add(bb_to_segment[succ])
                    nextseg_to_bb[frozenset(next_segment)].append(bb)
                converged = len(nextseg_to_bb) == 1
                for bb_list in nextseg_to_bb.values():
                    new_segment_id = len(new_segment)
                    for bb in bb_list:
                        new_bb_to_segment[bb] = new_segment_id
                    new_segment.append(bb_list)

            bb_to_segment = new_bb_to_segment
            segment = new_segment

        changed = False
        for bb_list in segment:
            if len(bb_list) == 1:
                continue
            changed = True
            saved_bb = bb_list[0]
            logging.debug(f"  Merging {bb_list} into {saved_bb}")
            self._merge_bbs(func, bb_list[1:], saved_bb, interesting_funcs)

        return changed

    def run_node_merge_pass(self, cfg: CFG) -> bool:
        funcs = self.get_funcs()
        changed = False
        for func in funcs:
            changed |= self.merge_duplicate_nodes(func, funcs)
        return changed

    def update_str_xrefs(self, cfg: CFG):
        live_bbs = set()
        for func in self.get_funcs():
            for bb in func.get_bbs():
                live_bbs.add(bb)
        for xref in cfg.string_xref.values():
            xref.bbs &= live_bbs

    def remove_unrelated_funcs(self, cfg: CFG):
        funcs = self.get_funcs()
        for func in list(cfg.funcnode_dict.values()):
            if func not in funcs:
                cfg.funcnode_dict.pop(func.addr)

    def verify_bb(self, bb: BB):
        if not __debug__:
            return
        for implicate_succ in bb.edge_implicate_bbs.keys():
            if len(bb.edge_implicate_bbs[implicate_succ]) == 0:
                continue
            if implicate_succ not in bb.dst_bbs:
                logging.debug(
                    f"WRONG: {bb} -> {implicate_succ} NOT EXISTS in {bb.dst_bbs}"
                )
            assert implicate_succ in bb.dst_bbs

    def verify_func_cfg(self, func: Funcnode):
        if not __debug__:
            return
        for bb in func.get_bbs():
            self.verify_bb(bb)

    def verify_cfg(self, cfg: CFG):
        if not __debug__:
            return
        for func in cfg.funcnode_dict.values():
            self.verify_func_cfg(func)

    def run_all_passes(self, cfg: CFG):
        self.remove_unrelated_funcs(cfg)
        changed = True
        count = 0
        while changed:
            logging.debug(f"Running Pass {count}")
            count += 1
            changed = False
            changed |= self.run_inliner_pass(cfg)
            self.verify_cfg(cfg)
            changed |= self.run_node_remove_pass(cfg)
            self.verify_cfg(cfg)
            changed |= self.run_node_merge_pass(cfg)
            self.verify_cfg(cfg)
            logging.debug(f"Finished Pass {count - 1}: {changed} changes")

        self.update_str_xrefs(cfg)

    # For debug purpose
    def run_passes_n_times(self, cfg: CFG, n: int):
        self.remove_unrelated_funcs(cfg)
        changed = True
        count = 0
        while changed:
            if count >= n:
                break
            logging.debug(f"Running Pass {count}")
            count += 1
            changed = False
            changed |= self.run_inliner_pass(cfg)
            self.verify_cfg(cfg)
            changed |= self.run_node_remove_pass(cfg)
            self.verify_cfg(cfg)
            changed |= self.run_node_merge_pass(cfg)
            self.verify_cfg(cfg)
            logging.debug(f"Finished Pass {count - 1}: {changed} changes")
        self.update_str_xrefs(cfg)
