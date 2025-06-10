# -*- coding: utf-8 -*-
import json
from typing import List, Dict, Optional, Set, Tuple, DefaultDict
from bisect import bisect_right


class Funcnode:
    def __init__(self, addr: int):
        # Entry address of this function
        self.addr: int = addr
        # All BBs which this function own
        self.BBs: Dict[int, BB] = {}
        # All functions called by this function
        self.call_func: Set[Funcnode] = set()
        # All BBs that call this function
        self.xrefs: Set[BB] = set()

    def build_dominators(self):
        """
        We are not much interested in the performance of this function.
        Naive dataflow equation solver (Lattice: Set of BBs, Join: Intersection)
        """
        entry_bb = self.get_entry()
        bbs = self.get_bbs()

        for bb in bbs:
            if bb == entry_bb:
                bb.doms = {bb}
            else:
                bb.doms = set(bbs)

        changed = True
        while changed:
            changed = False
            for bb in bbs:
                """
                Dataflow Equation:
                Dom(n) = {n}                                 if n is the entry_bb
                         {n} ∪ (⋂ (Dom(p) for p in n.preds)) otherwise
                """
                if bb == entry_bb:
                    assert bb.doms == {bb}
                    continue
                pred_doms = [pred.doms for pred in bb.pred_bbs]
                new_doms = {bb} | set.intersection(*pred_doms)
                if new_doms != bb.doms:
                    bb.doms = new_doms
                    changed = True

    def build_post_dominators(self):
        """
        TODO: Precondition "every vertex is reachable from the entry" does not hold, so needs fix!
        """
        # Sink BBs are connecdted to the virtual entry BB
        sink_bbs = set(self.get_sinks())
        virtual_entry = BB(-1, self)
        bbs = self.get_bbs()
        for bb in bbs:
            if bb in sink_bbs:
                bb.pdoms = {bb, virtual_entry}
            else:
                bb.pdoms = set(bbs)

        changed = True
        while changed:
            changed = False
            for bb in bbs:
                if bb in sink_bbs:
                    assert bb.pdoms == {bb, virtual_entry}
                    continue
                succ_pdoms = [succ.pdoms for succ in bb.dst_bbs]
                new_pdoms = {bb} | set.intersection(*succ_pdoms)
                if new_pdoms != bb.pdoms:
                    bb.pdoms = new_pdoms
                    changed = True

        for bb in bbs:
            if virtual_entry in bb.pdoms:
                bb.pdoms.remove(virtual_entry)

        del virtual_entry

    def update_preds(self):
        """
        For BBs, pred_bbs are not always reliable, so sometimes needs rebuilding.
        """
        for bb in self.BBs.values():
            bb.pred_bbs = set()
        for bb in self.BBs.values():
            for dst_bb in bb.dst_bbs:
                dst_bb.pred_bbs.add(bb)

    def register_bb(self, bb: "BB"):
        self.BBs[bb.start_addr] = bb

    def remove_bb(self, bb: "BB"):
        del self.BBs[bb.start_addr]

    def get_sinks(self) -> List["BB"]:
        return [bb for bb in self.BBs.values() if not bb.dst_bbs]

    def get_entry(self) -> "BB":
        return self.BBs[self.addr]

    def get_bbs(self) -> List["BB"]:
        return list(self.BBs.values())

    def __str__(self):
        return hex(self.addr)

    def __repr__(self):
        return self.__str__()


class BB:
    def __init__(self, start_addr: int, parent_funcnode: Funcnode):
        # Entry of this BB; this works as a unique identifier
        # In Ghidra, `block.getFirstStartAddress().getOffset()``
        self.start_addr: int = start_addr
        # Address of final inst of this BB
        # In Ghidra, `block.getLastRange().getMaxAddress().getOffset()`
        self.end_addr: Optional[int] = None

        # Successor BBs
        self.dst_bbs: Set[BB] = set()
        # Predecessor BBs (NOT always correct; sometimes needs rebuilding by Funcnode.update_preds)
        self.pred_bbs: Set[BB] = set()

        # Function that this BB belongs to
        self.parent_funcnode: Funcnode = parent_funcnode
        # Info of string literals that this BB refers to
        self.xrefs: Set[XREF] = set()
        # Functions that this BB calls
        self.call_func: Set[Funcnode] = set()

        # Passing edge (self -> other) can implicate passing other removed BBs
        # (i.e. self -> removed -> other in original CFG)
        # Or can be perceived as a metadata of the outgoing edges
        self.edge_implicate_bbs: DefaultDict[BB, Set[BB]] = DefaultDict(set)

        # Dominators of this BB
        self.doms: Set["BB"] = set()
        # Post-dominators of this BB
        self.pdoms: Set["BB"] = set()

    def __str__(self):
        return hex(self.start_addr)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        assert isinstance(other, BB)
        return self.start_addr == other.start_addr

    def __hash__(self):
        return hash(self.start_addr)


class XREF:
    """
    Represents info about string literals (literal + referring BBs)
    """

    def __init__(self, literal: bytes):
        # BBs that refer to this literal
        self.bbs: Set[BB] = set()
        # byte-level string literal
        self.literal: bytes = literal

        # Address in .rodata section that this literal appears; for debugging
        self.ro_addrs: Set[int] = set()
        # This is not used; just for Ghidra-output compatibility
        self.funcnodes: Set[int] = set()


class AddrToBBLookup:
    """
    (BB -> address) can be done by BB.start_addr
    (address -> BB) can be done by this class
    """

    def __init__(self, bb_set: Set[BB]):
        bbs = list(bb_set)
        self.sorted_bbs = sorted(bbs, key=lambda x: x.start_addr)
        self.start_addrs = [bb.start_addr for bb in self.sorted_bbs]

    def _get_bb(self, addr: int):
        index = bisect_right(self.start_addrs, addr) - 1
        if index >= 0:
            bb = self.sorted_bbs[index]
            if bb.end_addr and bb.start_addr <= addr <= bb.end_addr:
                return bb
        return None

    def __call__(self, addr: int):
        return self._get_bb(addr)


class Edge:
    """
    This is not used. To be removed.
    """

    def __init__(self, bb1: BB, bb2: BB):
        self.bb1 = bb1
        self.bb2 = bb2

    def __eq__(self, other):
        if self.bb1 == other.bb1 and self.bb2 == other.bb2:
            return True
        else:
            return False


class Path:
    """
    This class is to be removed
    """

    def __init__(self, func: Funcnode):
        self._edges: List[Edge] = []
        self.sum_score: float = 0
        self.bbs: List[BB] = []
        self.loop = False
        self.funcnode: Funcnode = func

    def add_edge(self, edge: Edge):
        self._edges.append(edge)

    def remove_edges(self, edges: List[Edge]):
        for edge in edges:
            if edge in self._edges:
                self._edges.remove(edge)

    def __add__(self, other):
        # self._edges = self._edges + other._edges
        # 重複するエッジを弾く
        for o_edge in other._edges:
            include = False
            for s_edge in self._edges:
                if o_edge == s_edge:
                    include = True
                    break
            if not include:
                self._edges.append(o_edge)
        # 重複するbbを弾く
        for bb in other.bbs:
            if bb not in self.bbs:
                self.bbs.append(bb)
        return self

    def __str__(self) -> str:
        res = f"SCORE: {self.sum_score}\n"
        if len(self._edges) == 0:
            assert len(self.bbs) == 1
            return res + f"{hex(self.bbs[0].start_addr)}\n"
        for edge in reversed(self._edges):
            res += f"{hex(edge.bb1.start_addr)} -> {hex(edge.bb2.start_addr)}\n"
        return res

    def __repr__(self):
        return self.__str__()

    def copy(self):
        path = Path(self.funcnode)
        path._edges = self._edges.copy()
        path.sum_score = self.sum_score
        path.bbs = self.bbs.copy()
        return path

    def print_edge(self):
        rev = self._edges[::-1]
        for edge in rev:
            print(f"{hex(edge.bb1.start_addr)} -> {hex(edge.bb2.start_addr)}")

    def contains(self, target: Edge):
        for edge in self._edges:
            if target == edge:
                return True
        return False

    def create_BB_set(self):
        for edge in self._edges:
            if edge.bb1 not in self.bbs:
                self.bbs.append(edge.bb1)
            if edge.bb2 not in self.bbs:
                self.bbs.append(edge.bb2)

    def path_completion(self):
        # The goal of this function is to add appropriate edges
        # from BBs that ends with call instruction to the next BBs
        # TODO: This function assumes that every `call`s return.
        #       To fix this, PIN needs to do some more work.
        bb1_set = set([edge.bb1 for edge in self._edges])
        for edge in self._edges:
            dst_bb = edge.bb2
            if dst_bb in bb1_set:
                continue
            # edge's destination has no out-edge.
            # if the destination has exactly one out-edge then we add the edge
            # to supply the out-edge from bbs that ends with call instruction.
            if len(dst_bb.dst_bbs) == 1:
                succ = next(iter(dst_bb.dst_bbs))
                self.add_edge(Edge(dst_bb, succ))


class CFG:
    """
    Represents the whole-program CFG + info about string literals
    """

    def __init__(self):
        # Maps address -> Funcnode (Mostly for List[Funcnode] purpose)
        self.funcnode_dict: Dict[int, Funcnode] = {}
        # Maps literal -> xref (Mostly for List[xref] purpose)
        self.string_xref: Dict[bytes, XREF] = {}

    def get_funcs(self) -> List[Funcnode]:
        return list(self.funcnode_dict.values())

    def get_string_refer_bbs(self) -> Set[BB]:
        return {bb for xref in self.string_xref.values() for bb in xref.bbs}

    def get_string_refer_funcs(self):
        return {bb.parent_funcnode for bb in self.get_string_refer_bbs()}

    def get_bb_from_addr(self, addr: int) -> Optional[BB]:
        return self.addr2bb(addr)

    def get_num_funcs(self) -> int:
        return len(self.funcnode_dict)

    def get_num_bbs(self) -> int:
        return sum(len(func.BBs) for func in self.funcnode_dict.values())

    def get_num_edges(self) -> int:
        return sum(
            len(bb.dst_bbs)
            for func in self.funcnode_dict.values()
            for bb in func.BBs.values()
        )

    def build_dominators(self):
        for func in self.get_funcs():
            func.build_dominators()
            func.build_post_dominators()

    def build_func_distance_map(self):
        """
        NOTE: This is super slow, although we don't need a super fast implementation.
        """

        def get_caller_distances(func: Funcnode) -> Dict[Funcnode, int]:
            distances = {func: 0}
            queue: List[Funcnode] = [func]
            while queue:
                current = queue.pop(0)
                caller_funcs = {bb.parent_funcnode for bb in current.xrefs}
                for caller in caller_funcs:
                    if caller not in distances:
                        distances[caller] = distances[current] + 1
                        queue.append(caller)
            return distances

        distance_map: Dict[Tuple[Funcnode, Funcnode], int] = {}
        funcs = self.get_funcs()

        for i, f1 in enumerate(funcs):
            f1_dists = get_caller_distances(f1)
            for f2 in funcs[i:]:
                f2_dists = get_caller_distances(f2)
                # Find the smallest common element in the two distance maps
                common_funcs = set(f1_dists.keys()) & set(f2_dists.keys())
                if common_funcs:
                    min_dist = min(f1_dists[f] + f2_dists[f] for f in common_funcs)
                else:
                    min_dist = 100
                distance_map[f1, f2] = min_dist
                distance_map[f2, f1] = min_dist
        self.func_distance_map = distance_map

    def get_func_distance(self, f1: Funcnode, f2: Funcnode) -> int:
        return self.func_distance_map[f1, f2]

    def get_bb_distance(self, bb1: BB, bb2: BB) -> int:
        return self.get_func_distance(bb1.parent_funcnode, bb2.parent_funcnode)

    def struct_CFG(self, json_path: str):
        """
        The loaded data of Ghidra CFG is not complete and needs some more work here.
        This is the actual initialization of this class
        """
        # _funcnode: {"call_func": [], "BBs": {}, "xrefs":[]}
        # _bb: {"dst_bbs": [], "call_func": [], "xrefs":[], "end_addr": None, "parent_funcnode": None}
        with open(json_path, "r") as f:
            _fuccnode_dict = json.load(f)
        bb_set = set()
        for func_addr in _fuccnode_dict.keys():
            _funcnode = _fuccnode_dict[str(func_addr)]
            funcnode = Funcnode(int(func_addr))
            self.funcnode_dict[int(func_addr)] = funcnode
            for bb_addr in _funcnode["BBs"].keys():
                _bb = _funcnode["BBs"][bb_addr]
                bb = BB(int(bb_addr), funcnode)
                bb.end_addr = _bb["end_addr"]
                bb.parent_funcnode = funcnode
                funcnode.BBs[int(bb_addr)] = bb
                bb_set.add(bb)
        """
        for bb in sorted(bb_set, key=lambda x: x.start_addr):
            print(f"BB: {hex(bb.start_addr)}")
            if not bb.end_addr:
                print("  Unknown Function")
        """

        self.addr2bb = AddrToBBLookup(bb_set)

        for func_addr in _fuccnode_dict.keys():
            _funcnode = _fuccnode_dict[func_addr]
            funcnode = self.funcnode_dict[int(func_addr)]
            for bb_addr in _funcnode["BBs"].keys():
                _bb = _funcnode["BBs"][bb_addr]
                bb = funcnode.BBs[int(bb_addr)]
                for dst_addr in _bb["dst_bbs"]:
                    bb.dst_bbs.add(funcnode.BBs[dst_addr])
                    funcnode.BBs[dst_addr].pred_bbs.add(bb)
                for call_addr in _bb["call_func"]:
                    callee = self.funcnode_dict[call_addr]
                    bb.call_func.add(callee)
                    funcnode.call_func.add(callee)
                    callee.xrefs.add(bb)

        for xref in self.string_xref.values():
            funcnode_addr = xref.funcnodes
            xref.funcnodes = set()
            bb_addr = xref.bbs
            xref.bbs = set()
            for funcaddr in funcnode_addr:
                xref.funcnodes.add(self.funcnode_dict[funcaddr].addr)
                for bbaddr in bb_addr:
                    if bbaddr in self.funcnode_dict[funcaddr].BBs.keys():
                        xref.bbs.add(self.funcnode_dict[funcaddr].BBs[bbaddr])
            for bb in xref.bbs:
                bb.xrefs.add(xref)

    def convert_edges_to_Paths(self, edges: List[Tuple[int, int]]) -> List[Path]:
        """
        To be replaced
        """
        paths: Dict[Funcnode, Path] = {}

        for src_addr, dst_addr in edges:
            src_bb = self.addr2bb(src_addr)
            dst_bb = self.addr2bb(dst_addr)
            if not src_bb or not dst_bb:
                continue
            if dst_bb.start_addr != dst_addr:
                continue
            src_funcnode = src_bb.parent_funcnode
            dst_funcnode = dst_bb.parent_funcnode
            if src_funcnode.addr != dst_funcnode.addr:
                continue

            if src_bb and dst_bb:
                parent_funcnode = src_bb.parent_funcnode
                if parent_funcnode not in paths:
                    paths[parent_funcnode] = Path(parent_funcnode)
                paths[parent_funcnode].add_edge(Edge(src_bb, dst_bb))
                if src_bb not in paths[parent_funcnode].bbs:
                    paths[parent_funcnode].bbs.append(src_bb)
                if dst_bb not in paths[parent_funcnode].bbs:
                    paths[parent_funcnode].bbs.append(dst_bb)

        # BBの最後の命令がcall命令の時にエッジが出力されないので、それを補完
        for path in paths.values():
            path.path_completion()
            path.create_BB_set()
        return list(paths.values())

    def convert_edges_to_BBs(self, edges: List[Tuple[int, int]]) -> Set[BB]:
        """
        We need this method in addition to another that retrieves real edges because
        Ghidra CFG graph lacks completeness (i.e. missing run-time edges)
        """
        bbs: Set[BB] = set()
        for src_addr, dst_addr in edges:
            src_bb = self.get_bb_from_addr(src_addr)
            dst_bb = self.get_bb_from_addr(dst_addr)
            if src_bb:
                bbs.add(src_bb)
            if dst_bb:
                bbs.add(dst_bb)

        return bbs
